#include <Arduino.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <WiFiClient.h>

// For extracting the attacker's IP from the socket
#include <lwip/sockets.h>

// LibSSH Includes
#include <libssh_esp32.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

enum AppState {
    STATE_IDLE,
    STATE_SCANNING,
    STATE_SELECTING,
    STATE_AWAITING_PASSWORD,
    STATE_CONNECTING,
    STATE_AWAITING_TARGET, // New State
    STATE_HONEYPOT
};

AppState currentState = STATE_IDLE;
int networkCount = 0;
int selectedIndex = 0;
String selectedSSID = "";
String inputBuffer = "";

// Logging Server config
String targetHost = "";
uint16_t targetPort = 0;
int globalSessionCount = 0; // Increments every new SSH connection

TaskHandle_t sshTaskHandle = NULL;

// ----------------------------------------------------
// JSON Escaping & Network Logging
// ----------------------------------------------------
String escapeJSON(String input) {
    input.replace("\\", "\\\\");
    input.replace("\"", "\\\"");
    input.replace("\n", "\\n");
    input.replace("\r", "");
    return input;
}

void sendLogToServer(String ip, int session, String command) {
    WiFiClient client;
    // Attempt a raw TCP connection to the target
    if (client.connect(targetHost.c_str(), targetPort)) {
        String payload = "{\n";
        payload += "  \"ip\": \"" + ip + "\",\n";
        payload += "  \"session\": " + String(session) + ",\n";
        payload += "  \"command\": \"" + escapeJSON(command) + "\"\n";
        payload += "}\n";
        
        client.print(payload);
        client.stop();
        Serial.println("[LOG SENT] " + command);
    } else {
        Serial.println("\n[!] Failed to send log to " + targetHost + ":" + String(targetPort));
    }
}

// ----------------------------------------------------
// UI Logic (Serial)
// ----------------------------------------------------
void pushLog(String msg) {
    Serial.println("[LOG] " + msg);
}

void printState() {
    Serial.println("\n========================================");
    switch (currentState) {
        case STATE_IDLE:
            Serial.println("SSH Pot: IDLE");
            Serial.println("Send 'SCAN' to start");
            break;
        case STATE_SCANNING:
            Serial.println("Scanning... Searching networks...");
            break;
        case STATE_SELECTING:
            Serial.println("Select Network (Send 'W' for Up, 'S' for Down, 'C' to Connect)");
            Serial.println("----------------------------------------");
            for (int i = 0; i < networkCount; i++) {
                Serial.print(i == selectedIndex ? " > " : "   ");
                Serial.print(WiFi.SSID(i));
                Serial.print(" (RSSI: ");
                Serial.print(WiFi.RSSI(i));
                Serial.println(")");
            }
            break;
        case STATE_AWAITING_PASSWORD:
            Serial.println("Enter Password for:");
            Serial.println(selectedSSID);
            break;
        case STATE_CONNECTING:
            Serial.println("Connecting...");
            break;
        case STATE_AWAITING_TARGET:
            Serial.println("Wi-Fi Connected!");
            Serial.println("Enter logging server IP:PORT (e.g. 192.168.1.50:8080)");
            break;
        case STATE_HONEYPOT:
            Serial.println("SSH POT ACTIVE");
            Serial.print("Local IP: "); 
            Serial.println(WiFi.localIP());
            Serial.println("Logging targets to: " + targetHost + ":" + String(targetPort));
            Serial.println("Awaiting connections...");
            break;
    }
    Serial.println("========================================\n");
}

// ----------------------------------------------------
// The FreeRTOS SSH Honeypot Task
// ----------------------------------------------------
void sshHoneypotTask(void *pvParameters) {
    ssh_bind sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, "22");
    
    // REQUIREMENT: You must have an RSA key stored in SPIFFS for SSH to work!
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/spiffs/ssh_host_rsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        pushLog("BIND ERR! Key missing?");
        vTaskDelete(NULL);
    }

    pushLog("Listening on port 22");

    while (true) {
        ssh_session session = ssh_new();
        
        // This blocks until a hacker connects
        if (ssh_bind_accept(sshbind, session) == SSH_OK) {
            pushLog("--- NEW TARGET ---");
            
            int currentSessionId = ++globalSessionCount;
            String clientIp = "Unknown";
            
            // Extract the attacker's IP address from the socket descriptor
            int fd = ssh_get_fd(session);
            if (fd >= 0) {
                struct sockaddr_in peer_addr;
                socklen_t peer_len = sizeof(peer_addr);
                if (getpeername(fd, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
                    clientIp = inet_ntoa(peer_addr.sin_addr);
                }
            }

            if (ssh_handle_key_exchange(session) == SSH_OK) {
                ssh_message message;
                bool authenticated = false;
                
                // 1. Password Interception Loop
                while ((message = ssh_message_get(session))) {
                    if (ssh_message_type(message) == SSH_REQUEST_AUTH && 
                        ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                        
                        String user = ssh_message_auth_user(message);
                        String pass = ssh_message_auth_password(message);
                        
                        pushLog("U: " + user + " | P: " + pass);
                        // Send the attempted login credentials as a command log
                        sendLogToServer(clientIp, currentSessionId, "LOGIN ATTEMPT - User: " + user + " Pass: " + pass);
                        
                        // Let them in regardless of what they typed!
                        ssh_message_auth_reply_success(message, 0);
                        ssh_message_free(message);
                        authenticated = true;
                        break; 
                    }
                    ssh_message_reply_default(message);
                    ssh_message_free(message);
                }

                if (authenticated) {
                    ssh_channel channel = NULL;
                    
                    // 2. Open Shell Channel
                    while ((message = ssh_message_get(session))) {
                        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN) {
                            channel = ssh_message_channel_request_open_reply_accept(message);
                            ssh_message_free(message);
                            break;
                        }
                        ssh_message_reply_default(message);
                        ssh_message_free(message);
                    }

                    // 3. Accept PTY / Shell environment requests
                    if (channel) {
                        while ((message = ssh_message_get(session))) {
                            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                                ssh_message_channel_request_reply_success(message);
                                int subtype = ssh_message_subtype(message);
                                ssh_message_free(message);
                                if (subtype == SSH_CHANNEL_REQUEST_SHELL) break; // Start terminal
                            } else {
                                ssh_message_reply_default(message);
                                ssh_message_free(message);
                            }
                        }

                        // 4. Fake Bash Terminal Loop
                        ssh_channel_write(channel, "\r\nWelcome to Ubuntu 20.04.4 LTS\r\n\r\nroot@ubuntu:~# ", 50);
                        
                        char buffer[256];
                        int nbytes;
                        String cmd = "";
                        
                        while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
                            for(int i=0; i<nbytes; i++) {
                                char c = buffer[i];
                                ssh_channel_write(channel, &c, 1); // Echo character
                                
                                if (c == '\r' || c == '\n') {
                                    cmd.trim();
                                    if (cmd.length() > 0) {
                                        pushLog("> " + cmd);
                                        
                                        // Send the executed command to your log server
                                        sendLogToServer(clientIp, currentSessionId, cmd);
                                        
                                        if (cmd == "ls") {
                                            ssh_channel_write(channel, "\r\nbin boot dev etc home lib root sys usr var\r\n", 46);
                                        } else if (cmd == "whoami") {
                                            ssh_channel_write(channel, "\r\nroot\r\n", 8);
                                        } else if (cmd == "exit") {
                                            goto end_session; // Break out of everything
                                        } else {
                                            String err = "\r\nbash: " + cmd + ": command not found\r\n";
                                            ssh_channel_write(channel, err.c_str(), err.length());
                                        }
                                        cmd = "";
                                    }
                                    ssh_channel_write(channel, "root@ubuntu:~# ", 15);
                                } else {
                                    cmd += c;
                                }
                            }
                        }
                    }
                    end_session:
                    if (channel) {
                        ssh_channel_close(channel);
                        ssh_channel_free(channel);
                    }
                }
            }
            pushLog("--- DISCONNECTED ---");
        }
        ssh_disconnect(session);
        ssh_free(session);
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

// ----------------------------------------------------
// Wi-Fi & General Operations
// ----------------------------------------------------
void connectToWiFi(String password) {
    currentState = STATE_CONNECTING;
    printState();
    WiFi.begin(selectedSSID.c_str(), password.c_str());

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) delay(500);

    if (WiFi.status() == WL_CONNECTED) {
        // Now we wait for the target IP instead of jumping straight to HONEYPOT
        currentState = STATE_AWAITING_TARGET;
        printState();
    } else {
        Serial.println("\n[!] Connection failed. Please try again.");
        currentState = STATE_SELECTING;
        printState();
    }
}

void processCommand(String cmd) {
    cmd.trim();
    if (cmd.length() == 0) return;

    if (currentState == STATE_AWAITING_PASSWORD) {
        connectToWiFi(cmd);
        return;
    }

    if (currentState == STATE_AWAITING_TARGET) {
        int colonIndex = cmd.indexOf(':');
        if (colonIndex > 0) {
            targetHost = cmd.substring(0, colonIndex);
            targetPort = cmd.substring(colonIndex + 1).toInt();
            
            currentState = STATE_HONEYPOT;
            printState();
            
            // Spin up the SSH server only after we have the target log server
            xTaskCreate(sshHoneypotTask, "SSH_Task", 16384, NULL, 1, &sshTaskHandle);
        } else {
            Serial.println("\n[!] Invalid format. Please use IP:PORT (e.g. 192.168.1.10:8000)");
        }
        return;
    }

    cmd.toUpperCase();
    if (cmd == "SCAN") {
        currentState = STATE_SCANNING;
        printState();
        networkCount = WiFi.scanNetworks();
        selectedIndex = 0;
        currentState = (networkCount == 0) ? STATE_IDLE : STATE_SELECTING;
        printState();
    } 
    else if (cmd == "STOP") {
        WiFi.disconnect();
        if (sshTaskHandle != NULL) {
            vTaskDelete(sshTaskHandle);
            sshTaskHandle = NULL;
        }
        currentState = STATE_IDLE;
        printState();
    } 
    else if (currentState == STATE_SELECTING) {
        if (cmd == "W" && selectedIndex > 0) selectedIndex--;
        else if (cmd == "S" && selectedIndex < networkCount - 1) selectedIndex++;
        else if (cmd == "C") {
            selectedSSID = WiFi.SSID(selectedIndex);
            currentState = STATE_AWAITING_PASSWORD;
        }
        printState();
    } else {
        Serial.println("\n[!] Invalid command for current state.");
    }
}

void setup() {
    Serial.begin(115200);
    
    if (!SPIFFS.begin(true)) {
        Serial.println("SPIFFS Mount Failed");
    }

    libssh_begin(); 

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    Serial.println("\nHardware Initialized. Commands: SCAN, STOP, W, S, C");
    printState();
}

void loop() {
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') {
            if (inputBuffer.length() > 0) {
                processCommand(inputBuffer);
                inputBuffer = "";
            }
        } else {
            inputBuffer += c;
        }
    }
}
