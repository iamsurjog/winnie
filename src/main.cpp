#include <Arduino.h>
#include <WiFi.h>
#include <SPIFFS.h>
#include <WiFiClient.h>
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
    STATE_AWAITING_TARGET,
    STATE_HONEYPOT
};

AppState currentState = STATE_IDLE;
int networkCount = 0;
int selectedIndex = 0;
String selectedSSID = "";
String inputBuffer = "";

String targetHost = "";
uint16_t targetPort = 0;
int globalSessionCount = 0; 

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
// Virtual Filesystem Helper
// ----------------------------------------------------
String resolvePath(String cwd, String arg) {
    if (arg == "" || arg == "~") return "/root";
    if (arg == "/") return "/";
    
    String newPath = cwd;
    if (arg.startsWith("/")) {
        newPath = arg; // Absolute path
    } else {
        if (arg == "..") {
            if (cwd == "/") return "/";
            int lastSlash = cwd.lastIndexOf('/');
            if (lastSlash == 0) return "/";
            return cwd.substring(0, lastSlash);
        } else if (arg == ".") {
            return cwd;
        } else {
            if (cwd != "/") newPath += "/";
            newPath += arg;
        }
    }
    
    // Strip trailing slashes for consistency
    if (newPath.length() > 1 && newPath.endsWith("/")) {
        newPath = newPath.substring(0, newPath.length() - 1);
    }
    return newPath;
}

// ----------------------------------------------------
// UI Logic (Serial)
// ----------------------------------------------------
void pushLog(String msg) { Serial.println("[LOG] " + msg); }

void printState() {
    Serial.println("\n========================================");
    switch (currentState) {
        case STATE_IDLE: Serial.println("SSH Pot: IDLE\nSend 'SCAN' to start"); break;
        case STATE_SCANNING: Serial.println("Scanning... Searching networks..."); break;
        case STATE_SELECTING:
            Serial.println("Select Network (W/S to scroll, C to connect)");
            for (int i = 0; i < networkCount; i++) {
                Serial.print(i == selectedIndex ? " > " : "   ");
                Serial.print(WiFi.SSID(i));
                Serial.println(" (" + String(WiFi.RSSI(i)) + ")");
            }
            break;
        case STATE_AWAITING_PASSWORD: Serial.println("Enter Password for:\n" + selectedSSID); break;
        case STATE_CONNECTING: Serial.println("Connecting..."); break;
        case STATE_AWAITING_TARGET: Serial.println("Wi-Fi Connected!\nEnter logging server IP:PORT (e.g. 192.168.1.50:8080)"); break;
        case STATE_HONEYPOT:
            Serial.println("SSH POT ACTIVE");
            Serial.println("Local IP: " + WiFi.localIP().toString());
            Serial.println("Logging to: " + targetHost + ":" + String(targetPort));
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
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/spiffs/ssh_host_rsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        pushLog("BIND ERR! Key missing?");
        vTaskDelete(NULL);
    }

    pushLog("Listening on port 22");

    while (true) {
        ssh_session session = ssh_new();
        if (ssh_bind_accept(sshbind, session) == SSH_OK) {
            pushLog("--- NEW TARGET ---");
            
            int currentSessionId = ++globalSessionCount;
            String clientIp = "Unknown";
            
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
                
                while ((message = ssh_message_get(session))) {
                    if (ssh_message_type(message) == SSH_REQUEST_AUTH && 
                        ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                        
                        String user = ssh_message_auth_user(message);
                        String pass = ssh_message_auth_password(message);
                        sendLogToServer(clientIp, currentSessionId, "LOGIN: " + user + " / " + pass);
                        
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
                    
                    while ((message = ssh_message_get(session))) {
                        if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN) {
                            channel = ssh_message_channel_request_open_reply_accept(message);
                            ssh_message_free(message);
                            break;
                        }
                        ssh_message_reply_default(message);
                        ssh_message_free(message);
                    }

                    if (channel) {
                        while ((message = ssh_message_get(session))) {
                            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                                ssh_message_channel_request_reply_success(message);
                                int subtype = ssh_message_subtype(message);
                                ssh_message_free(message);
                                if (subtype == SSH_CHANNEL_REQUEST_SHELL) break;
                            } else {
                                ssh_message_reply_default(message);
                                ssh_message_free(message);
                            }
                        }

                        // Start Fake Bash
                        String initialPrompt = "\r\nWelcome to Ubuntu 20.04.4 LTS\r\n\r\nroot@ubuntu:~# ";
                        ssh_channel_write(channel, initialPrompt.c_str(), initialPrompt.length());
                        
                        char buffer[256];
                        int nbytes;
                        String cmd = "";
                        String cwd = "/root";
                        
                        while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
                            for(int i=0; i<nbytes; i++) {
                                char c = buffer[i];
                                
                                if (c == '\n') continue; // Ignore raw newline to prevent double execution
                                
                                if (c == '\r') {
                                    ssh_channel_write(channel, "\r\n", 2); // Echo the enter key
                                    cmd.trim();
                                    
                                    if (cmd.length() > 0) {
                                        sendLogToServer(clientIp, currentSessionId, cmd);
                                        
                                        int spaceIdx = cmd.indexOf(' ');
                                        String baseCmd = cmd;
                                        String args = "";
                                        if (spaceIdx > 0) {
                                            baseCmd = cmd.substring(0, spaceIdx);
                                            args = cmd.substring(spaceIdx + 1);
                                            args.trim();
                                        }

                                        auto writeLine = [&](String s) {
                                            if (s.length() > 0) {
                                                String out = s + "\r\n";
                                                ssh_channel_write(channel, out.c_str(), out.length());
                                            }
                                        };

                                        // Command Emulation Router
                                        if (baseCmd == "exit") goto end_session;
                                        else if (baseCmd == "pwd") writeLine(cwd);
                                        else if (baseCmd == "whoami") writeLine("root");
                                        else if (baseCmd == "id") writeLine("uid=0(root) gid=0(root) groups=0(root)");
                                        else if (baseCmd == "uname") {
                                            if (args == "-a") writeLine("Linux ubuntu 5.4.0-104-generic #118-Ubuntu SMP Thu Mar 3 13:59:15 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux");
                                            else writeLine("Linux");
                                        } else if (baseCmd == "cd") {
                                            cwd = resolvePath(cwd, args);
                                        } else if (baseCmd == "ls") {
                                            String target = args.length() > 0 ? resolvePath(cwd, args) : cwd;
                                            if (target == "/") writeLine("bin boot dev etc home lib media mnt opt proc root run sbin srv sys tmp usr var");
                                            else if (target == "/root") writeLine("snap .bash_history .ssh install.sh");
                                            else if (target == "/etc") writeLine("passwd shadow ssh network init.d");
                                            else if (target == "/var") writeLine("log tmp run lib backups");
                                            else if (target == "/tmp") writeLine("systemd-private-xyz.service");
                                        } else if (baseCmd == "cat") {
                                            if (args == "") writeLine("cat: missing operand");
                                            else {
                                                String target = resolvePath(cwd, args);
                                                if (target == "/etc/passwd") writeLine("root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
                                                else if (target == "/etc/shadow") writeLine("root:$6$xyz123abc:18000:0:99999:7:::\r\ndaemon:*:18000:0:99999:7:::");
                                                else writeLine("cat: " + args + ": No such file or directory");
                                            }
                                        } else if (baseCmd == "echo") writeLine(args);
                                        else if (baseCmd == "touch" || baseCmd == "mkdir" || baseCmd == "rm") {
                                            if (args == "") writeLine(baseCmd + ": missing operand");
                                            // Act as silent success otherwise
                                        } else if (baseCmd == "wget" || baseCmd == "curl") {
                                            if (args == "") writeLine(baseCmd + ": missing URL");
                                            else writeLine("Connecting to " + args + " (10.0.0.1:80)\r\nHTTP request sent, awaiting response... 200 OK\r\nLength: 1024 [application/x-sh]\r\nSaved!");
                                        } else if (baseCmd == "help") {
                                            writeLine("GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)\r\nThese shell commands are defined internally.");
                                        } else {
                                            writeLine(baseCmd + ": command not found");
                                        }
                                        cmd = "";
                                    }
                                    
                                    // Construct and send the prompt with the updated path
                                    String p = "root@ubuntu:";
                                    p += (cwd == "/root") ? "~" : cwd;
                                    p += "# ";
                                    ssh_channel_write(channel, p.c_str(), p.length());
                                    
                                } else if (c == '\b' || c == 0x7F) {
                                    // Handle Backspace Visually
                                    if (cmd.length() > 0) {
                                        cmd = cmd.substring(0, cmd.length() - 1);
                                        ssh_channel_write(channel, "\b \b", 3);
                                    }
                                } else {
                                    cmd += c;
                                    ssh_channel_write(channel, &c, 1);
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
// Core Controls (Same as before)
// ----------------------------------------------------
void connectToWiFi(String password) {
    currentState = STATE_CONNECTING;
    printState();
    WiFi.begin(selectedSSID.c_str(), password.c_str());

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) delay(500);

    if (WiFi.status() == WL_CONNECTED) {
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

    if (currentState == STATE_AWAITING_PASSWORD) { connectToWiFi(cmd); return; }
    if (currentState == STATE_AWAITING_TARGET) {
        int colonIndex = cmd.indexOf(':');
        if (colonIndex > 0) {
            targetHost = cmd.substring(0, colonIndex);
            targetPort = cmd.substring(colonIndex + 1).toInt();
            currentState = STATE_HONEYPOT;
            printState();
            xTaskCreate(sshHoneypotTask, "SSH_Task", 16384, NULL, 1, &sshTaskHandle);
        } else {
            Serial.println("\n[!] Invalid format. Please use IP:PORT");
        }
        return;
    }

    String upperCmd = cmd;
    upperCmd.toUpperCase();
    
    if (upperCmd == "SCAN") {
        currentState = STATE_SCANNING;
        printState();
        networkCount = WiFi.scanNetworks();
        selectedIndex = 0;
        currentState = (networkCount == 0) ? STATE_IDLE : STATE_SELECTING;
        printState();
    } 
    else if (upperCmd == "STOP") {
        WiFi.disconnect();
        if (sshTaskHandle != NULL) {
            vTaskDelete(sshTaskHandle);
            sshTaskHandle = NULL;
        }
        currentState = STATE_IDLE;
        printState();
    } 
    else if (currentState == STATE_SELECTING) {
        if (upperCmd == "W" && selectedIndex > 0) selectedIndex--;
        else if (upperCmd == "S" && selectedIndex < networkCount - 1) selectedIndex++;
        else if (upperCmd == "C") {
            selectedSSID = WiFi.SSID(selectedIndex);
            currentState = STATE_AWAITING_PASSWORD;
        }
        printState();
    }
}

void setup() {
    Serial.begin(115200);
    SPIFFS.begin(true);
    libssh_begin(); 
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    Serial.println("\nCommands: SCAN, STOP, W, S, C");
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
        } else inputBuffer += c;
    }
}
