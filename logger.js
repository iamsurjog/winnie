const net = require('net');

const PORT = 5000; // Match this with the port you enter in the Serial Monitor
const HOST = '0.0.0.0'; // Listen on all network interfaces

const server = net.createServer((socket) => {
    let buffer = '';

    // Collect data chunks as they come in
    socket.on('data', (data) => {
        buffer += data.toString();
    });

    // Parse the JSON once the ESP32 closes the connection
    socket.on('end', () => {
        if (buffer.trim()) {
            try {
                const log = JSON.parse(buffer);
                
                // Print it out nicely formatted
                console.log('\n[🚨] NEW HONEYPOT EVENT');
                console.log(` ├─ Target IP  : ${log.ip}`);
                console.log(` ├─ Session ID : ${log.session}`);
                console.log(` └─ Action     : ${log.command}`);
                
            } catch (err) {
                console.error('\n[!] Failed to parse incoming JSON.');
                console.error(` └─ Raw data: ${buffer.trim()}`);
            }
        }
    });

    socket.on('error', (err) => {
        console.error(`[!] Socket error: ${err.message}`);
    });
});

server.listen(PORT, HOST, () => {
    console.log(`[*] TCP Log Server active and listening on port ${PORT}`);
    console.log(`[*] When the ESP32 asks, enter your laptop's IP and this port (e.g., 10.119.7.131:${PORT})`);
});
