/**
 * Servidor principal para Packet Sniffer Dashboard
 * Puerto: 8080
 * API Endpoints:
 *   POST /api/packets - Recibir paquetes
 *   GET  /api/packets - Obtener últimos paquetes
 *   GET  /api/stats   - Obtener estadísticas
 *   GET  /           - Dashboard principal
 */

const express = require('express');
const app = express();
const port = 8080;

// Middleware
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Almacenamiento en memoria
let packets = [];
let stats = {
    totalPackets: 0,
    totalBytes: 0,
    startTime: new Date(),
    byProtocol: {},
    bySourceIP: {},
    byDestinationIP: {},
    byPort: {}
};

// Función para obtener protocolo por número
function getProtocolName(protoNum) {
    const protocols = {
        '1': 'ICMP',
        '2': 'IGMP',
        '6': 'TCP',
        '17': 'UDP',
        '41': 'IPv6',
        '89': 'OSPF'
    };
    return protocols[protoNum] || `Proto ${protoNum}`;
}

// Ruta para recibir paquetes
app.post('/api/packets', (req, res) => {
    try {
        const packet = req.body;
        packet.receivedAt = new Date();
        
        // Extraer información básica
        const layers = packet.layers || {};
        const frame = layers.frame || {};
        const ip = layers.ip || {};
        
        // Estadísticas del paquete
        const packetInfo = {
            timestamp: packet.receivedAt,
            srcIp: ip.ip_ip_src || 'Unknown',
            dstIp: ip.ip_ip_dst || 'Unknown',
            protocol: ip.ip_ip_proto || '0',
            protocolName: getProtocolName(ip.ip_ip_proto),
            length: parseInt(frame.frame_len || 0),
            srcPort: layers.tcp ? layers.tcp.tcp_srcport : layers.udp ? layers.udp.udp_srcport : 'N/A',
            dstPort: layers.tcp ? layers.tcp.tcp_dstport : layers.udp ? layers.udp.udp_dstport : 'N/A',
            raw: packet
        };
        
        // Guardar paquete
        packets.push(packetInfo);
        
        // Actualizar estadísticas
        stats.totalPackets++;
        stats.totalBytes += packetInfo.length;
        
        // Por protocolo
        const protoKey = packetInfo.protocolName;
        stats.byProtocol[protoKey] = (stats.byProtocol[protoKey] || 0) + 1;
        
        // Por IP origen
        if (packetInfo.srcIp !== 'Unknown') {
            stats.bySourceIP[packetInfo.srcIp] = (stats.bySourceIP[packetInfo.srcIp] || 0) + 1;
        }
        
        // Por IP destino
        if (packetInfo.dstIp !== 'Unknown') {
            stats.byDestinationIP[packetInfo.dstIp] = (stats.byDestinationIP[packetInfo.dstIp] || 0) + 1;
        }
        
        // Por puerto (si existe)
        if (packetInfo.dstPort !== 'N/A') {
            const portKey = `${packetInfo.dstPort}/${packetInfo.protocolName}`;
            stats.byPort[portKey] = (stats.byPort[portKey] || 0) + 1;
        }
        
        // Limitar memoria - mantener últimos 5000 paquetes
        if (packets.length > 5000) {
            packets = packets.slice(-4000);
        }
        
        res.status(200).json({ 
            status: 'success', 
            message: 'Packet received',
            packetId: packets.length 
        });
        
    } catch (error) {
        console.error('Error processing packet:', error);
        res.status(500).json({ 
            status: 'error', 
            message: 'Internal server error' 
        });
    }
});

// Obtener últimos paquetes
app.get('/api/packets', (req, res) => {
    const limit = parseInt(req.query.limit) || 100;
    const filteredPackets = packets.slice(-limit);
    res.json({
        total: packets.length,
        packets: filteredPackets
    });
});

// Obtener estadísticas
app.get('/api/stats', (req, res) => {
    const uptime = Date.now() - stats.startTime;
    const packetsPerSecond = (stats.totalPackets / (uptime / 1000)).toFixed(2);
    const bytesPerSecond = (stats.totalBytes / (uptime / 1000)).toFixed(2);
    
    res.json({
        summary: {
            totalPackets: stats.totalPackets,
            totalBytes: stats.totalBytes,
            uptime: Math.floor(uptime / 1000),
            packetsPerSecond: packetsPerSecond,
            bytesPerSecond: bytesPerSecond,
            startTime: stats.startTime
        },
        byProtocol: stats.byProtocol,
        bySourceIP: Object.entries(stats.bySourceIP)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {}),
        byDestinationIP: Object.entries(stats.byDestinationIP)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {}),
        byPort: Object.entries(stats.byPort)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {})
    });
});

// Ruta raíz - dashboard
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Ruta de salud
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        packetsReceived: stats.totalPackets,
        uptime: Math.floor((Date.now() - stats.startTime) / 1000)
    });
});

// Iniciar servidor
app.listen(port, () => {
    console.log('='.repeat(60));
    console.log('📡 PACKET SNIFFER DASHBOARD');
    console.log('='.repeat(60));
    console.log(`✅ Servidor corriendo en: http://localhost:${port}`);
    console.log(`📊 Dashboard: http://localhost:${port}/`);
    console.log(`📝 API Health: http://localhost:${port}/health`);
    console.log(`📨 Enviar paquetes a: http://localhost:${port}/api/packets`);
    console.log('='.repeat(60));
    console.log('\n📋 COMANDOS PARA ENVIAR PAQUETES:');
    console.log('Linux/Mac:');
    console.log('  sudo tshark -i eth0 -T ek | curl -X POST http://localhost:8080/api/packets \\');
    console.log('    -H "Content-Type: application/json" --data-binary @-');
    console.log('\nWindows (PowerShell):');
    console.log('  tshark -i Ethernet0 -T ek | curl.exe -X POST http://localhost:8080/api/packets \\');
    console.log('    -H "Content-Type: application/json" --data-binary @-');
    console.log('='.repeat(60));
});