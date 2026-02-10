/**
 * Dashboard JavaScript - Packet Sniffer
 * Controla la interfaz y actualización en tiempo real
 */

// Configuración
const CONFIG = {
    UPDATE_INTERVAL: 2000, // 2 segundos
    MAX_PACKETS_DISPLAY: 50,
    SERVER_URL: window.location.origin
};

// Estado global
let state = {
    packets: [],
    stats: {},
    lastUpdate: null,
    charts: {},
    packetsPerSecond: 0,
    lastPacketCount: 0,
    lastSecond: Math.floor(Date.now() / 1000)
};

// Inicializar gráficos
function initializeCharts() {
    const protocolColors = {
        'TCP': '#10b981',
        'UDP': '#f59e0b',
        'ICMP': '#ef4444',
        'IGMP': '#8b5cf6',
        'IPv6': '#3b82f6',
        'OSPF': '#ec4899'
    };

    // Gráfico de protocolos
    state.charts.protocol = new Chart(
        document.getElementById('protocolChart').getContext('2d'),
        {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [],
                    borderWidth: 2,
                    borderColor: '#1e293b'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#94a3b8',
                            padding: 20
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.raw || 0;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        }
    );

    // Gráfico de actividad
    state.charts.activity = new Chart(
        document.getElementById('activityChart').getContext('2d'),
        {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Paquetes por segundo',
                    data: [],
                    borderColor: '#60a5fa',
                    backgroundColor: 'rgba(96, 165, 250, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8',
                            maxRotation: 0
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#94a3b8'
                        }
                    }
                }
            }
        }
    );

    // Gráfico de IPs origen
    state.charts.source = new Chart(
        document.getElementById('sourceChart').getContext('2d'),
        {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Paquetes',
                    data: [],
                    backgroundColor: '#10b981',
                    borderColor: '#10b981',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    },
                    y: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        }
    );

    // Gráfico de IPs destino
    state.charts.destination = new Chart(
        document.getElementById('destinationChart').getContext('2d'),
        {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Paquetes',
                    data: [],
                    backgroundColor: '#8b5cf6',
                    borderColor: '#8b5cf6',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    },
                    y: {
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        ticks: {
                            color: '#94a3b8'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        }
    );
}

// Actualizar estadísticas
async function updateStats() {
    try {
        const response = await fetch(`${CONFIG.SERVER_URL}/api/stats`);
        if (!response.ok) throw new Error('Error en la respuesta');
        
        const data = await response.json();
        state.stats = data;
        
        // Actualizar tarjetas
        document.getElementById('totalPackets').textContent = 
            data.summary.totalPackets.toLocaleString();
        
        document.getElementById('packetsPerSecond').textContent = 
            parseFloat(data.summary.packetsPerSecond).toFixed(1);
        
        document.getElementById('totalTraffic').textContent = 
            formatBytes(data.summary.totalBytes);
        
        document.getElementById('uptime').textContent = 
            formatUptime(data.summary.uptime);
        
        // Actualizar gráfico de protocolos
        updateProtocolChart(data.byProtocol);
        
        // Actualizar gráficos de IPs
        updateIPCharts(data);
        
        // Actualizar status del servidor
        updateServerStatus(true);
        
    } catch (error) {
        console.error('Error actualizando estadísticas:', error);
        updateServerStatus(false);
    }
}

// Actualizar tabla de paquetes
async function updatePacketsTable() {
    try {
        const response = await fetch(`${CONFIG.SERVER_URL}/api/packets?limit=${CONFIG.MAX_PACKETS_DISPLAY}`);
        if (!response.ok) throw new Error('Error en la respuesta');
        
        const data = await response.json();
        state.packets = data.packets;
        
        const tableBody = document.getElementById('packetsTableBody');
        tableBody.innerHTML = '';
        
        // Ordenar por tiempo (más recientes primero)
        const recentPackets = [...state.packets].reverse();
        
        recentPackets.forEach((packet, index) => {
            const row = document.createElement('tr');
            
            const time = new Date(packet.timestamp).toLocaleTimeString();
            const protocolClass = getProtocolClass(packet.protocolName);
            
            row.innerHTML = `
                <td>${time}</td>
                <td><span class="ip-address">${packet.srcIp}</span></td>
                <td><span class="ip-address">${packet.dstIp}</span></td>
                <td><span class="protocol-badge ${protocolClass}">${packet.protocolName}</span></td>
                <td>${packet.dstPort}</td>
                <td>${packet.length.toLocaleString()} B</td>
                <td>
                    <button class="btn btn-sm view-packet" data-index="${index}">
                        <i class="fas fa-eye"></i> Ver
                    </button>
                </td>
            `;
            
            tableBody.appendChild(row);
        });
        
        // Actualizar contador
        document.getElementById('packetCount').textContent = 
            `Mostrando ${Math.min(recentPackets.length, CONFIG.MAX_PACKETS_DISPLAY)} de ${data.total} paquetes`;
        
        // Añadir event listeners a los botones
        document.querySelectorAll('.view-packet').forEach(button => {
            button.addEventListener('click', (e) => {
                const index = parseInt(e.target.closest('.view-packet').dataset.index);
                showPacketDetails(recentPackets[index]);
            });
        });
        
    } catch (error) {
        console.error('Error actualizando tabla:', error);
    }
}

// Actualizar gráfico de actividad
function updateActivityChart() {
    const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    
    // Calcular paquetes por segundo
    const currentSecond = Math.floor(Date.now() / 1000);
    if (currentSecond > state.lastSecond) {
        state.packetsPerSecond = state.lastPacketCount;
        state.lastPacketCount = 0;
        state.lastSecond = currentSecond;
    }
    
    // Añadir nuevo punto
    state.charts.activity.data.labels.push(now);
    state.charts.activity.data.datasets[0].data.push(state.packetsPerSecond);
    
    // Mantener solo últimos 20 puntos
    if (state.charts.activity.data.labels.length > 20) {
        state.charts.activity.data.labels.shift();
        state.charts.activity.data.datasets[0].data.shift();
    }
    
    state.charts.activity.update('none');
}

// Actualizar gráfico de protocolos
function updateProtocolChart(protocolData) {
    const entries = Object.entries(protocolData).sort((a, b) => b[1] - a[1]);
    
    state.charts.protocol.data.labels = entries.map(([proto]) => proto);
    state.charts.protocol.data.datasets[0].data = entries.map(([, count]) => count);
    
    // Asignar colores
    state.charts.protocol.data.datasets[0].backgroundColor = entries.map(([proto]) => {
        const colorMap = {
            'TCP': '#10b981',
            'UDP': '#f59e0b',
            'ICMP': '#ef4444',
            'IGMP': '#8b5cf6',
            'IPv6': '#3b82f6',
            'OSPF': '#ec4899'
        };
        return colorMap[proto] || '#8b5cf6';
    });
    
    state.charts.protocol.update();
}

// Actualizar gráficos de IPs
function updateIPCharts(data) {
    // IPs Origen
    const sourceEntries = Object.entries(data.bySourceIP);
    state.charts.source.data.labels = sourceEntries.map(([ip]) => ip);
    state.charts.source.data.datasets[0].data = sourceEntries.map(([, count]) => count);
    state.charts.source.update();
    
    // IPs Destino
    const destEntries = Object.entries(data.byDestinationIP);
    state.charts.destination.data.labels = destEntries.map(([ip]) => ip);
    state.charts.destination.data.datasets[0].data = destEntries.map(([, count]) => count);
    state.charts.destination.update();
}

// Mostrar detalles del paquete
function showPacketDetails(packet) {
    const modal = document.getElementById('packetModal');
    const details = document.getElementById('packetDetails');
    
    // Formatear JSON para visualización
    const formatted = JSON.stringify(packet.raw, null, 2);
    details.textContent = formatted;
    
    modal.style.display = 'flex';
    
    // Cerrar modal
    document.querySelector('.close-modal').onclick = () => {
        modal.style.display = 'none';
    };
    
    // Cerrar al hacer clic fuera
    modal.onclick = (e) => {
        if (e.target === modal) {
            modal.style.display = 'none';
        }
    };
}

// Actualizar estado del servidor
function updateServerStatus(isConnected) {
    const indicator = document.getElementById('statusIndicator');
    const statusText = document.getElementById('statusText');
    
    if (isConnected) {
        indicator.className = 'status-indicator connected';
        statusText.textContent = 'Conectado al servidor';
        statusText.style.color = '#10b981';
    } else {
        indicator.className = 'status-indicator';
        statusText.textContent = 'Desconectado';
        statusText.style.color = '#ef4444';
    }
}

// Funciones de utilidad
function getProtocolClass(protocol) {
    const map = {
        'TCP': 'tcp',
        'UDP': 'udp',
        'ICMP': 'icmp',
        'IGMP': 'other',
        'IPv6': 'other',
        'OSPF': 'other'
    };
    return map[protocol] || 'other';
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    
    if (hours > 0) {
        return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${secs}s`;
    } else {
        return `${secs}s`;
    }
}

// Función principal de actualización
async function updateDashboard() {
    try {
        await updateStats();
        await updatePacketsTable();
        updateActivityChart();
        
        // Incrementar contador de paquetes para cálculo por segundo
        if (state.packets.length > state.lastPacketCount) {
            state.lastPacketCount = state.packets.length;
        }
        
    } catch (error) {
        console.error('Error en updateDashboard:', error);
    }
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Inicializar gráficos
    initializeCharts();
    
    // Actualizar dashboard periódicamente
    setInterval(updateDashboard, CONFIG.UPDATE_INTERVAL);
    
    // Actualizar inmediatamente
    updateDashboard();
    
    // Botón de actualizar
    document.getElementById('refreshBtn').addEventListener('click', updateDashboard);
    
    // Botón de limpiar (solo frontend)
    document.getElementById('clearBtn').addEventListener('click', () => {
        if (confirm('¿Limpiar la tabla de paquetes? (Esto solo afecta la visualización)')) {
            document.getElementById('packetsTableBody').innerHTML = '';
            document.getElementById('packetCount').textContent = 'Mostrando 0 paquetes';
        }
    });
    
    // Mostrar URL del servidor
    document.getElementById('serverUrl').textContent = CONFIG.SERVER_URL;
});