from scapy.all import sniff
from collections import defaultdict, deque
import time
import threading
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from datetime import datetime
import pandas as pd
import numpy as np

class NetworkMonitor:
    def __init__(self):
        # Almacenamiento de datos
        self.packet_counts = defaultdict(int)
        self.connection_history = defaultdict(lambda: deque(maxlen=100))
        self.port_scan_threshold = 10
        self.suspicious_ips = set()
        self.packet_queue = deque(maxlen=1000)
        self.lock = threading.Lock()
        
        # Métricas para detección de anomalías
        self.baseline_traffic = defaultdict(lambda: {
            'mean': 0,
            'std': 0,
            'samples': deque(maxlen=100)
        })

    def analizar_paquete(self, paquete):
        if not paquete.haslayer("IP"):
            return

        timestamp = datetime.now()
        ip_origen = paquete["IP"].src
        ip_destino = paquete["IP"].dst

        with self.lock:
            self.packet_counts[ip_origen] += 1
            
            packet_data = {
                'timestamp': timestamp,
                'src_ip': ip_origen,
                'dst_ip': ip_destino,
                'protocol': 'TCP' if paquete.haslayer("TCP") else 'UDP' if paquete.haslayer("UDP") else 'Other'
            }

            if paquete.haslayer("TCP"):
                packet_data['dst_port'] = paquete["TCP"].dport
                self.connection_history[ip_origen].append(packet_data['dst_port'])
                
                # Detección de escaneo de puertos
                if len(set(self.connection_history[ip_origen])) > self.port_scan_threshold:
                    self.suspicious_ips.add(ip_origen)
                    print(f"⚠️ Posible escaneo de puertos detectado desde {ip_origen}")

            self.packet_queue.append(packet_data)
            self.detect_anomalies(ip_origen)

    def detect_anomalies(self, ip):
        traffic_data = self.baseline_traffic[ip]
        current_count = self.packet_counts[ip]
        traffic_data['samples'].append(current_count)
        
        if len(traffic_data['samples']) > 10:
            mean = np.mean(traffic_data['samples'])
            std = np.std(traffic_data['samples'])
            z_score = (current_count - mean) / (std if std > 0 else 1)
            
            if abs(z_score) > 3:
                print(f"🚨 Anomalía detectada para IP {ip}: Z-score = {z_score:.2f}")

    def start_capture(self, count=None):
        print("Iniciando captura de paquetes...")
        sniff(prn=self.analizar_paquete, store=0, count=count)

class DashboardApp:
    def __init__(self, network_monitor):
        self.network_monitor = network_monitor
        self.app = dash.Dash(__name__)
        self.setup_layout()

    def setup_layout(self):
        self.app.layout = html.Div([
            html.H1("Monitor de Red en Tiempo Real"),
            
            html.Div([
                html.Div([
                    html.H3("Tráfico por IP"),
                    dcc.Graph(id='traffic-graph'),
                ], className='graph-container'),
                
                html.Div([
                    html.H3("Distribución de Protocolos"),
                    dcc.Graph(id='protocol-pie'),
                ], className='graph-container'),
                
                html.Div([
                    html.H3("IPs Sospechosas"),
                    html.Div(id='suspicious-ips'),
                ], className='alerts-container'),
            ]),
            
            dcc.Interval(
                id='interval-component',
                interval=1000,  # Actualización cada segundo
                n_intervals=0
            )
        ])

        self.setup_callbacks()

    def setup_callbacks(self):
        @self.app.callback(
            [Output('traffic-graph', 'figure'),
             Output('protocol-pie', 'figure'),
             Output('suspicious-ips', 'children')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_graphs(_):
            with self.network_monitor.lock:
                df = pd.DataFrame(list(self.network_monitor.packet_queue))
                
            if df.empty:
                return {}, {}, "No hay datos"

            # Gráfico de tráfico
            traffic_fig = go.Figure(data=[
                go.Bar(
                    x=list(self.network_monitor.packet_counts.keys()),
                    y=list(self.network_monitor.packet_counts.values())
                )
            ])
            traffic_fig.update_layout(
                title="Paquetes por IP",
                xaxis_title="IP",
                yaxis_title="Cantidad de Paquetes"
            )

            # Gráfico de protocolos
            protocol_counts = df['protocol'].value_counts()
            protocol_fig = go.Figure(data=[go.Pie(
                labels=protocol_counts.index,
                values=protocol_counts.values
            )])
            protocol_fig.update_layout(title="Distribución de Protocolos")

            # Lista de IPs sospechosas
            suspicious_ips_div = html.Div([
                html.P(f"IP Sospechosa: {ip}") 
                for ip in self.network_monitor.suspicious_ips
            ])

            return traffic_fig, protocol_fig, suspicious_ips_div

    def run_server(self, debug=False, port=8050):
        self.app.run_server(debug=debug, port=port)

def main():
    monitor = NetworkMonitor()
    dashboard = DashboardApp(monitor)
    
    # Iniciar la captura de paquetes en un hilo separado
    capture_thread = threading.Thread(target=monitor.start_capture)
    capture_thread.daemon = True
    capture_thread.start()
    
    # Iniciar el dashboard
    dashboard.run_server(debug=True)

if __name__ == "__main__":
    main()