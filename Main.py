from scapy.all import sniff

# Definir una función de análisis de paquetes
def analizar_paquete(paquete):
    if paquete.haslayer("IP"):
        ip_origen = paquete["IP"].src
        ip_destino = paquete["IP"].dst
        print(f"Paquete detectado de {ip_origen} a {ip_destino}")
        
        # Verificar intentos sospechosos
        if paquete.haslayer("TCP"):
            puerto_destino = paquete["TCP"].dport
            print(f"Intento de conexión a puerto: {puerto_destino}")
            # Aquí puedes añadir lógica para alertas si detectas muchos intentos desde la misma IP
            
# Capturar tráfico en la red
sniff(prn=analizar_paquete, store=0, count=100)

#kal#a