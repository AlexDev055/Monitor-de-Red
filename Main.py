from scapy.all import sniff

def analizar_paquete(paquete):
    if paquete.haslayer("IP"):
        ip_origen = paquete["IP"].src
        ip_destino = paquete["IP"].dst
        print(f"Paquete detectado de {ip_origen} a {ip_destino}")
        
    
        if paquete.haslayer("TCP"):
            puerto_destino = paquete["TCP"].dport
            print(f"Intento de conexión a puerto: {puerto_destino}")
   
sniff(prn=analizar_paquete, store=0, count=100)
