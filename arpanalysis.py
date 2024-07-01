import os
import time
from scapy.all import ARP, arping, Ether, sr1, sniff

# Direccion IP del router
router_ip = input("IP del router: ")

# Obtener la direccion MAC real del router
def get_true_mac(ip):
    ans, _ = arping(ip, timeout=2, verbose=False)
    for snt, rcv in ans:
        return rcv[Ether].src
    return None

# Obtener la direccion MAC actual del router desde la tabla ARP
def get_current_mac(ip):
    arp_response = os.popen(f"arp -a {ip}").read()
    for line in arp_response.split("\n"):
        if ip in line:
            return line.split()[3]
    return None

# Comparar las direcciones MAC y detectar spoofing
def monitor_arp(router_ip, true_mac):
    while True:
        current_mac = get_current_mac(router_ip)
        if current_mac:
            if current_mac != true_mac:
                print("ALERTA: ARP spoofing detectado! Direccion MAC actual" ,current_mac, "no coincide con la direccion MAC verdadera" , true_mac)
            else:
                print("La tabla ARP es correcta.")
        else:
            print("Error: No se pudo obtener la direccion MAC actual para", router_ip)
        time.sleep(10)  # Esperar 10 segundos antes de volver a verificar

# Obtener la direccion MAC verdadera del router
true_mac = get_true_mac(router_ip)
if true_mac:
    print("La direccion MAC verdadera del router es:", true_mac)
    monitor_arp(router_ip, true_mac)
else:
    print("Error: No se pudo obtener la direccion MAC verdadera para", router_ip)
