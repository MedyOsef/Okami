import pyshark
import ipaddress
import threading
from collections import namedtuple, deque
from queue import Queue

# Définition d'une structure légère pour stocker les paquets
PacketInfo = namedtuple('PacketInfo', ['sniff_timestamp', 'layer', 'srcPort', 'dstPort', 'ipSrc', 'ipDst', 'highest_layer'])

# File d'attente pour les paquets capturés
packet_queue = Queue()

# Utilisation d'une file d'attente pour éviter les pertes de paquets
def packet_handler(packet):
    packet_queue.put(packet)

# Fonction pour déterminer si une adresse IP est privée
def is_private_ip(ip_address):
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

# Fonction pour filtrer et traiter les paquets
def process_packet(packet):
    try:
        # On filtre les paquets ICMP
        if hasattr(packet, 'icmp'):
            p_info = PacketInfo(
                sniff_timestamp=packet.sniff_timestamp,
                layer='ICMP',
                srcPort='',
                dstPort='',
                ipSrc=packet.ip.src,
                ipDst=packet.ip.dst,
                highest_layer=packet.highest_layer
            )
            print(f"ICMP packet: {p_info.ipSrc} > {p_info.ipDst}")
            return

        # On traite les paquets TCP/UDP
        if packet.transport_layer in ['TCP', 'UDP']:
            if hasattr(packet, 'ipv6'):
                return  # On ignore les paquets IPv6

            if hasattr(packet, 'ip'):
                if is_private_ip(packet.ip.src) and is_private_ip(packet.ip.dst):
                    # On capture les informations pertinentes
                    layer = packet.transport_layer
                    src_port = getattr(packet[layer.lower()], 'srcport', '')
                    dst_port = getattr(packet[layer.lower()], 'dstport', '')

                    p_info = PacketInfo(
                        sniff_timestamp=packet.sniff_timestamp,
                        layer=layer,
                        srcPort=src_port,
                        dstPort=dst_port,
                        ipSrc=packet.ip.src,
                        ipDst=packet.ip.dst,
                        highest_layer=packet.highest_layer
                    )
                    output = f"{p_info.layer} {p_info.ipSrc}:{p_info.srcPort} > {p_info.ipDst}:{p_info.dstPort}"
                    print(output)
    except AttributeError as e:
        pass  # On ignore les paquets qui ne contiennent pas les attributs nécessaires

# Fonction pour traiter les paquets en continu
def packet_processor():
    while True:
        packet = packet_queue.get()
        process_packet(packet)
        packet_queue.task_done()

# Initialisation de la capture sur l'interface réseau spécifiée
intF = 'Ethernet 2'
capture = pyshark.LiveCapture(interface=intF)

# Lancement d'un thread pour le traitement des paquets
threading.Thread(target=packet_processor, daemon=True).start()

# Capture des paquets en continu avec gestion asynchrone
capture.apply_on_packets(packet_handler)
