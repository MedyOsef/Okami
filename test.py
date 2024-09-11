import pyshark
import netifaces
import ipaddress
import PySimpleGUI as sg


sg.theme("DarkGrey15")
pktsummarylist = []
updatepklist = False
menu_def = [['&File', ['!&Open', '&Save::savekey', '---', '&Properties', 'E&xit']], ['&Help', ['&About...']]]

layout = [[sg.Menu(menu_def)],
    [sg.Button("Start Capture", key="-startcap-"),
     sg.Button("Stop Capture", key="-stopcap-")],
    [sg.Text("ALL PACKETS", font=('Helvetica Bold', 20))],
    [sg.Listbox(key="-pktsall-",
                size=(100, 20),
                enable_events=True,
                values=pktsummarylist)]
]

window = sg.Window("Ōkami",layout, size=(1600, 800), resizable=True)
#window.read()

class pckt(object):
    def __init__(self, sniff_timestamp: str ='', layer: str ='', srcPort: str ='', dstPort: str ='',ipSrc: str ='', ipDst: str ='', highest_layer=''):
        self.sniff_timestamp = sniff_timestamp
        self.layer = layer
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.ipSrc = ipSrc
        self.ipDst = ipDst
        self.highest_layer = highest_layer


# Default interface [AF_INET] AddressFamily IPv4
#intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
intF='Ethernet 2'
capture = pyshark.LiveCapture(interface=intF)


def is_private_ip(ip_address):
    """
    Détermine si l'adresse IP donnée est privée

    Args:
        ip_address: L'adresse IP à vérifier

    Returns:
        True si l'IP est privée
    """
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private


def packetFilter(packet: capture):
    #Filtre les paquets
    if hasattr(packet, 'icmp'):
        # On a reçu un ping
        p = pckt()
        p.ipDst = packet.ip.dst
        p.ipSrc = packet.ip.src
        p.highest_layer = packet.highest_layer
        packet_info = vars(p)
        output = f"{packet_info['layer']} {packet_info['ipSrc']} > {packet_info['ipDst']}"
        print("ICMP packet:", output)
        return

    if packet.transport_layer == 'TCP' or packet.transport_layer == 'UDP':
        if hasattr(packet, 'ipv6'):
            # Désactivé IPv6
            return

        if hasattr(packet, 'ip'):
            # Vérifie si les adresses IP source et destination sont privées
            if is_private_ip(packet.ip.src) and is_private_ip(packet.ip.dst):
                # Communication locale détectée
                p = pckt()

                p.ipSrc = packet.ip.src
                p.ipDst = packet.ip.dst
                p.sniff_timestamp = packet.sniff_timestamp
                p.highest_layer = packet.highest_layer

                if hasattr(packet, 'UDP'):
                    p.dstPort = packet.udp.dstport
                    p.srcPort = packet.udp.srcport
                    p.layer = packet.transport_layer
                if hasattr(packet, 'TCP'):
                    p.dstPort = packet.tcp.dstport
                    p.srcPort = packet.tcp.srcport
                    p.layer = packet.transport_layer

                packet_info = vars(p)
                output = f"{packet_info['layer']} {packet_info['ipSrc']}:{packet_info['srcPort']} > {packet_info['ipDst']}:{packet_info['dstPort']}"
                print(output)
                return


for packet in capture.sniff_continuously():
    # Filtre les paquets
    packetFilter(packet)

