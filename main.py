import psutil
import socket

# Nom de l'interface que tu veux cibler (par exemple 'Ethernet' ou 'Wi-Fi')
interface_name = 'Ethernet 2'

def get_host_ip(interface):
# Obtenir les informations de toutes les interfaces réseau
    interfaces = psutil.net_if_addrs()

    # Vérifier si l'interface existe et récupérer son adresse IPv4
    if interface_name in interfaces:
        for address in interfaces[interface_name]:
            if address.family == socket.AF_INET:  # Utiliser socket.AF_INET
                return address.address
    else:
        pass

interf = get_host_ip(interface_name)
print(interf)

import matplotlib.animation as animation


def update_graph(i):
    global pkt_list
    tcp_count = sum(1 for pkt in pkt_list if pkt.haslayer(scp.TCP))
    udp_count = sum(1 for pkt in pkt_list if pkt.haslayer(scp.UDP))
    icmp_count = sum(1 for pkt in pkt_list if pkt.haslayer(scp.ICMP))

    plt.cla()  # Effacer le graphique précédent
    protocols = ['TCP', 'UDP', 'ICMP']
    counts = [tcp_count, udp_count, icmp_count]
    plt.bar(protocols, counts)


# Création du graphique animé
ani = animation.FuncAnimation(plt.gcf(), update_graph, interval=1000)
plt.show()
