import customtkinter as ctk  # Pour l'interface graphique
import psutil
import scapy.all as scp  # Pour la capture de paquets
import scapy.arch.windows as scpwinarch  # Pour les interfaces Windows
import threading  # Pour exécuter la capture de paquets en parallèle
import platform
from datetime import datetime
from scapy.arch import get_if_list
import matplotlib.pyplot as plt  # Pour les graphiques
import time  # Pour gérer les horodatages des SYN
from collections import defaultdict  # Pour stocker les tentatives SYN
from PIL import Image, ImageTk
import socket


# Initialiser le thème de l'interface
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# Fonction pour redimensionner l'image
def resize_image(image_path, new_width, new_height):
    image = Image.open(image_path)
    image = image.resize((new_width, new_height))  # Redimensionner l'image
    image.save("resized_image.png")  # Sauvegarder la nouvelle image redimensionnée
    return "resized_image.png"


# Chemin de l'image d'origine
image_path = "assets/logo-7.png"

# Redimensionner l'image (par exemple 200x200)
resized_image_path = resize_image(image_path, 110, 110)


# Créer la fenêtre principale
window = ctk.CTk()
window.title("Ōkami")
window.geometry("1350x800")

# Liste pour stocker les résumés des paquets capturés
alert_list = []
pktsummarylist = []
updatepklist = False  # Indique si la capture est en cours

# Obtenir les interfaces réseau
if platform.system() == "Windows":
    ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list() if len(str(x["name"])) <= 26]
else:
    ifaces = get_if_list()
capiface = ifaces[2]


# Fonction pour obtenir l'adresse IP de l'hôte
def get_host_ip(interface):
    interfaces = psutil.net_if_addrs()
    if interface in interfaces:
        for address in interfaces[interface]:
            if address.family == socket.AF_INET:  # Utiliser socket.AF_INET
                return address.address
    else:
        pass


# Fonction de traitement des paquets
pkt_list = []
alert_list = []
filter_expression = ""


def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    pkt_summary = pkt.summary()  # Obtenir un résumé du paquet
    pktsummarylist.append(pkt_summary)  # Ajouter le résumé à la liste
    pkt_list.append(pkt)  # Ajouter le paquet à la liste des paquets capturés

    detect_scans(pkt)


# Fonction pour démarrer la capture de paquets
def start_capture():
    global updatepklist
    updatepklist = True
    pktsummarylist.clear()
    pkt_list.clear()
    alert_list.clear()  # Réinitialiser les alertes

    def capture():
        while updatepklist:
            try:
                scp.sniff(prn=pkt_process, iface=capiface, filter=filter_expression, store=0)
            except Exception as e:
                print(f"Capture error: {e}")
                continue

    sniffthread = threading.Thread(target=capture, daemon=True)
    sniffthread.start()


# Variables globales pour la détection des scans
alerted_ips = {}
scan_attempts = defaultdict(list)
SYN_THRESHOLD = 10
FIN_THRESHOLD = 5
NULL_THRESHOLD = 5
XMAS_THRESHOLD = 5
TIME_WINDOW = 20  # Fenêtre de temps pour détecter des multiples scans


def display_alert(message, src_ip):
    current_time = time.time()
    if src_ip != get_host_ip(capiface):
        if src_ip in alerted_ips and current_time - alerted_ips[src_ip] < TIME_WINDOW:
            return

        alert_list.append(message)
        alert_listbox.insert(ctk.END, message)
        alert_listbox.yview_moveto(1)  # Scroller vers le bas

        alerted_ips[src_ip] = current_time


def detect_scans(pkt):
    global scan_attempts
    current_time = time.time()

    if pkt.haslayer(scp.IP):
        src_ip = pkt[scp.IP].src

        # DÉTECTION SYN
        if pkt.haslayer(scp.TCP) and pkt[scp.TCP].flags == 'S':
            scan_attempts[src_ip].append(('SYN', current_time))
            syn_attempts = [t for t in scan_attempts[src_ip] if t[0] == 'SYN' and current_time - t[1] <= TIME_WINDOW]
            if len(syn_attempts) >= SYN_THRESHOLD:
                alert_message = f"[ALERTE] Scan SYN détecté de {src_ip} avec {len(syn_attempts)} tentatives SYN."
                display_alert(alert_message, src_ip)

        # DÉTECTION FIN
        elif pkt.haslayer(scp.TCP) and pkt[scp.TCP].flags == 'F':
            scan_attempts[src_ip].append(('FIN', current_time))
            fin_attempts = [t for t in scan_attempts[src_ip] if t[0] == 'FIN' and current_time - t[1] <= TIME_WINDOW]
            if len(fin_attempts) >= FIN_THRESHOLD:
                alert_message = f"[ALERTE] Scan FIN détecté de {src_ip} avec {len(fin_attempts)} tentatives FIN."
                display_alert(alert_message, src_ip)

        # DÉTECTION NULL
        elif pkt.haslayer(scp.TCP) and pkt[scp.TCP].flags == 0:
            scan_attempts[src_ip].append(('NULL', current_time))
            null_attempts = [t for t in scan_attempts[src_ip] if t[0] == 'NULL' and current_time - t[1] <= TIME_WINDOW]
            if len(null_attempts) >= NULL_THRESHOLD:
                alert_message = f"[ALERTE] Scan NULL détecté de {src_ip} avec {len(null_attempts)} tentatives NULL."
                display_alert(alert_message, src_ip)

        # DÉTECTION XMAS
        elif pkt.haslayer(scp.TCP) and pkt[scp.TCP].flags == 0x29:  # FIN + PSH + URG
            scan_attempts[src_ip].append(('XMAS', current_time))
            xmas_attempts = [t for t in scan_attempts[src_ip] if t[0] == 'XMAS' and current_time - t[1] <= TIME_WINDOW]
            if len(xmas_attempts) >= XMAS_THRESHOLD:
                alert_message = f"[ALERTE] Scan XMAS détecté de {src_ip} avec {len(xmas_attempts)} tentatives XMAS."
                display_alert(alert_message, src_ip)

        # Nettoyage des anciennes tentatives
        scan_attempts[src_ip] = [attempt for attempt in scan_attempts[src_ip] if
                                 current_time - attempt[1] <= TIME_WINDOW]


# Fonction pour mettre à jour et afficher les statistiques
def show_stats():
    protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    for pkt in pkt_list:
        if pkt.haslayer(scp.TCP):
            protocols["TCP"] += 1
        elif pkt.haslayer(scp.UDP):
            protocols["UDP"] += 1
        elif pkt.haslayer(scp.ICMP):
            protocols["ICMP"] += 1
        else:
            protocols["Other"] += 1

    # Création du graphique
    plt.figure(figsize=(10, 6))
    plt.bar(protocols.keys(), protocols.values(), color=['blue', 'green', 'red', 'purple'])
    plt.title('Packet Distribution by Protocol')
    plt.xlabel('Protocol')
    plt.ylabel('Number of Packets')
    plt.show()

def stop_capture():
    global updatepklist
    updatepklist = False

# Widgets de l'interface graphique
iface_label = ctk.CTkLabel(window, text="Interface:")
iface_label.grid(row=0, column=0, padx=10, pady=10)

iface_combo = ctk.CTkComboBox(window, values=ifaces)
iface_combo.grid(row=0, column=1, padx=10, pady=10)

start_button = ctk.CTkButton(window, text="Start Capture", command=start_capture)
start_button.grid(row=0, column=2, padx=10, pady=10)

stop_button = ctk.CTkButton(window, text="Stop Capture", command=stop_capture)
stop_button.grid(row=0, column=3, padx=10, pady=10)

alert_listbox = ctk.CTkTextbox(window, height=10, width=80)
alert_listbox.grid(row=1, column=0, columnspan=4, padx=10, pady=10)

# Lancer la boucle principale
window.mainloop()
