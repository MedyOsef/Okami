import PySimpleGUI as sg  # Pour l'interface graphique
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
from PIL import Image
import socket



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


# Définir le thème et les éléments de l'interface
sg.theme("DarkGrey15")

# Liste pour stocker les résumés des paquets capturés
alert_list = []
pktsummarylist = []
updatepklist = False  # Indique si la capture est en cours

# Définition du menu
menu_def = [['&File', ['&Open', '&Save::savekey', '---', '&Properties', 'E&xit']],
            ['&Help', ['&About...']]]

# Obtenir les interfaces réseau
if platform.system() == "Windows":
    ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list() if len(str(x["name"])) <= 26]
else:
    ifaces = get_if_list()
capiface = ifaces[2]

# Définir la disposition de l'interface graphique
layout = [[sg.Menu(menu_def)],
          [sg.Text("Interface:", font=('Helvetica Bold', 10)), sg.Combo(values=ifaces, readonly=True, key='-COMBO-', enable_events=True, default_value=ifaces[2]),
           sg.Image(filename=resized_image_path, pad=((780, 0) ,0)),],
          [sg.Button("Start Capture", key="-startcap-", button_color=('#f3f3f3', '#0a85d9')),
           sg.Button("Stop Capture", key="-stopcap-", disabled=True),
           sg.Button("Save Capture", key="-savepcap-", disabled=True),
           sg.Button("Show Proto Stats", key="-showstats-", button_color=('#0a85d9', '#f3f3f3')),],  # Bouton pour afficher les statistiques
          [sg.Text("ALL PACKETS", font=('Helvetica Bold', 14), size=(52, None), justification="left"),
           sg.Text("ALERT PACKETS", font=('Helvetica Bold', 14), size=(70, None), justification="left")],
          [sg.Listbox(key='-pktsall-', size=(80,20), values=alert_list, enable_events=True, text_color='green'),
           sg.Listbox(key='-alerts-', size=(80,20), values=pktsummarylist, enable_events=True, text_color='red')],
]

# Créer la fenêtre
window = sg.Window("Ōkami", layout, size=(1200, 800), finalize=True)

def get_host_ip(interface):
# Obtenir les informations de toutes les interfaces réseau
    interfaces = psutil.net_if_addrs()

    # Vérifier si l'interface existe et récupérer son adresse IPv4
    if interface in interfaces:
        for address in interfaces[interface]:
            if address.family == socket.AF_INET:  # Utiliser socket.AF_INET
                return address.address
    else:
        pass



pkt_list = []  # Pour stocker les objets paquet
alert_list = []  # Liste pour stocker les alertes

# Fonction de traitement des paquets
def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    pkt_summary = pkt.summary()  # Obtenir un résumé du paquet
    pktsummarylist.append(pkt_summary)  # Ajouter le résumé à la liste
    pkt_list.append(pkt)  # Ajouter le paquet à la liste des paquets capturés

    # Appel de la fonction de détection de scan SYN
    # detect_syn_scan(pkt)
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
                scp.sniff(prn=pkt_process, iface=capiface, filter="", store=0)
            except Exception as e:
                print(f"Capture error: {e}")
                continue

    sniffthread = threading.Thread(target=capture, daemon=True)
    sniffthread.start()

# Fonction pour afficher les alertes à l'écran
"""def display_alert(message):
    alert_list.append(message)
    window["-alerts-"].update(values=alert_list, scroll_to_index=len(alert_list))"""

alerted_ips = {}
# Variables globales pour la détection des scans
scan_attempts = defaultdict(list)
SYN_THRESHOLD = 10
FIN_THRESHOLD = 5
NULL_THRESHOLD = 5
XMAS_THRESHOLD = 5
TIME_WINDOW = 20 # Fenêtre de temps pour détecter des multiples scans

def display_alert(message, src_ip):
    current_time = time.time()
    if src_ip != get_host_ip(capiface):
        # Si l'IP a été alertée récemment, ignorer la nouvelle alerte
        if src_ip in alerted_ips and current_time - alerted_ips[src_ip] < TIME_WINDOW:
            return

        alert_list.append(message)
        window["-alerts-"].update(values=alert_list, scroll_to_index=len(alert_list))

        # Mettre à jour le timestamp de la dernière alerte pour cette IP
        alerted_ips[src_ip] = current_time


########################################################################
# Fonction de détection de scan SYN améliorée
"""def detect_syn_scan(pkt):
    if pkt.haslayer(scp.TCP) and pkt[scp.TCP].flags == 'S':  # Vérifier si le paquet est un SYN
        src_ip = pkt[scp.IP].src
        current_time = time.time()

        # Enregistrer le timestamp de chaque tentative SYN
        syn_attempts[src_ip].append(current_time)

        # Supprimer les entrées trop anciennes (au-delà de la fenêtre de temps)
        syn_attempts[src_ip] = [timestamp for timestamp in syn_attempts[src_ip] if current_time - timestamp <= TIME_WINDOW]

        # Si le nombre de SYN dépasse le seuil dans la fenêtre de temps, alerter
        if len(syn_attempts[src_ip]) >= SYN_THRESHOLD:
            alert_message = f"[ALERTE] Scan SYN détecté de {src_ip} avec {len(syn_attempts[src_ip])} tentatives SYN en {TIME_WINDOW} secondes."
            #print(alert_message)
            #display_alert(alert_message)  # Afficher l'alerte à l'écran
            alert_list.append(alert_message)"""

################################################################


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


# Boucle principale de l'interface graphique
while True:
    event, values = window.read()

    if event in (sg.WIN_CLOSED, 'Exit'):
        break

    if event == "-showstats-":
        if len(pktsummarylist) > 0:
            show_stats()  # Afficher les statistiques lorsque l'utilisateur clique sur "Show Stats"
        else:
            sg.popup("Aucune Statistique,\ncar pas de paquet disponible", title="Pas de Statistique")

    if event == "-COMBO-":
        capiface = values['-COMBO-']

    if event == "-savepcap-":
        if len(pktsummarylist) > 0:
            file_path = sg.popup_get_file('Save as', save_as=True, no_window=True,
                                          default_path="Okami-capture_" + datetime.now().strftime("%d-%m-%Y_%H-%M-%S"),
                                          default_extension='.pcap')
            if file_path:
                scp.wrpcap(file_path, pkt_list)
        else:
            sg.popup("Sauvegarde impossible,\naucun paquet disponible", title="OK")

    if event == "-startcap-":
        window['-startcap-'].update(button_color=('#f3f3f3', '#606060'), disabled=True)
        window['-stopcap-'].update(button_color=('#f3f3f3', '#d60000'), disabled=False)
        window['-savepcap-'].update(disabled=True)
        window['-COMBO-'].update(disabled=True)
        print("Start on", capiface)
        start_capture()
        while True:
            event, values = window.read(timeout=10)
            if event == "-stopcap-":
                window['-startcap-'].update(button_color=('#f3f3f3', '#2e4499'), disabled=False)
                window['-stopcap-'].update(button_color=('#f3f3f3', '#606060'), disabled=True)
                window['-savepcap-'].update(button_color=('#f3f3f3', '#599e5e'), disabled=False)
                window['-COMBO-'].update(disabled=False)
                print("Stop")
                updatepklist = False
                break
            if event == sg.TIMEOUT_EVENT:
                window["-pktsall-"].update(values=pktsummarylist, scroll_to_index=len(pktsummarylist))
                window["-alerts-"].update(values=alert_list, scroll_to_index=len(alert_list))

    if event == "-pktsall-" and values["-pktsall-"]:
        selected_packet_index = pktsummarylist.index(values["-pktsall-"][0])
        packet_details = pkt_list[selected_packet_index].show(dump=True)
        sg.popup_scrolled(packet_details, title="Packet Details", size=(80, 20))

window.close()
