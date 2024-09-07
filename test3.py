import PySimpleGUI as sg  # Pour l'interface graphique
import scapy.all as scp  # Pour la capture de paquets
import scapy.arch.windows as scpwinarch  # Pour les interfaces Windows
import threading  # Pour exécuter la capture de paquets en parallèle
import platform
from datetime import datetime
from scapy.arch import get_if_list
import matplotlib.pyplot as plt  # Pour les graphiques

# Définir le thème et les éléments de l'interface
sg.theme("DarkGrey15")

# Liste pour stocker les résumés des paquets capturés
pktsummarylist = []
updatepklist = False  # Indique si la capture est en cours

# Définition du menu
menu_def = [['&File', ['!&Open', '&Save::savekey', '---', '&Properties', 'E&xit']],
            ['&Help', ['&About...']]]

# Obtenir les interfaces réseau
if platform.system() == "Windows":
    ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list() if len(str(x["name"])) <= 26]
else:
    ifaces = get_if_list()
capiface = ifaces[2]

# Définir la disposition de l'interface graphique
layout = [[sg.Menu(menu_def)],
          [sg.Text("Interface:", font=('Helvetica Bold', 10)),sg.Combo(values=ifaces, readonly=True, key='-COMBO-', enable_events=True, default_value=ifaces[2])],
          [sg.Button("Start Capture", key="-startcap-", button_color=('#f3f3f3', '#0a85d9')),
           sg.Button("Stop Capture", key="-stopcap-", disabled=True),
           sg.Button("Save Capture", key="-savepcap-", disabled=True),
           sg.Button("Show Proto Stats", key="-showstats-", button_color=('#0a85d9', '#f3f3f3')),],  # Bouton pour afficher les statistiques
          [sg.Text("ALL PACKETS", font=('Helvetica Bold', 20))],
          [sg.Listbox(key="-pktsall-",
                      size=(100, 20),
                      enable_events=True,
                      values=pktsummarylist, text_color='green')]
          ]

# Créer la fenêtre
window = sg.Window("Ōkami", layout, size=(1200, 600), resizable=True, finalize=True)

pkt_list = []  # Pour stocker les objets paquet


# Fonction de traitement des paquets
def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    pkt_summary = pkt.summary()  # Obtenir un résumé du paquet
    pktsummarylist.append(pkt_summary)  # Ajouter le résumé à la liste
    pkt_list.append(pkt)  # Ajouter le paquet à la liste des paquets capturés

    """if updatepklist:
        window["-pktsall-"].update(values=pktsummarylist, scroll_to_index=len(pktsummarylist))"""


# Fonction pour démarrer la capture de paquets
def start_capture():
    global updatepklist
    updatepklist = True
    pktsummarylist.clear()
    pkt_list.clear()

    def capture():
        while updatepklist:
            try:
                scp.sniff(prn=pkt_process, iface=capiface, filter="", store=0)
            except Exception as e:
                print(f"Capture error: {e}")
                continue

    sniffthread = threading.Thread(target=capture, daemon=True)
    sniffthread.start()


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
            sg.popup("Aucune Statistique,\ncar pas de paquet disponible",title="Pas de Statistique")

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
            sg.popup("Sauvegarde impossible,\naucun paquet disponible",title="OK")

    if event == "-startcap-":
        window['-startcap-'].update(button_color=('#f3f3f3', '#606060'), disabled=True)
        window['-stopcap-'].update(button_color=('#f3f3f3','#d60000'), disabled=False)
        window['-savepcap-'].update(disabled=True)
        window['-COMBO-'].update(disabled=True)
        print("Start on", capiface)
        start_capture()
        while True:
            event, values = window.read(timeout=10)
            if event == "-stopcap-":
                window['-startcap-'].update(button_color=('#f3f3f3', '#2e4499'), disabled=False)
                window['-stopcap-'].update(button_color=('#f3f3f3', '#606060'), disabled=True)
                window['-savepcap-'].update(button_color=('#f3f3f3','#599e5e'),disabled=False)
                window['-COMBO-'].update(disabled=False)
                print("Stop")
                updatepklist = False  # packet capture stopped by user
                break
            if event == sg.TIMEOUT_EVENT:
                window["-pktsall-"].update(values=pktsummarylist, scroll_to_index=len(pktsummarylist))

    if event == "-pktsall-" and values["-pktsall-"]:
        selected_packet_index = pktsummarylist.index(values["-pktsall-"][0])
        packet_details = pkt_list[selected_packet_index].show(dump=True)
        sg.popup_scrolled(packet_details, title="Packet Details", size=(80, 20))


window.close()
