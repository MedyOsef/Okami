from scapy.layers.inet import IP, TCP
from collections import defaultdict
import time

# Dictionnaire pour stocker les tentatives SYN par adresse IP source
syn_attempts = defaultdict(list)

# Seuil pour détecter un scan SYN (par exemple 5 SYN en 10 secondes)
SYN_THRESHOLD = 5
TIME_WINDOW = 10  # en secondes

def detect_syn_scan(pkt):
    global syn_attempts
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':  # Vérifier si le paquet est un SYN
        src_ip = pkt[IP].src
        current_time = time.time()

        # Enregistrer le timestamp de chaque tentative SYN
        syn_attempts[src_ip].append(current_time)

        # Supprimer les entrées trop anciennes (au-delà de la fenêtre de temps)
        syn_attempts[src_ip] = [timestamp for timestamp in syn_attempts[src_ip] if current_time - timestamp <= TIME_WINDOW]

        # Si le nombre de SYN dépasse le seuil dans la fenêtre de temps, alerter
        if len(syn_attempts[src_ip]) >= SYN_THRESHOLD:
            print(f"[ALERTE] Scan SYN détecté de la part de {src_ip} avec {len(syn_attempts[src_ip])} tentatives SYN en {TIME_WINDOW} secondes.")
