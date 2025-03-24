# task-1-Basic-Network-Sniffer

# ABIR MAJDI

from scapy.all import sniff

num_paquets = 0

def packet_rappel(packet):
    global num_paquets
    num_paquets +=1
    print(f"Le numéro du paquet capturé est : {num_paquets}\n")
    
    print(packet.summary())  
    print("\n")
    
    if packet.haslayer("IP"):
        print(f"Source de l'IP: {packet["IP"].src} -> Destination de l'IP: {packet["IP"].dst}")
        print("\n")
    
    if packet.haslayer("TCP"):
        print(f"Paquet TCP \n Port source: {packet["TCP"].sport} -> Port de destination: {packet["TCP"].dport}")
        print("\n")
    
    if packet.haslayer("UDP"):
        print(f"Paquet UDP \n Port source: {packet["UDP"].sport} -> Port de destination: {packet["UDP"].dport}")
        print("\n")
    


print("Démarrage du network sniffer...")
sniff(prn=packet_rappel)
