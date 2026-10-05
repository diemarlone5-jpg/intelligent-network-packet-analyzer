import json
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_working_ifaces, conf
from collections import Counter

class NetworkSniffer:
    def __init__(self):
        self.packets_data = []
        self.stats = {
            "total_packets": 0,
            "protocols": Counter(),
            "sources": Counter(),
            "destinations": Counter()
        }
        self.setup_interface()

    def setup_interface(self):
        """Configure l'interface réseau active."""
        for iface in get_working_ifaces():
            if iface.ip and not iface.ip.startswith("127.") and not iface.ip.startswith("169.254."):
                if "vEthernet" not in iface.name and "Virtual" not in iface.name:
                    conf.iface = iface
                    print(f"[*] Carte réseau configurée : {iface.name} ({iface.ip})")
                    return
        print("[!] Interface par défaut utilisée.")

    def process_packet(self, packet):
        """Analyse et structure le paquet en dictionnaire."""
        if packet.haslayer(IP):
            self.stats["total_packets"] += 1
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            size = len(packet)
            proto_name = "AUTRE"
            sport, dport = None, None

            if packet.haslayer(TCP):
                proto_name = "TCP"
                sport, dport = packet[TCP].sport, packet[TCP].dport
            elif packet.haslayer(UDP):
                proto_name = "UDP"
                sport, dport = packet[UDP].sport, packet[UDP].dport
            elif packet.haslayer(ICMP):
                proto_name = "ICMP"

            # Mise à jour des statistiques
            self.stats["protocols"][proto_name] += 1
            self.stats["sources"][src_ip] += 1
            self.stats["destinations"][dst_ip] += 1

            # Structure des données du paquet
            packet_info = {
                "id": self.stats["total_packets"],
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto_name,
                "src_port": sport,
                "dst_port": dport,
                "length": size
            }
            self.packets_data.append(packet_info)

            print(f"[PAQUET #{self.stats['total_packets']}] {src_ip} -> {dst_ip} | {proto_name} | {size} octets")

    def start(self, count=10):
        """Démarre la capture."""
        print(f"[*] Capture de {count} paquets en cours...")
        sniff(count=count, prn=self.process_packet, store=False)
        print("[*] Capture terminée avec succès.\n")

    def save_to_json(self, filename="capture_output.json"):
        """Exporte les paquets et statistiques au format JSON."""
        output = {
            "summary": {
                "total_packets": self.stats["total_packets"],
                "protocols": dict(self.stats["protocols"]),
                "top_sources": dict(self.stats["sources"].most_common(5)),
                "top_destinations": dict(self.stats["destinations"].most_common(5))
            },
            "packets": self.packets_data
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=4)
        print(f"[+] Données sauvegardées dans : {filename}")