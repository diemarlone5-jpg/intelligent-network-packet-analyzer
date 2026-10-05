import json
from scapy.all import sniff, get_if_list, get_if_addr

class NetworkSniffer:
    def __init__(self):
        self.packets_data = []
        self.interface = self._find_active_interface()

    def _find_active_interface(self):
        interfaces = get_if_list()
        
        # 1er passage : Chercher en priorite la vraie carte Wi-Fi / Ethernet local (192.168.x.x)
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                if ip.startswith("192.168."):
                    print(f"[*] Carte reseau active detectee : {iface} ({ip})")
                    return iface
            except Exception:
                continue
                
        # 2eme passage : Autres sous-reseaux si 192.168 n'est pas trouve
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                if (ip.startswith("10.") or ip.startswith("172.")) and not ip.startswith("172.25."):
                    print(f"[*] Carte reseau secondaire : {iface} ({ip})")
                    return iface
            except Exception:
                continue

        return None

    def _process_packet(self, packet):
        if packet.haslayer("IP"):
            pkt_info = {
                "src_ip": packet["IP"].src,
                "dst_ip": packet["IP"].dst,
                "protocol": packet["IP"].proto,
                "length": len(packet)
            }
            if packet.haslayer("TCP"):
                pkt_info["protocol"] = "TCP"
                pkt_info["dst_port"] = packet["TCP"].dport
            elif packet.haslayer("UDP"):
                pkt_info["protocol"] = "UDP"
                pkt_info["dst_port"] = packet["UDP"].dport
            else:
                pkt_info["protocol"] = str(packet["IP"].proto)
                pkt_info["dst_port"] = 0

            self.packets_data.append(pkt_info)
            print(f"[PAQUET #{len(self.packets_data)}] {pkt_info['src_ip']} -> {pkt_info['dst_ip']} | {pkt_info['protocol']} | {pkt_info['length']} octets")

    def start(self, count=10):
        self.packets_data = []
        print(f"[*] Capture de {count} paquets en cours...")
        
        if self.interface:
            sniff(iface=self.interface, prn=self._process_packet, count=count, timeout=15)
        else:
            sniff(prn=self._process_packet, count=count, timeout=15)
            
        print("[*] Capture terminee avec succes.")

    def save_to_json(self, filename="capture_output.json"):
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(self.packets_data, f, indent=4)
        print(f"[+] Donnees sauvegardees dans : {filename}")
