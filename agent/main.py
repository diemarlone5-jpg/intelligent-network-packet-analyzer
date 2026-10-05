from capture.sniffer import NetworkSniffer
from analyzer.explainer import explain_packet, group_communications

def main():
    print("==================================================")
    print("     INTELLIGENT NETWORK PACKET ANALYZER - V4     ")
    print("==================================================")

    sniffer = NetworkSniffer()

    try:
        # Capture de 10 paquets
        sniffer.start(count=10)
        
        print("\n--- 1. EXPLICATIONS DES PAQUETS (FAIT vs INTERPRETATION) ---")
        for p in sniffer.packets_data[:3]:
            exp = explain_packet(p)
            print(f"[FAIT]           : {exp['fait_observe']}")
            print(f"[INTERPRETATION] : {exp['interpretation']}\n")

        print("--- 2. COMMUNICATIONS ENRICHIES PAR API EXTERNE ---")
        communications = group_communications(sniffer.packets_data)
        for c in communications:
            geo = c["geo_info"]
            print(f"Hotes : {c['hosts'][0]} <--> {c['hosts'][1]}")
            print(f"  ├ Paquets : {c['packet_count']} | Volume : {c['total_bytes']} octets | Protocoles : {c['protocols']}")
            print(f"  └ Enrichissement API : Pays={geo['pays']} | Org/FSI={geo['org']}\n")

        # Enregistrement du fichier de capture
        sniffer.save_to_json("capture_output.json")

    except Exception as e:
        print(f"[E] Erreur : {e}")

if __name__ == "__main__":
    main()
