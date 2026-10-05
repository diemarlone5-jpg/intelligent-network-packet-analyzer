import urllib.request
import json

KNOWN_PORTS = {
    80: ("HTTP", "Communication Web non securisee"),
    443: ("HTTPS", "Communication Web securisee"),
    53: ("DNS", "Resolution de noms de domaine"),
    22: ("SSH", "Connexion a distance securisee"),
    21: ("FTP", "Transfert de fichiers non chiffre"),
    5353: ("mDNS", "Decouverte d'appareils sur le reseau local")
}

def get_ip_info(ip):
    """Enrichit une IP via l'API externe gratuite ip-api.com."""
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "255.255.255.255":
        return {"pays": "Reseau Local / Broadcast", "org": "Interne"}
    
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,org"
        req = urllib.request.urlopen(url, timeout=2)
        data = json.loads(req.read().decode('utf-8'))
        if data.get("status") == "success":
            return {"pays": data.get("country", "Inconnu"), "org": data.get("org", "Inconnu")}
    except Exception:
        pass
    return {"pays": "Inconnu", "org": "Inconnu"}

def explain_packet(packet):
    """Transforme un paquet brut en explication lisible (Fait vs Interpretation)."""
    src = packet.get("src_ip", "Inconnu")
    dst = packet.get("dst_ip", "Inconnu")
    dport = packet.get("dst_port", 0)
    proto = packet.get("protocol", "IP")

    service_name, description = KNOWN_PORTS.get(dport, ("Inconnu", "Service non identifie par defaut"))

    fait = f"Paquet {proto} envoie de {src} vers {dst} sur le port {dport}"
    interpretation = f"Service probable : {service_name}. {description}."

    return {
        "fait_observe": fait,
        "interpretation": interpretation
    }

def group_communications(packets):
    """Regroupe les paquets par session et enrichit avec l'API externe."""
    conversations = {}
    for p in packets:
        src = p.get("src_ip", "Inconnu")
        dst = p.get("dst_ip", "Inconnu")
        pair = tuple(sorted([src, dst]))
        
        if pair not in conversations:
            target_ip = dst if src.startswith("192.168.") else src
            api_info = get_ip_info(target_ip)

            conversations[pair] = {
                "hosts": pair,
                "packet_count": 0,
                "total_bytes": 0,
                "protocols": set(),
                "geo_info": api_info
            }
        conversations[pair]["packet_count"] += 1
        conversations[pair]["total_bytes"] += p.get("length", 0)
        conversations[pair]["protocols"].add(p.get("protocol", "Inconnu"))

    for conv in conversations.values():
        conv["protocols"] = list(conv["protocols"])

    return list(conversations.values())
