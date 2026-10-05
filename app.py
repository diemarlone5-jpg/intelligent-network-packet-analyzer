import streamlit as st
import json
import os
import pandas as pd
from capture.sniffer import NetworkSniffer
from analyzer.explainer import explain_packet, group_communications

st.set_page_config(page_title="Network Packet Analyzer", page_icon="📡", layout="wide")

st.title("📡 Intelligent Network Packet Analyzer")
st.markdown("---")

# Sidebar pour les commandes
st.sidebar.header("⚙️ Contrôles")
packet_count = st.sidebar.slider("Nombre de paquets à capturer", 5, 50, 10)

if st.sidebar.button("🚀 Lancer la capture en direct"):
    with st.spinner(f"Capture de {packet_count} paquets en cours..."):
        sniffer = NetworkSniffer()
        try:
            sniffer.start(count=packet_count)
            sniffer.save_to_json("capture_output.json")
            st.sidebar.success("Capture terminée !")
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Erreur : {e}")

# Lecture des données enregistrées
if os.path.exists("capture_output.json"):
    raw_packets = []
    with open("capture_output.json", "r", encoding="utf-8") as f:
        try:
            raw_packets = json.load(f)
        except Exception:
            raw_packets = []

    # S'assurer que chaque élément est bien un dictionnaire Python
    packets = []
    for item in raw_packets:
        if isinstance(item, str):
            try:
                packets.append(json.loads(item))
            except Exception:
                pass
        elif isinstance(item, dict):
            packets.append(item)

    if packets:
        # 1. Tableau de bord / Statistiques
        comms = group_communications(packets)
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Paquets Capturés", len(packets))
        col2.metric("Communications Uniques", len(comms))
        col3.metric("Volume Total (Octets)", sum(p.get("length", 0) for p in packets))

        st.markdown("---")

        # 2. Vue des Communications & Enrichissement API
        st.subheader("🌐 Communications & Enrichissement API")
        
        comms_data = []
        for c in comms:
            geo = c.get("geo_info", {})
            comms_data.append({
                "Hôte A": c["hosts"][0],
                "Hôte B": c["hosts"][1],
                "Paquets": c["packet_count"],
                "Volume (Octets)": c["total_bytes"],
                "Protocoles": ", ".join(c["protocols"]),
                "Pays (API)": geo.get("pays", "Inconnu"),
                "Organisation / FSI": geo.get("org", "Inconnu")
            })
        
        st.dataframe(pd.DataFrame(comms_data), use_container_width=True)

        st.markdown("---")

        # 3. Détails des Paquets (Fait vs Interprétation)
        st.subheader("🔍 Analyse Détaillée (Fait vs Interprétation)")
        
        explanations = [explain_packet(p) for p in packets]
        exp_df = pd.DataFrame(explanations)
        exp_df.columns = ["Fait Observé", "Interprétation"]
        st.table(exp_df)

    else:
        st.info("Aucun paquet valide trouvé. Cliquez sur 'Lancer la capture' dans le panneau de gauche.")
else:
    st.info("Aucune capture disponible. Utilisez le panneau de gauche pour démarrer.")
