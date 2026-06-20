# agents/rapporteur/dashboard_app.py
# Dashboard SOC interactif — Bonus "Interface de visualisation" (PDF du projet)
#
# Lancement :
#     cd agents/rapporteur
#     streamlit run dashboard_app.py
#
# Sources de données (par ordre de priorité) :
#   1. SharedMemory de l'Extracteur (canal "analysis_results") — données live
#   2. Historique persistant (incidents_history.json) — données déjà traitées
#   3. memory.json — métadonnées des rapports générés par le LLM
#
# Le dashboard s'affiche même si LangChain/Ollama/SharedMemory sont indisponibles.

import json
import os
import sys
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

# ── Résolution des chemins ────────────────────────────────────────────────────
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, "..", ".."))
EXTRACTEUR_DIR = os.path.join(PROJECT_ROOT, "agents", "extracteur")
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, PROJECT_ROOT)
sys.path.insert(0, EXTRACTEUR_DIR)

from dashboard_data import load_all_incidents, compute_stats, HISTORY_PATH
from analyser_adapter import analyseur_result_to_incident_batch

# SharedMemory optionnelle (non bloquante si l'Extracteur n'est pas installé)
try:
    from shared_memory import SharedMemory
    # Même chemin que l'Analyseur (upstream direct)
    PROCESSED_DIR    = os.path.join(PROJECT_ROOT, "data", "processed")
    _shared_memory   = SharedMemory(base_dir=PROCESSED_DIR)
    SHARED_MEM_READY = True
except Exception:
    _shared_memory   = None
    SHARED_MEM_READY = False

BASE_DIR    = PROJECT_ROOT
SHARED_JSON = os.getenv(
    "SHARED_MEMORY_PATH",
    os.path.join(BASE_DIR, "data", "shared", "memory.json"),
)

SEVERITY_COLORS = {"CRITICAL": "#d62728", "HIGH": "#ff7f0e", "MEDIUM": "#f4d03f", "LOW": "#2ca02c"}
SEVERITY_ICONS  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ─── Chargement des données ───────────────────────────────────────────────────

@st.cache_data(ttl=5)
def get_live_from_shared_memory() -> list:
    """Lit les résultats bruts de l'Analyseur dans la SharedMemory."""
    if not SHARED_MEM_READY or _shared_memory is None:
        return []
    try:
        raw = _shared_memory.read("analysis_results") or []
        return analyseur_result_to_incident_batch(raw)
    except Exception:
        return []


@st.cache_data(ttl=5)
def get_incidents_df(include_live: bool) -> pd.DataFrame:
    """Fusionne l'historique persistant + données live de la SharedMemory."""
    history    = load_all_incidents()
    live       = get_live_from_shared_memory() if include_live else []

    # Upsert : les données live (plus récentes) écrasent l'historique sur même event_id
    merged = {i["incident_id"]: i for i in history}
    for inc in live:
        merged[inc["incident_id"]] = inc
    all_incidents = list(merged.values())

    if not all_incidents:
        return pd.DataFrame()

    df = pd.DataFrame(all_incidents)
    df["severity"] = df.get("severity", "MEDIUM").fillna("MEDIUM").str.upper()
    if "timestamp" in df.columns:
        df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    else:
        df["timestamp_dt"] = pd.NaT
    df["false_positive"] = df.get("false_positive", False).fillna(False)
    return df


@st.cache_data(ttl=5)
def get_shared_meta() -> dict:
    if not os.path.exists(SHARED_JSON):
        return {}
    try:
        with open(SHARED_JSON, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def read_text_file(path: str) -> str:
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return ""


# ─── Page config ─────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SOC Dashboard — Agent Rapporteur",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Dashboard SOC — Agent Rapporteur")
st.caption(f"Mis à jour automatiquement • {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")

# ─── Barre de contrôle ────────────────────────────────────────────────────────

c1, c2, c3 = st.columns([1, 1, 5])
with c1:
    if st.button("🔄 Rafraîchir"):
        st.cache_data.clear()
        st.rerun()
with c2:
    include_live = st.toggle(
        "🔴 Live (SharedMemory)",
        value=SHARED_MEM_READY,
        disabled=not SHARED_MEM_READY,
        help="Inclut les résultats non encore traités de l'Agent Analyseur"
              if SHARED_MEM_READY else "SharedMemory indisponible",
    )

if not SHARED_MEM_READY:
    st.warning(
        "⚠️ SharedMemory indisponible (module `src.utils.shared_memory` introuvable). "
        "Seul l'historique local est affiché.",
        icon="⚠️",
    )

df = get_incidents_df(include_live)

if df.empty:
    st.info(
        "Aucun incident enregistré. Lance l'Agent Rapporteur (`python rapporteur_agent.py --mode poll`) "
        "pour alimenter ce dashboard depuis l'Agent Analyseur."
    )
    st.stop()

# ─── Sidebar — filtres ───────────────────────────────────────────────────────

st.sidebar.header("🔍 Filtres")

severities_available = [s for s in SEVERITY_ORDER if s in df["severity"].unique()]
selected_sev = st.sidebar.multiselect(
    "Criticité", options=severities_available, default=severities_available
)

attack_types_avail = (
    sorted(df["attack_type"].dropna().unique().tolist())
    if "attack_type" in df.columns else []
)
selected_attacks = st.sidebar.multiselect(
    "Type d'attaque", options=attack_types_avail, default=attack_types_avail
)

hide_fp = st.sidebar.checkbox("Masquer les faux positifs", value=False)

filtered = df[df["severity"].isin(selected_sev)]
if attack_types_avail:
    filtered = filtered[filtered["attack_type"].isin(selected_attacks)]
if hide_fp:
    filtered = filtered[~filtered["false_positive"]]

st.sidebar.divider()
live_count = len(get_live_from_shared_memory()) if include_live else 0
st.sidebar.caption(f"🔴 Live (SharedMemory) : {live_count} incident(s)")
st.sidebar.caption(f"📁 Historique local : {len(load_all_incidents())} incident(s)")
st.sidebar.caption(f"📊 Affichés (filtrés) : {len(filtered)}")

# ─── KPIs ────────────────────────────────────────────────────────────────────

stats = compute_stats(filtered.to_dict("records"))

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total alertes",       stats["total_alerts"])
k2.metric("Incidents confirmés", stats["confirmed_incidents"])
k3.metric("Faux positifs",       stats["false_positives"])
k4.metric("Taux de détection",   f"{stats['detection_rate']}%")
k5.metric(
    "🔴 CRITICAL",
    stats["severity_counts"].get("CRITICAL", 0),
    delta=None,
)

st.divider()

# ─── Graphiques ──────────────────────────────────────────────────────────────

g1, g2, g3 = st.columns(3)

with g1:
    st.subheader("Répartition par criticité")
    sev_df = pd.DataFrame(
        [{"Criticité": k, "Nombre": v}
         for k, v in stats["severity_counts"].items() if v > 0]
    )
    if not sev_df.empty:
        fig = px.pie(
            sev_df, names="Criticité", values="Nombre", hole=0.45,
            color="Criticité", color_discrete_map=SEVERITY_COLORS,
        )
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Aucune donnée.")

with g2:
    st.subheader("Types d'attaques")
    attack_df = pd.DataFrame(
        [{"Type": k, "Nombre": v} for k, v in stats["attack_types"].items()]
    ).sort_values("Nombre", ascending=True)
    if not attack_df.empty:
        fig = px.bar(attack_df, x="Nombre", y="Type", orientation="h")
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Aucune donnée.")

with g3:
    st.subheader("Top IPs suspectes")
    ip_counts = (
        filtered["source_ip"].value_counts().head(5)
        if "source_ip" in filtered.columns else pd.Series(dtype=int)
    )
    if not ip_counts.empty:
        ip_df = ip_counts.reset_index()
        ip_df.columns = ["IP", "Occurrences"]
        fig = px.bar(ip_df, x="Occurrences", y="IP", orientation="h")
        fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("Aucune donnée.")

# ─── Timeline ────────────────────────────────────────────────────────────────

st.subheader("📈 Évolution des incidents dans le temps")
timeline_df = filtered.dropna(subset=["timestamp_dt"]).copy()
if not timeline_df.empty:
    timeline_df["date"] = timeline_df["timestamp_dt"].dt.date
    grouped = timeline_df.groupby(["date", "severity"]).size().reset_index(name="Nombre")
    fig = px.bar(
        grouped, x="date", y="Nombre", color="severity",
        color_discrete_map=SEVERITY_COLORS, barmode="stack",
        labels={"date": "Date", "severity": "Criticité"},
    )
    fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=300)
    st.plotly_chart(fig, use_container_width=True)
else:
    st.caption("Aucun horodatage exploitable sur les incidents filtrés.")

# ─── Alertes de corrélation (si dispo) ───────────────────────────────────────

if "correlation_pattern" in filtered.columns:
    corr_df = filtered[filtered["correlation_pattern"].fillna("") != ""]
    if not corr_df.empty:
        st.subheader("🔗 Alertes de corrélation détectées")
        corr_display = corr_df[
            [c for c in ["incident_id", "timestamp", "severity", "correlation_pattern",
                         "source_ip", "risk_score"] if c in corr_df.columns]
        ].copy()
        if "severity" in corr_display.columns:
            corr_display["severity"] = corr_display["severity"].apply(
                lambda s: f"{SEVERITY_ICONS.get(s, '')} {s}"
            )
        st.dataframe(corr_display, use_container_width=True, hide_index=True)

st.divider()

# ─── Table des incidents ───────────────────────────────────────────────────

st.subheader("📋 Tous les incidents")
display_cols = [c for c in [
    "incident_id", "timestamp", "severity", "attack_type",
    "source_ip", "affected_system", "risk_score",
    "mitre_technique", "needs_escalation", "false_positive",
] if c in filtered.columns]

table_df = filtered[display_cols].copy()
if "severity" in table_df.columns:
    table_df["severity"] = table_df["severity"].apply(
        lambda s: f"{SEVERITY_ICONS.get(s, '')} {s}"
    )
table_df = (
    table_df.sort_values("timestamp", ascending=False)
    if "timestamp" in table_df.columns else table_df
)
st.dataframe(table_df, use_container_width=True, hide_index=True)

# ─── Détail d'un incident ─────────────────────────────────────────────────

with st.expander("🔎 Voir le détail d'un incident"):
    ids = filtered["incident_id"].dropna().tolist() if "incident_id" in filtered.columns else []
    if ids:
        chosen = st.selectbox("Choisir un incident", ids)
        row = filtered[filtered["incident_id"] == chosen]
        if not row.empty:
            st.json(row.iloc[0].dropna().to_dict())
    else:
        st.caption("Aucun incident disponible.")

st.divider()

# ─── Rapports individuels générés ────────────────────────────────────────────

st.subheader("📄 Rapports d'incidents")

REPORTS_DIR = os.path.join(PROJECT_ROOT, "data", "reports")

def get_report_files() -> list:
    """Récupère tous les rapports individuels triés du plus récent au plus ancien."""
    if not os.path.exists(REPORTS_DIR):
        return []
    files = [
        f for f in os.listdir(REPORTS_DIR)
        if f.startswith("incident_report") and f.endswith(".txt")
    ]
    files.sort(reverse=True)
    return files

report_files = get_report_files()

if not report_files:
    st.caption("Aucun rapport individuel généré pour le moment.")
else:
    st.caption(f"{len(report_files)} rapport(s) disponible(s) dans `data/reports/`")

    # Barre de recherche
    search = st.text_input("🔍 Rechercher un rapport (ID incident, IP, type...)", "")

    filtered_reports = [
        f for f in report_files
        if not search or search.lower() in f.lower()
    ]

    if not filtered_reports:
        st.caption("Aucun rapport ne correspond à la recherche.")
    else:
        # Afficher les rapports dans des expanders
        for filename in filtered_reports[:20]:  # max 20 affichés
            filepath = os.path.join(REPORTS_DIR, filename)
            # Extraire l'ID incident depuis le nom du fichier
            parts = filename.replace("incident_report_", "").replace(".txt", "")
            label_parts = parts.rsplit("_", 2)
            incident_id = "_".join(label_parts[:-2]) if len(label_parts) > 2 else parts

            # Lire les 2 premières lignes pour aperçu
            preview = ""
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f.readlines() if l.strip()]
                    preview = lines[1] if len(lines) > 1 else ""
            except Exception:
                pass

            with st.expander(f"📋 {incident_id}   —   {preview[:80]}"):
                content = read_text_file(filepath)
                if content:
                    st.markdown(content)
                else:
                    st.caption("Fichier introuvable.")

        if len(filtered_reports) > 20:
            st.caption(f"... et {len(filtered_reports) - 20} autre(s) rapport(s). Utilisez la recherche pour filtrer.")

st.divider()

# ─── Rapports LLM ────────────────────────────────────────────────────────────

st.subheader(" Resume Rapports ")
meta = get_shared_meta()

tab1, tab2 = st.tabs(["Synthèse", "Resume"])
with tab1:
    info = meta.get("last_summary_report")
    if info:
        st.caption(f"Généré le {info.get('generated_at', 'N/A')}")
        st.text(read_text_file(info.get("filepath", "")) or "Fichier introuvable.")
    else:
        st.caption("Aucune synthèse générée pour le moment.")
with tab2:
    info = meta.get("last_dashboard")
    if info:
        st.caption(f"Généré le {info.get('generated_at', 'N/A')}")
        st.text(read_text_file(info.get("filepath", "")) or "Fichier introuvable.")
    else:
        st.caption("Aucun dashboard texte généré pour le moment.")