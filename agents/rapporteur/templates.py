# pour la génération des rapports d'incidents SOC

from datetime import datetime


def get_incident_report_template(incident_data: dict) -> str:
    """
    Gabarit principal pour un rapport d'incident détaillé.
    incident_data doit contenir les champs analysés par l'Agent Analyseur.
    """
    return f"""
Tu es un analyste SOC senior. Génère un rapport d'incident professionnel et structuré
basé sur les données suivantes :

=== DONNÉES D'INCIDENT ===
- ID Incident     : {incident_data.get('incident_id', 'N/A')}
- Date/Heure      : {incident_data.get('timestamp', datetime.now().isoformat())}
- Source IP       : {incident_data.get('source_ip', 'Inconnue')}
- Destination IP  : {incident_data.get('dest_ip', 'Inconnue')}
- Type d'attaque  : {incident_data.get('attack_type', 'Non classifié')}
- Criticité       : {incident_data.get('severity', 'MEDIUM')}
- Anomalies       : {incident_data.get('anomalies', [])}
- Événements liés : {incident_data.get('correlated_events', [])}
- Système affecté : {incident_data.get('affected_system', 'Inconnu')}
- Score de risque : {incident_data.get('risk_score', 'N/A')}

=== FORMAT ATTENDU DU RAPPORT ===

# RAPPORT D'INCIDENT DE SÉCURITÉ

## 1. Résumé Exécutif
[Résumé en 3-4 phrases : nature de l'incident, impact potentiel, urgence]

## 2. Description Détaillée
[Explication technique de l'incident : comment il s'est produit, chronologie]

## 3. Indicateurs de Compromission (IoC)
[Liste des IPs, hashes, domaines suspects, comportements anormaux]

## 4. Impact Évalué
[Systèmes affectés, données potentiellement compromises, continuité de service]

## 5. Recommandations de Mitigation
[Actions immédiates à prendre, mesures correctives, ordre de priorité]

## 6. Actions Suggérées pour l'Agent Exécuteur
[Actions concrètes : bloquer IP X, isoler machine Y, notifier équipe Z]

## 7. Conclusion
[Bilan et prochaines étapes de surveillance]

---
Rapport généré automatiquement par le Système Multi-Agents SOC
"""


def get_summary_template(incidents_list: list) -> str:
    """
    Gabarit pour un rapport de synthèse sur plusieurs incidents.
    """
    incidents_text = "\n".join([
        f"- [{inc.get('severity', 'N/A')}] {inc.get('attack_type', 'Inconnu')} "
        f"depuis {inc.get('source_ip', 'N/A')} à {inc.get('timestamp', 'N/A')}"
        for inc in incidents_list
    ])

    return f"""
Tu es un analyste SOC senior. Génère un rapport de synthèse pour les incidents suivants :

=== LISTE DES INCIDENTS ({len(incidents_list)} au total) ===
{incidents_text}

=== FORMAT ATTENDU ===

# RAPPORT DE SYNTHÈSE SOC — {datetime.now().strftime('%d/%m/%Y %H:%M')}

## Vue d'ensemble
[Nombre total d'incidents, répartition par criticité, tendances observées]

## Incidents Critiques & Élevés
[Détail des incidents les plus graves, à traiter en priorité]

## Patterns Détectés
[Corrélations entre incidents, campagnes d'attaque potentielles]

## Recommandations Globales
[Actions stratégiques pour renforcer la posture de sécurité]

## Métriques Clés
- Total incidents : {len(incidents_list)}
- Criticité CRITICAL : [nombre]
- Criticité HIGH : [nombre]
- Criticité MEDIUM : [nombre]
- Criticité LOW : [nombre]

---
Synthèse générée automatiquement par le Système Multi-Agents SOC
"""


def get_dashboard_template(stats: dict) -> str:
    """
    Gabarit pour générer un tableau de bord textuel synthétique.
    """
    return f"""
Génère un tableau de bord de sécurité SOC synthétique et lisible
basé sur ces statistiques :

=== STATISTIQUES ===
- Période analysée    : {stats.get('period', 'Dernières 24h')}
- Total alertes       : {stats.get('total_alerts', 0)}
- Incidents confirmés : {stats.get('confirmed_incidents', 0)}
- Faux positifs       : {stats.get('false_positives', 0)}
- Taux de détection   : {stats.get('detection_rate', 'N/A')}%
- Types d'attaques    : {stats.get('attack_types', {})}
- Top IPs suspectes   : {stats.get('top_suspicious_ips', [])}
- Actions exécutées   : {stats.get('executed_actions', [])}

=== FORMAT ATTENDU ===

# 📊 TABLEAU DE BORD SOC — {datetime.now().strftime('%d/%m/%Y')}

## Résumé de la Période
[Vue d'ensemble en 2-3 phrases]

## Statistiques Clés
[Tableau ou liste structurée des métriques importantes]

## Menaces Principales
[Top 3 des menaces détectées avec description courte]

## Statut du Système
[Santé globale, alertes actives, systèmes surveillés]

## Prochaines Actions Recommandées
[Liste priorisée d'actions pour les prochaines heures]

---
Dashboard généré automatiquement — Système Multi-Agents SOC
"""
