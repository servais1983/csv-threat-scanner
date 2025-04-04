#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de génération de rapports pour CSV Threat Scanner.
"""

import os
import logging
import json
from datetime import datetime
import jinja2
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from colorama import Fore, Style

class ReportGenerator:
    """
    Génère un rapport détaillé basé sur les résultats de l'analyse de sécurité.
    """
    
    def __init__(self, template_dir='templates'):
        """
        Initialise le générateur de rapports.
        
        Args:
            template_dir (str): Répertoire contenant les templates Jinja2
        """
        self.logger = logging.getLogger('report_generator')
        self.template_dir = template_dir
        
        # Vérification et création du répertoire de templates si nécessaire
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
            self.logger.info(f"Répertoire de templates créé: {template_dir}")
            # Création du template par défaut
            self._create_default_template()
        
        # Configuration de l'environnement Jinja2
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=jinja2.select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Ajouter des filtres personnalisés
        self.jinja_env.filters['format_datetime'] = lambda dt: dt.strftime('%Y-%m-%d %H:%M:%S') if isinstance(dt, datetime) else str(dt)
        self.jinja_env.filters['severity_color'] = self._severity_color
    
    def _create_default_template(self):
        """Crée un template HTML par défaut pour le rapport."""
        default_template = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'analyse de sécurité {{ scan_info.scan_date }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        .header {
            background-color: #34495e;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .summary {
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-bottom: 30px;
        }
        .summary-box {
            flex: 1;
            min-width: 200px;
            margin: 10px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
            border-left: 5px solid #3498db;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        .summary-box.critical {
            border-left-color: #e74c3c;
        }
        .summary-box.high {
            border-left-color: #e67e22;
        }
        .summary-box.medium {
            border-left-color: #f1c40f;
        }
        .summary-box.low {
            border-left-color: #2ecc71;
        }
        .summary-number {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .threat-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        .threat-table th, .threat-table td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .threat-table th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        .threat-table tr:hover {
            background-color: #f5f5f5;
        }
        .severity-critical {
            color: white;
            background-color: #e74c3c;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .severity-high {
            color: white;
            background-color: #e67e22;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .severity-medium {
            color: white;
            background-color: #f1c40f;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .severity-low {
            color: white;
            background-color: #2ecc71;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .charts {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        .chart {
            flex: 1;
            min-width: 300px;
            height: 400px;
            margin: 15px;
            padding: 15px;
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            font-size: 0.9em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Rapport d'analyse de sécurité</h1>
        <p>Date de l'analyse: {{ scan_info.scan_date }}</p>
    </div>
    
    <div class="summary">
        <div class="summary-box">
            <div class="summary-title">Fichier analysé</div>
            <div>{{ scan_info.filename }}</div>
        </div>
        <div class="summary-box">
            <div class="summary-title">Entrées analysées</div>
            <div class="summary-number">{{ scan_info.records_analyzed }}</div>
        </div>
        <div class="summary-box">
            <div class="summary-title">Durée de l'analyse</div>
            <div>{{ scan_info.duration | round(2) }} secondes</div>
        </div>
        <div class="summary-box critical">
            <div class="summary-title">Menaces critiques</div>
            <div class="summary-number">{{ results.critical | length }}</div>
        </div>
        <div class="summary-box high">
            <div class="summary-title">Menaces élevées</div>
            <div class="summary-number">{{ results.high | length }}</div>
        </div>
        <div class="summary-box medium">
            <div class="summary-title">Menaces moyennes</div>
            <div class="summary-number">{{ results.medium | length }}</div>
        </div>
        <div class="summary-box low">
            <div class="summary-title">Menaces faibles</div>
            <div class="summary-number">{{ results.low | length }}</div>
        </div>
    </div>
    
    <div class="charts">
        <div class="chart" id="menaces-par-severite">
            {{ severity_chart }}
        </div>
        <div class="chart" id="menaces-par-type">
            {{ type_chart }}
        </div>
    </div>
    
    {% if results.critical %}
    <h2>Menaces critiques</h2>
    <table class="threat-table">
        <thead>
            <tr>
                <th>Type</th>
                <th>Détails</th>
                <th>Timestamp</th>
                <th>Utilisateur</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
            {% for threat in results.critical %}
            <tr>
                <td><span class="severity-critical">{{ threat.type }}</span></td>
                <td>{{ threat.details }}</td>
                <td>{{ threat.timestamp }}</td>
                <td>{{ threat.user }}</td>
                <td>{{ threat.source }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}
    
    {% if results.high %}
    <h2>Menaces élevées</h2>
    <table class="threat-table">
        <thead>
            <tr>
                <th>Type</th>
                <th>Détails</th>
                <th>Timestamp</th>
                <th>Utilisateur</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
            {% for threat in results.high %}
            <tr>
                <td><span class="severity-high">{{ threat.type }}</span></td>
                <td>{{ threat.details }}</td>
                <td>{{ threat.timestamp }}</td>
                <td>{{ threat.user }}</td>
                <td>{{ threat.source }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}
    
    {% if results.medium %}
    <h2>Menaces moyennes</h2>
    <table class="threat-table">
        <thead>
            <tr>
                <th>Type</th>
                <th>Détails</th>
                <th>Timestamp</th>
                <th>Utilisateur</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
            {% for threat in results.medium %}
            <tr>
                <td><span class="severity-medium">{{ threat.type }}</span></td>
                <td>{{ threat.details }}</td>
                <td>{{ threat.timestamp }}</td>
                <td>{{ threat.user }}</td>
                <td>{{ threat.source }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}
    
    {% if results.low %}
    <h2>Menaces faibles</h2>
    <table class="threat-table">
        <thead>
            <tr>
                <th>Type</th>
                <th>Détails</th>
                <th>Timestamp</th>
                <th>Utilisateur</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
            {% for threat in results.low %}
            <tr>
                <td><span class="severity-low">{{ threat.type }}</span></td>
                <td>{{ threat.details }}</td>
                <td>{{ threat.timestamp }}</td>
                <td>{{ threat.user }}</td>
                <td>{{ threat.source }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}
    
    <div class="footer">
        <p>Généré par CSV Threat Scanner - {{ scan_info.scan_date }}</p>
    </div>
</body>
</html>
"""
        with open(os.path.join(self.template_dir, 'default_report.html'), 'w', encoding='utf-8') as f:
            f.write(default_template)
        self.logger.info("Template par défaut créé")
    
    def _severity_color(self, severity):
        """Retourne la couleur CSS correspondant au niveau de sévérité."""
        colors = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f1c40f',
            'low': '#2ecc71'
        }
        return colors.get(severity.lower(), '#3498db')
    
    def _generate_severity_chart(self, results):
        """Génère un graphique de répartition des menaces par sévérité."""
        severity_counts = {
            'Critique': len(results.get('critical', [])),
            'Élevée': len(results.get('high', [])),
            'Moyenne': len(results.get('medium', [])),
            'Faible': len(results.get('low', []))
        }
        
        # Couleurs pour chaque niveau de sévérité
        colors = ['#e74c3c', '#e67e22', '#f1c40f', '#2ecc71']
        
        # Créer la figure avec Plotly
        fig = go.Figure(data=[
            go.Pie(
                labels=list(severity_counts.keys()),
                values=list(severity_counts.values()),
                hole=0.4,
                marker=dict(colors=colors),
                textinfo='label+percent',
                insidetextorientation='radial'
            )
        ])
        
        fig.update_layout(
            title='Répartition des menaces par sévérité',
            showlegend=True,
            height=400,
            margin=dict(l=0, r=0, t=50, b=0)
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def _generate_threat_type_chart(self, results):
        """Génère un graphique de répartition des menaces par type."""
        # Rassembler tous les types de menaces
        all_threats = results.get('critical', []) + results.get('high', []) + results.get('medium', []) + results.get('low', [])
        
        # Compter les occurrences de chaque type
        type_counts = {}
        for threat in all_threats:
            threat_type = threat.get('type', 'unknown')
            type_counts[threat_type] = type_counts.get(threat_type, 0) + 1
        
        # Convertir en DataFrame pour Plotly
        df = pd.DataFrame({
            'Type': list(type_counts.keys()),
            'Count': list(type_counts.values())
        })
        
        # Trier par nombre d'occurrences décroissant
        df = df.sort_values('Count', ascending=False)
        
        # Créer le graphique
        fig = px.bar(
            df,
            x='Type',
            y='Count',
            color='Count',
            color_continuous_scale='Viridis',
            labels={'Type': 'Type de menace', 'Count': 'Nombre d\'occurrences'},
        )
        
        fig.update_layout(
            title='Types de menaces détectées',
            xaxis_tickangle=-45,
            height=400,
            margin=dict(l=0, r=0, t=50, b=100)
        )
        
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
    
    def generate(self, results, scan_info):
        """
        Génère un rapport HTML basé sur les résultats de l'analyse.
        
        Args:
            results (dict): Résultats de l'analyse par sévérité
            scan_info (dict): Informations sur l'analyse effectuée
        
        Returns:
            str: Rapport HTML
        """
        try:
            # Génération des graphiques
            severity_chart = self._generate_severity_chart(results)
            type_chart = self._generate_threat_type_chart(results)
            
            # Chargement du template
            template = self.jinja_env.get_template('default_report.html')
            
            # Rendu du template avec les données
            html_report = template.render(
                results=results,
                scan_info=scan_info,
                severity_chart=severity_chart,
                type_chart=type_chart
            )
            
            self.logger.info(f"{Fore.GREEN}Rapport généré avec succès{Style.RESET_ALL}")
            return html_report
            
        except Exception as e:
            self.logger.error(f"{Fore.RED}Erreur lors de la génération du rapport: {str(e)}{Style.RESET_ALL}")
            # En cas d'erreur, générer un rapport basique
            basic_report = f"""<!DOCTYPE html>
<html>
<head>
    <title>Rapport d'analyse basique</title>
</head>
<body>
    <h1>Rapport d'analyse de sécurité (format basique)</h1>
    <p>Date: {scan_info.get('scan_date', 'Inconnue')}</p>
    <p>Fichier: {scan_info.get('filename', 'Inconnu')}</p>
    <h2>Résumé des menaces:</h2>
    <ul>
        <li>Critique: {len(results.get('critical', []))}</li>
        <li>Élevée: {len(results.get('high', []))}</li>
        <li>Moyenne: {len(results.get('medium', []))}</li>
        <li>Faible: {len(results.get('low', []))}</li>
    </ul>
    <p>Note: Une erreur s'est produite lors de la génération du rapport complet.</p>
</body>
</html>"""
            return basic_report
