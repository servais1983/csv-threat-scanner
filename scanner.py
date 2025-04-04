#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CSV Threat Scanner - Outil d'analyse de fichiers CSV pour la détection de menaces.
"""

import os
import sys
import argparse
import logging
import time
import pandas as pd
from tqdm import tqdm
from colorama import init, Fore, Style
from datetime import datetime

# Import des modules internes
from threat_detector import ThreatDetector
from report_generator import ReportGenerator
from utils import setup_logger, load_config

# Initialisation de colorama pour les couleurs dans le terminal
init()

def parse_arguments():
    """Parse les arguments de ligne de commande."""
    parser = argparse.ArgumentParser(description='Analyse les fichiers CSV pour détecter des menaces potentielles.')
    parser.add_argument('--input', '-i', required=True, help='Chemin vers le fichier CSV à analyser')
    parser.add_argument('--output', '-o', default='threat_report.html', help='Nom du fichier de rapport (par défaut: threat_report.html)')
    parser.add_argument('--config', '-c', default='config.yaml', help='Fichier de configuration')
    parser.add_argument('--verbose', '-v', action='store_true', help='Mode verbeux')
    return parser.parse_args()

def main():
    """Fonction principale du scanner."""
    # Traitement des arguments
    args = parse_arguments()
    
    # Configuration du logger
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(log_level)
    
    logger.info(f"{Fore.CYAN}CSV Threat Scanner{Style.RESET_ALL} - Démarrage de l'analyse")
    start_time = time.time()
    
    # Vérification de l'existence du fichier d'entrée
    if not os.path.isfile(args.input):
        logger.error(f"{Fore.RED}Erreur : Le fichier {args.input} n'existe pas.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Chargement de la configuration
    try:
        config = load_config(args.config)
        logger.debug(f"Configuration chargée depuis {args.config}")
    except Exception as e:
        logger.warning(f"{Fore.YELLOW}Impossible de charger la configuration : {str(e)}. Utilisation des paramètres par défaut.{Style.RESET_ALL}")
        config = {}
    
    # Chargement du fichier CSV
    try:
        logger.info(f"Chargement du fichier CSV : {args.input}")
        df = pd.read_csv(args.input)
        logger.info(f"Fichier chargé avec succès : {len(df)} entrées trouvées")
    except Exception as e:
        logger.error(f"{Fore.RED}Erreur lors du chargement du fichier CSV : {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Initialisation du détecteur de menaces
    detector = ThreatDetector(config.get('threat_detection', {}))
    
    # Analyse des menaces
    logger.info("Analyse des menaces en cours...")
    try:
        with tqdm(total=len(df), desc="Analyse", unit="entrées") as pbar:
            results = detector.analyze(df, progress_callback=lambda: pbar.update(1))
    except Exception as e:
        logger.error(f"{Fore.RED}Erreur pendant l'analyse : {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Génération du rapport
    logger.info("Génération du rapport HTML...")
    try:
        report_gen = ReportGenerator(template_dir=config.get('templates', 'templates'))
        report_html = report_gen.generate(
            results=results,
            scan_info={
                'filename': os.path.basename(args.input),
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'records_analyzed': len(df),
                'duration': time.time() - start_time
            }
        )
        
        # Écriture du rapport
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        logger.info(f"{Fore.GREEN}Rapport généré avec succès : {args.output}{Style.RESET_ALL}")
        
        # Affichage du récapitulatif
        total_threats = sum(len(threats) for threat_type, threats in results.items())
        logger.info(f"{Fore.YELLOW}Récapitulatif :{Style.RESET_ALL}")
        logger.info(f"  - Entrées analysées : {len(df)}")
        logger.info(f"  - Menaces détectées : {total_threats}")
        for threat_type, threats in results.items():
            if threats:
                if threat_type == 'critical':
                    color = Fore.RED
                elif threat_type == 'high':
                    color = Fore.LIGHTRED_EX
                elif threat_type == 'medium':
                    color = Fore.YELLOW
                else:
                    color = Fore.RESET
                logger.info(f"  - {color}{threat_type.capitalize()}{Style.RESET_ALL} : {len(threats)} menaces")
        
    except Exception as e:
        logger.error(f"{Fore.RED}Erreur lors de la génération du rapport : {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Fin du programme
    elapsed_time = time.time() - start_time
    logger.info(f"Analyse terminée en {elapsed_time:.2f} secondes")

if __name__ == "__main__":
    main()
