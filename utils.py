#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fonctions utilitaires pour CSV Threat Scanner.
"""

import os
import logging
import yaml
import sys
from colorama import Fore, Style

def setup_logger(log_level=logging.INFO):
    """
    Configure le logger pour l'application.
    
    Args:
        log_level (int): Niveau de logging (par défaut: logging.INFO)
    
    Returns:
        logging.Logger: Logger configuré
    """
    # Créer le logger
    logger = logging.getLogger('csv_threat_scanner')
    logger.setLevel(log_level)
    
    # Vérifier si des handlers existent déjà pour éviter les doublons
    if not logger.handlers:
        # Configuration du handler de console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        
        # Format personnalisé pour le logging
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        
        # Ajouter le handler au logger
        logger.addHandler(console_handler)
        
        # Si en mode DEBUG, ajouter un fichier de log
        if log_level == logging.DEBUG:
            # Assurer que le répertoire logs existe
            logs_dir = 'logs'
            if not os.path.exists(logs_dir):
                os.makedirs(logs_dir)
                
            # Configuration du handler de fichier
            file_handler = logging.FileHandler(os.path.join(logs_dir, 'threat_scanner.log'))
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
    
    return logger

def load_config(config_file='config.yaml'):
    """
    Charge la configuration depuis un fichier YAML.
    
    Args:
        config_file (str): Chemin vers le fichier de configuration (par défaut: config.yaml)
    
    Returns:
        dict: Configuration chargée
    
    Raises:
        FileNotFoundError: Si le fichier de configuration n'existe pas
        yaml.YAMLError: Si le fichier YAML est mal formaté
    """
    # Configuration par défaut
    default_config = {
        'templates': 'templates',
        'signatures': 'signatures',
        'threat_detection': {
            'threshold': {
                'encryption_count': 10,
                'failed_login': 5
            },
            'business_hours': {
                'start': 8,
                'end': 18
            }
        }
    }
    
    # Si le fichier n'existe pas, créer un nouveau fichier avec la configuration par défaut
    if not os.path.isfile(config_file):
        logger = logging.getLogger('csv_threat_scanner')
        logger.warning(f"{Fore.YELLOW}Fichier de configuration {config_file} non trouvé. Création avec valeurs par défaut.{Style.RESET_ALL}")
        
        # Créer le répertoire si nécessaire
        config_dir = os.path.dirname(config_file)
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir)
        
        # Écrire la configuration par défaut
        with open(config_file, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        return default_config
    
    # Charger la configuration depuis le fichier
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    return config
