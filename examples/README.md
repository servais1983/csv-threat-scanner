# Exemples pour CSV Threat Scanner

Ce répertoire contient des fichiers CSV d'exemple pour tester les fonctionnalités de détection de menaces de l'outil.

## Fichiers disponibles

### event_logs.csv

Un fichier d'exemple contenant des journaux d'événements fictifs qui simulent diverses activités sur un réseau, y compris des comportements légitimes et malveillants. Ce fichier contient des exemples de :

- Tentatives de connexion depuis des adresses IP malveillantes connues
- Commandes suspectes liées à des logiciels malveillants et ransomwares
- Comportements typiques des ransomwares (chiffrement massif de fichiers)
- Désactivation de fonctionnalités de sécurité (Windows Defender, pare-feu, etc.)
- Suppression des copies shadow de Windows
- Création d'utilisateurs suspects
- Élévation de privilèges
- Connexions à des serveurs de commande et contrôle
- Activités suspectes liées à BitLocker
- Modifications du registre Windows potentiellement dangereuses

## Utilisation

Pour tester l'outil avec ces exemples, utilisez la commande suivante :

```bash
python scanner.py --input examples/event_logs.csv --output rapport.html
```

## Format de fichier CSV

Les fichiers CSV doivent contenir au minimum les colonnes suivantes :
- `timestamp` : Horodatage de l'événement (date et heure)
- `user` : Nom d'utilisateur ou compte associé à l'événement
- `action` : Type d'action effectuée (login, file_access, command_executed, etc.)
- `source` : Source de l'action (adresse IP, nom d'hôte, etc.)
- `target` : Cible de l'action (fichier, utilisateur, service, etc.)
- `status` : Statut de l'action (success, failure, denied, etc.)
- `details` : Informations supplémentaires sur l'événement

## Création de vos propres fichiers de test

Vous pouvez créer vos propres fichiers CSV pour tester des scénarios spécifiques. Assurez-vous simplement de respecter le format des colonnes.

Pour générer des rapports plus complets, incluez des événements qui devraient déclencher différentes catégories de menaces :

1. **Menaces critiques** : Activité de ransomware, suppression des sauvegardes, etc.
2. **Menaces élevées** : Désactivation des protections, connexions à des IPs malveillantes, etc.
3. **Menaces moyennes** : Processus suspects, changements de comptes, etc.
4. **Menaces faibles** : Mots-clés suspects, comportements inhabituels, etc.
