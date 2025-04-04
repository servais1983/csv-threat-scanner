# CSV Threat Scanner

Un outil puissant pour analyser les fichiers CSV à la recherche de comportements suspects, traces de malware, ransomware et autres menaces potentielles dans votre environnement informatique.

## Fonctionnalités

- Analyse des fichiers de logs au format CSV
- Détection de multiples types de menaces :
  - Traces de ransomware (BitLocker forcé, extensions modifiées)
  - Changements de comptes suspects
  - Activités de malware connues
  - Connexions réseau suspectes
  - Modifications de registres Windows potentiellement dangereuses
  - Et bien plus...
- Génération de rapports HTML clairs et détaillés
- Alertes configurables sur différents niveaux de gravité

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/csv-threat-scanner.git
cd csv-threat-scanner

# Installer les dépendances
pip install -r requirements.txt
```

## Utilisation

```bash
python scanner.py --input mon_fichier.csv --output rapport.html
```

### Options

- `--input` : Fichier CSV à analyser (obligatoire)
- `--output` : Nom du fichier de rapport (par défaut: threat_report.html)
- `--config` : Fichier de configuration personnalisé (optionnel)
- `--verbose` : Affiche des informations détaillées pendant l'analyse

## Structure des fichiers CSV supportés

L'outil est conçu pour être flexible, mais fonctionne mieux avec des fichiers CSV qui contiennent au moins certains des champs suivants :
- Horodatage (timestamp)
- Utilisateur ou compte
- Action effectuée
- Source de l'action
- Destination ou cible
- Statut de l'opération
- Détails supplémentaires

## Exemples de menaces détectées

- Chiffrement de fichiers multiples en peu de temps (possible ransomware)
- Élévations de privilèges non autorisées
- Installations de logiciels suspects
- Désactivation des outils de sécurité
- Communications avec des domaines malveillants connus

## Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.
