#  Mini-SIEM Python (v2.0)

Un outil d'analyse de logs interactif en ligne de commande, conçu pour identifier rapidement les adresses IP malveillantes, évaluer leur niveau de menace et générer des rapports de sécurité.

##  Objectif du projet
Ce projet a été réalisé pour consolider mes compétences en **Python** appliquées à la **Cybersécurité**. Il met en pratique :
- La Programmation Orientée Objet (POO)
- La manipulation et l'extraction de données à partir de fichiers textes (Logs)
- L'utilisation de dictionnaires et d'ensembles (`set`) pour optimiser la mémoire et la recherche
- La gestion robuste des erreurs (`try/except`) et la validation de données
- L'exportation de données structurées au format standardisé JSON
- La création d'un menu interactif en CLI (Command Line Interface)

##  Fonctionnalités
1. **Ingestion de logs résiliente** : Lit le fichier `logs.txt`, ignore automatiquement les lignes mal formatées et vérifie la validité cryptographique des adresses IP.
2. **Identification des menaces** : Isole les adresses IP uniques.
3. **Cartographie des attaques** : Compte le nombre de requêtes et liste les ports spécifiques (sans doublons) touchés par chaque attaquant.
4. **Classification automatique** : Évalue le niveau de menace (FAIBLE, MOYENNE, ÉLEVÉE, CRITIQUE) en fonction du volume de requêtes.
5. **Exportation des rapports** : Sauvegarde les résultats de l'analyse dans un fichier `.json` horodaté pour une utilisation ultérieure.

##  Comment l'utiliser
1. Assurez-vous d'avoir Python installé sur votre machine.
2. Clonez ce dépôt ou téléchargez les fichiers.
3. Lancez le script depuis votre terminal :
```bash
python mini_siem.py
