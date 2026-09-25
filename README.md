# 🛡️ Mini-SIEM Python

Un outil d'analyse de logs interactif en ligne de commande, conçu pour identifier rapidement les adresses IP malveillantes et les ports ciblés lors de tentatives d'intrusion.

## 🎯 Objectif du projet
Ce projet a été réalisé pour consolider mes compétences en **Python** appliquées à la **Cybersécurité**. Il met en pratique :
- La Programmation Orientée Objet (POO)
- La manipulation et l'extraction de données à partir de fichiers textes (Logs)
- L'utilisation de dictionnaires pour optimiser la mémoire et la recherche
- La création d'un menu interactif en CLI (Command Line Interface)

## ⚙️ Fonctionnalités
1. **Ingestion de logs** : Lit et nettoie automatiquement un fichier `logs.txt`.
2. **Identification des menaces** : Isole les adresses IP uniques.
3. **Cartographie des attaques** : Compte le nombre de requêtes et liste les ports spécifiques touchés par chaque attaquant.

## 🚀 Comment l'utiliser
1. Assurez-vous d'avoir Python installé sur votre machine.
2. Clonez ce dépôt ou téléchargez les fichiers.
3. Lancez le script depuis votre terminal :
```bash
python mini_siem.py
