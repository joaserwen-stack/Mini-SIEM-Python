import os
import json
import ipaddress
from datetime import datetime

class Attaquant:
    def __init__(self, ip_cible):
        self.ip = ip_cible
        self.nb_requetes = 0
        # Utilisation d'un 'set' (ensemble) au lieu d'une liste pour éviter les doublons de ports
        self.ports_touches = set()
        self.premiere_activite = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.niveau_menace = "FAIBLE"

    def ajouter_tentative(self, port):
        self.nb_requetes += 1
        self.ports_touches.add(port)
        self.evaluer_menace()

    def evaluer_menace(self):
        # Logique de classification automatique
        if self.nb_requetes >= 10:
            self.niveau_menace = "CRITIQUE"
        elif self.nb_requetes >= 5:
            self.niveau_menace = "ELEVEE"
        elif self.nb_requetes >= 3:
            self.niveau_menace = "MOYENNE"

    def vers_dictionnaire(self):
        # Prépare l'objet pour l'exportation JSON
        return {
            "ip": self.ip,
            "requetes_totales": self.nb_requetes,
            "ports_cibles": list(self.ports_touches),
            "date_detection": self.premiere_activite,
            "niveau_menace": self.niveau_menace
        }

def nettoyer_ecran():
    os.system('cls' if os.name == 'nt' else 'clear')

def valider_ip(ip):
    # Vérifie cryptographiquement que la chaîne est bien une adresse IP valide
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Initialisation de la base de données en mémoire
base_attaquants = {}

while True:
    print("\n" + "="*45)
    print("SYSTÈME D'ANALYSE DE LOGS - SIEM CLI v2.0")
    print("="*45)
    print("1. Analyser un fichier de logs")
    print("2. Afficher le rapport des menaces")
    print("3. Exporter les donnees en JSON")
    print("4. Quitter")
    
    choix = input("\nVeuillez selectionner une option (1-4) : ")
    
    if choix == "1":
        chemin_fichier = input("Entrez le chemin du fichier (ex: logs.txt) : ")
        if not os.path.exists(chemin_fichier):
            print(f"[ERREUR] Le fichier '{chemin_fichier}' est introuvable.")
            continue
            
        lignes_traitees = 0
        lignes_ignorees = 0
        
        try:
            with open(chemin_fichier, "r") as fichier:
                for ligne in fichier:
                    ligne_propre = ligne.strip()
                    if not ligne_propre:
                        continue
                        
                    try:
                        ip, port = ligne_propre.split(",")
                        ip = ip.strip()
                        port = port.strip()
                        
                        # Sécurité : On s'assure que l'IP est valide et que le port est un chiffre
                        if not valider_ip(ip) or not port.isdigit():
                            lignes_ignorees += 1
                            continue
                            
                        if ip not in base_attaquants:
                            base_attaquants[ip] = Attaquant(ip)
                            
                        base_attaquants[ip].ajouter_tentative(port)
                        lignes_traitees += 1
                        
                    except ValueError:
                        lignes_ignorees += 1
                        
            print(f"[SUCCES] Analyse terminee. Lignes traitees : {lignes_traitees} | Lignes ignorees (format invalide) : {lignes_ignorees}")
        except Exception as e:
            print(f"[ERREUR CRITIQUE] Une erreur inattendue est survenue lors de la lecture : {e}")

    elif choix == "2":
        nettoyer_ecran()
        print("\n" + "-"*40)
        print("RAPPORT DE SECURITE DETAILLE")
        print("-"*40)
        
        if not base_attaquants:
            print("[INFO] Aucune donnee en memoire. Veuillez lancer une analyse d'abord.")
            continue
            
        for ip, attaquant in base_attaquants.items():
            print(f"IP Suspecte    : {ip}")
            print(f"Niveau Menace  : {attaquant.niveau_menace}")
            print(f"Total Requetes : {attaquant.nb_requetes}")
            print(f"Ports Cibles   : {', '.join(attaquant.ports_touches)}")
            print(f"1ere Detection : {attaquant.premiere_activite}")
            print("-" * 40)

    elif choix == "3":
        if not base_attaquants:
            print("[INFO] Aucune donnee a exporter. Veuillez lancer une analyse d'abord.")
            continue
            
        nom_export = f"rapport_siem_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        donnees_export = {ip: obj.vers_dictionnaire() for ip, obj in base_attaquants.items()}
        
        try:
            with open(nom_export, "w") as f:
                json.dump(donnees_export, f, indent=4)
            print(f"[SUCCES] Donnees exportees avec succes dans le fichier : {nom_export}")
        except IOError:
            print("[ERREUR] Impossible d'ecrire le fichier d'export JSON.")

    elif choix == "4":
        print("[INFO] Fermeture du systeme d'analyse. Au revoir.")
        break
        
    else:
        print("[ERREUR] Option non reconnue. Veuillez taper 1, 2, 3 ou 4.")
