class Attaquant : 
    def __init__(self, ip_cible) : 
        self.ip = ip_cible
        self.nb_requetes = 0
        self.ports_touches = []

    def ajouter_tentative(self,port) : 
        self.nb_requetes += 1
        self.ports_touches.append(port)

# 1. Le carnet vide du policier
base_attaquants = {}

while True:
    print("\n===  MENU MINI-SIEM ===")
    print("1. Analyser le fichier logs.txt")
    print("2. Afficher les menaces détectées")
    print("3. Quitter")
    
    choix = input("Votre choix est le suivant : ")

    # On compare avec du texte ("1", "2", "3")
    if choix == "1": 
        with open("logs.txt", "r") as fichier:
            for ligne in fichier:
                ligne_propre = ligne.strip()
        
                # 2. On coupe la ligne avec nos ciseaux
                ip, port = ligne_propre.split(",")
                
                # 3. Est-ce que cette IP est inconnue dans notre carnet ?
                if ip not in base_attaquants:
                    # 4. On fabrique une figurine et on la range dans le carnet
                    base_attaquants[ip] = Attaquant(ip)
                
                # On appuie sur le bouton pour enregistrer le port !
                base_attaquants[ip].ajouter_tentative(port)
                
        print(" Analyse terminée avec succès !")

    elif choix == "2":
        for ip, attaquant in base_attaquants.items():
            print(f" Menace : {ip}")
            print(f"   - Nombre d'attaques : {attaquant.nb_requetes}")
            print(f"   - Ports touchés : {attaquant.ports_touches}")
            print("-" * 30) # une petite ligne de séparation

    elif choix == "3":
        print("Au revoir !")
        break # On casse la boucle pour arrêter le programme

    else:
        print(" Choix invalide. Veuillez réessayer.")