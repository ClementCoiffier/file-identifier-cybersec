import sys
import json

def load_signatures(db_path="signatures.json"):
    """Charge la base de signatures et convertit les magic en bytes."""
    with open(db_path, "r") as f:
        data= json.load(f)  #dictionnaire à une seule clé : « signatures » et une liste de valeurs
    for sig in data["signatures"]: #item de la collection « sigs »
        sig["magic_bytes"] = bytes.fromhex(sig["magic"]) #conversion d'octets depuis l'hexa
    return data["signatures"]

def read_header(filepath, num_bytes=16): #16 octets (assez pour couvrir la plus longue signature de la base).
    """Lit les premiers octets d'un fichier en mode binaire."""
    with open(filepath, "rb") as f: 
        return f.read(num_bytes) #f.read(16)=retourne un objet bytes pas string

def identify(header, signatures):
    """Identifie le type réel d'un fichier à partir de son header.
    Retourne le dict de signature correspondant, ou None si inconnu.""" 
    if not header:
        return None #fichier vide 
    
    #Tri par longueur décroissante: les signatures les plus spécifiques sont testées en premier (ex: car sinon début de docx=zip).
    for sig in sorted(signatures, key=lambda s: len(s["magic_bytes"]), reverse=True):
        if header.startswith(sig["magic_bytes"]): #on compare le début du header avec chaque signature
            return sig
    return None

if __name__ == "__main__":
    path = sys.argv[1]
    header = read_header(path)
    sigs = load_signatures() #liste complète des dictionnaires
    result = identify(header, sigs)

    #print(f"{len(sigs)} signatures chargées")
    #for s in sigs:
    #    print(f" {s['type']}: {s['magic_bytes'].hex(' ').upper()}")
    
    # .hex(" ") affiche les octets séparés par des espaces.
    #print(f"Header de {path}: {header.hex(' ').upper()}") #.hex converti en hexa

    print(f"Fichier: {path}")
    print(f"Header : {header.hex(' ').upper() if header else '(fichier vide)'}")
    if result:
        print(f"Type détecté: {result['type']}")
    else:
        print("Type détecté: inconnu")