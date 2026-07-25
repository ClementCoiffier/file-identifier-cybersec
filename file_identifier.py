import sys
import json
import os 

#Types qui déguisés sous une autre extension, constituent un signal fort.
DANGEROUS_TYPES = {
    "Windows executable (PE)",
    "Linux executable (ELF)",
}

def load_signatures(db_path="signatures.json"):
    """Charge la base de signatures et convertit les magic en bytes."""
    with open(db_path, "r") as f:
        data= json.load(f)  #dictionnaire à une seule clé : « signatures » et une liste de valeurs.
    for sig in data["signatures"]: #item de la collection « sigs ».
        sig["magic_bytes"] = bytes.fromhex(sig["magic"]) #conversion d'octets depuis l'hexa.
    return data["signatures"]

def read_header(filepath, num_bytes=16): #16 octets (assez pour couvrir la plus longue signature de la base).
    """Lit les premiers octets d'un fichier en mode binaire."""
    with open(filepath, "rb") as f: 
        return f.read(num_bytes) #f.read(16)=retourne un objet bytes pas string.

def identify(header, signatures):
    """Identifie le type réel d'un fichier à partir de son header.
    Retourne le dict de signature correspondant, ou None si inconnu.""" 
    if not header:
        return None #fichier vide.
    
    #Tri par longueur décroissante: les signatures les plus spécifiques sont testées en premier (ex: car sinon début de docx=zip).
    for sig in sorted(signatures, key=lambda s: len(s["magic_bytes"]), reverse=True):
        if header.startswith(sig["magic_bytes"]): #on compare le début du header avec chaque signature
            return sig
    return None

def get_extension(filepath):
    """Retourne l'extension en min, ou '' si le fichier n'en a pas. """
    return os.path.splitext(filepath)[1].lower()

def check_mismatch(filepath, sig):
    """Compare l'extension du fichier au type réel détecté.
    Retourne un tuple (verdict, message).
    Verdicts possibles: OK, MISMATCH, CRITICAL, NO_EXT, UNKNOWN"""

    ext = get_extension(filepath)

    if sig is None:
        return("UKNOWN", "Type réel non identifiable (signature absente de la base)")

    if ext == "":
        return ("NO_EXT", f"Fichier sans extension, type réel : {sig['type']}")

    if ext in sig["extensions"]:
        return ("OK", f"Extension cohérente avec le contenu ({sig['type']})")

    if sig["type"] in DANGEROUS_TYPES:
        return ("CRITICAL", f"L'extension {ext} masque un exécutable ({sig['type']})")

    return ("MISMATCH", f"L'extension {ext} ne correspond pas au contenu ({sig['type']})")

LABELS = {
    "OK":       "[OK]       ",
    "MISMATCH": "[SUSPECT]  ",
    "CRITICAL": "[CRITIQUE] ",
    "NO_EXT":   "[INFO]     ",
    "UNKNOWN":  "[INCONNU]  ",
}

EXIT_CODES = {"OK": 0, "NO_EXT": 0, "UNKNOWN": 0, "MISMATCH": 1, "CRITICAL": 2}

if __name__ == "__main__":
    path = sys.argv[1]
    header = read_header(path)
    sigs = load_signatures() #liste complète des dictionnaires.
    result = identify(header, sigs)
    verdict, message = check_mismatch(path, result)

    #print(f"{len(sigs)} signatures chargées")
    #for s in sigs:
    #    print(f" {s['type']}: {s['magic_bytes'].hex(' ').upper()}")
    
    # .hex(" ") affiche les octets séparés par des espaces.
    #print(f"Header de {path}: {header.hex(' ').upper()}") #.hex converti en hexa

    print(f"Fichier: {path}")
    print(f"Header : {header.hex(' ').upper() if header else '(fichier vide)'}")
    print(f"Type détecté: {result['type'] if result else 'inconnu'}")
    print(f"{LABELS[verdict]}{message}")

    sys.exit(EXIT_CODES[verdict])