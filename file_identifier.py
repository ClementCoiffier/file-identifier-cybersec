import sys
import json
import os 
import argparse

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json") #Base trouvée, peu importe où on l'appelle.

#Types qui déguisés sous une autre extension, constituent un signal fort.
DANGEROUS_TYPES = {
    "Windows executable (PE)",
    "Linux executable (ELF)",
}

def load_signatures(db_path=DB_PATH):
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
        return("UNKNOWN", "Type réel non identifiable (signature absente de la base)")

    if ext == "":
        return ("NO_EXT", f"Fichier sans extension, type réel : {sig['type']}")

    if ext in sig["extensions"]:
        return ("OK", f"Extension cohérente avec le contenu ({sig['type']})")

    if sig["type"] in DANGEROUS_TYPES:
        return ("CRITICAL", f"L'extension {ext} masque un exécutable ({sig['type']})")

    return ("MISMATCH", f"L'extension {ext} ne correspond pas au contenu ({sig['type']})")

def scan_file(filepath, signatures):
    """Analyse un fichier et retourne un dict de résultat."""
    try:
        header = read_header(filepath)
    except (PermissionError, OSError) as e:
        return {"path": filepath, "type": None,
                "verdict": "Erreur", "message": f"Lecture impossible : {e}"}

    sig = identify(header, signatures)
    verdict, message = check_mismatch(filepath, sig)
    return {"path": filepath,
            "type": sig["type"] if sig else None, 
            "verdict": verdict, "message": message}

def collect_files(paths, recursive=False):
    """Transforme une liste de chemins (fichiers ou dossiers) en liste de fichiers."""
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append(p)
        elif os.path.isdir(p):
            if recursive:
                for root, _, names in os.walk(p): #_ convention Python pour « variable dont je n'ai pas l'usage »
                    for n in sorted(names):
                        files.append(os.path.join(root, n))
            else:
                for n in sorted(os.listdir(p)):
                    full = os.path.join(p, n)
                    if os.path.isfile(full):
                        files.append(full)
        else:
            print(f"[ERREUR] Chemin introuvable : {p}", file=sys.stderr)
    return files

LABELS = {
    "OK":       "[OK]       ",
    "MISMATCH": "[SUSPECT]  ",
    "CRITICAL": "[CRITIQUE] ",
    "NO_EXT":   "[INFO]     ",
    "UNKNOWN":  "[INCONNU]  ",
    "ERREUR":   "[ERREUR]   ",
}

EXIT_CODES = {"OK": 0, "NO_EXT": 0, "UNKNOWN": 0, "MISMATCH": 1, "ERREUR": 1, "CRITICAL": 2}

def main():
    parser = argparse.ArgumentParser(
        description="Identifie le type réel des fichiers via leur magic number "
                    "et signale les extensions mensongères.")
    parser.add_argument("paths", nargs="+", metavar="CHEMIN", #accepte un ou plusieurs chemins, et argparse refuse tout seul l'appel sans argument avec un message d'usage
                        help="fichiers ou dossiers à analyser")
    parser.add_argument("-r", "--recursive", action="store_true",
                        help="parcourir aussi les sous-dossiers")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="n'afficher que les anomalies")
    parser.add_argument("--db", default=DB_PATH,
                        help="chemin vers une base de signatures alternative")
    args = parser.parse_args()

    signatures = load_signatures(args.db)
    files = collect_files(args.paths, args.recursive)

    counts = {}
    worst = 0

    for filepath in files:
        r = scan_file(filepath, signatures)
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1 #incrémente un compteur qui peut ne pas encore exister ; get renvoie 0 par défaut au lieu de lever une KeyError
        worst = max(worst, EXIT_CODES[r["verdict"]]) #fait remonter la gravité maximale

        if args.quiet and EXIT_CODES[r["verdict"]] == 0:
            continue
        print(f"{LABELS[r['verdict']]}{r['path']}")
        print(f"{'':11}{r['message']}")

    resume = ", ".join(f"{n} {v}" for v, n in sorted(counts.items()))
    print(f"\n{len(files)} fichier(s) analysé(s) - {resume or 'aucun résultat'}")
    sys.exit(worst)

if __name__ == "__main__":
    main()