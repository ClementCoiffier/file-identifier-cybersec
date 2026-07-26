import sys
import json
import os 
import argparse
import csv
import zipfile
import math

from enum import Enum
from datetime import datetime
from collections import Counter

VERSION = "0.6.0"
RESET = "\033[0m" #remet tout à zéro, si pas de RESET toute la suite de la console reste colorée.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json") #Base trouvée, peu importe où on l'appelle.
CSV_FIELDS = ["path", "size", "header", "type", "entropy", "printable_ratio", "verdict", "message"]

#Types qui déguisés sous une autre extension, constituent un signal fort.
DANGEROUS_TYPES = {
    "Windows executable (PE)",
    "Linux executable (ELF)",
    "Java archive (JAR)",
    "Android package (APK)",
}

# Sous-types de ZIP, identifiés par les fichiers présents dans l'archive.
# L'ordre compte : les plus spécifiques d'abord (un APK contient aussi un META-INF/MANIFEST.MF, il doit donc être testé avant le JAR).
ZIP_SUBTYPES = [
    {"type": "Android package (APK)",
     "markers": ["AndroidManifest.xml", "classes.dex"],
     "extensions": [".apk"]},
    {"type": "Word document (OOXML)",
     "markers": ["word/document.xml"],
     "extensions": [".docx", ".docm", ".dotx"]},
    {"type": "Excel workbook (OOXML)",
     "markers": ["xl/workbook.xml"],
     "extensions": [".xlsx", ".xlsm", ".xltx"]},
    {"type": "PowerPoint presentation (OOXML)",
     "markers": ["ppt/presentation.xml"],
     "extensions": [".pptx", ".pptm", ".potx"]},
    {"type": "EPUB e-book",
     "markers": ["META-INF/container.xml", "mimetype"],
     "extensions": [".epub"]},
    {"type": "OpenDocument (ODF)",
     "markers": ["content.xml", "styles.xml", "mimetype"],
     "extensions": [".odt", ".ods", ".odp"]},
    {"type": "Java archive (JAR)",
     "markers": ["META-INF/MANIFEST.MF"],
     "extensions": [".jar", ".war", ".ear"]},
]

HEADER_SIZE = 16
SAMPLE_SIZE = 8192

# ASCII imprimable, plus tabulation, saut de ligne et retour chariot.
PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

# En dessous de cette taille, les mesures statistiques ne veulent rien dire.
MIN_SAMPLE_SIZE = 256

TEXT_RATIO_THRESHOLD = 0.95         # au-delà : contenu considéré textuel
DISGUISED_ENTROPY_THRESHOLD = 7.5   # au-delà, dans un fichier texte : chiffré ou compressé
PACKED_ENTROPY_THRESHOLD = 7.2      # au-delà, dans un exécutable : probablement packé

TEXT_EXTENSIONS = [
    ".txt", ".csv", ".tsv", ".log", ".md", ".json", ".xml", ".html", ".htm",
    ".css", ".js", ".py", ".c", ".h", ".java", ".ini", ".cfg", ".conf",
    ".yml", ".yaml", ".svg", ".sql", ".sh", ".bat", ".ps1",
]
class Verdict(Enum):
    """Verdicts possibles, avec leur libellé d'affichage et leur code de sortie."""
    #\033 est le caractère d'échappement ASCII (27)
    OK       = ("[OK]      ", 0, "\033[32m")    # vert 
    NO_EXT   = ("[INFO]    ", 0, "\033[36m")    # cyan
    UNKNOWN  = ("[INCONNU] ", 0, "\033[90m")    # gris
    MISMATCH = ("[SUSPECT] ", 1, "\033[33m")    # jaune
    ERREUR   = ("[ERREUR]  ", 1, "\033[35m")    # magenta
    CRITICAL = ("[CRITIQUE]", 2, "\033[31;1m")  # rouge gras

    def __init__(self, label, exit_code, color):
        self.label = label
        self.exit_code = exit_code
        self.color = color

def enable_colors():
    """Active les couleurs uniquement si la sortie est un vrai terminal."""
    if not sys.stdout.isatty(): #Si l'user écrit python file_identifier.py samples > rapport.txt, la sortie n'est plus un terminal mais un fichier. L'outil CLI teste isatty avant de colorer ce qui garde la sortie exploitable par grep ou par un autre script.
        return False
    if os.name =="nt": #pragma: no cover
        os.system("") #active l'interprétation des séquences ANSI sous Windows (contournement)
    return True

def colorize(verdict, text, enabled):
        return f"{verdict.color}{text}{RESET}" if enabled else text

def load_signatures(db_path=DB_PATH):
    """Charge la base de signatures et convertit les magic en bytes."""
    with open(db_path, "r") as f:
        data= json.load(f)  #dictionnaire à une seule clé : « signatures » et une liste de valeurs.
    for sig in data["signatures"]: #item de la collection « sigs ».
        sig["magic_bytes"] = bytes.fromhex(sig["magic"]) #conversion d'octets depuis l'hexa.
    return data["signatures"]

#def read_header(filepath, num_bytes=16): #16 octets (assez pour couvrir la plus longue signature de la base).
#    """Lit les premiers octets d'un fichier en mode binaire."""
#    with open(filepath, "rb") as f: 
#        return f.read(num_bytes) #f.read(16)=retourne un objet bytes pas string.

def read_sample(filepath, num_bytes=SAMPLE_SIZE):
    """Lit les premiers octets d'un fichier, assez pour l'analyse statistique."""
    with open(filepath, "rb") as f:
        return f.read(num_bytes)


def printable_ratio(data):
    """Fraction d'octets correspondant à des caractères affichables (0.0 à 1.0)."""
    if not data:
        return 0.0
    return sum(1 for b in data if b in PRINTABLE) / len(data)


def shannon_entropy(data):
    """Entropie de Shannon en bits par octet, de 0 (uniforme) à 8 (aléatoire)."""
    if not data:
        return 0.0
    total = len(data)
    entropie = -sum((count / total) * math.log2(count / total)
                    for count in Counter(data).values())
    return entropie if entropie else 0.0

def classify_unknown(filepath, printable):
    """Verdict pour un fichier dont aucune signature ne correspond."""
    ext = get_extension(filepath)

    if printable >= TEXT_RATIO_THRESHOLD:
        if ext in TEXT_EXTENSIONS:
            return (Verdict.OK,
                    f"Contenu textuel ({printable:.0%} d'octets imprimables), "
                    f"cohérent avec l'extension {ext}")
        return (Verdict.UNKNOWN,
                f"Contenu probablement textuel ({printable:.0%} d'octets "
                "imprimables), format précis non identifié")

    return (Verdict.UNKNOWN, "Type réel non identifiable (signature absente de la base)")

def entropy_findings(ext, sig, entropy, sample_size):
    """Anomalie révélée par l'entropie, ou None."""
    if sample_size < MIN_SAMPLE_SIZE:
        return None

    if ext in TEXT_EXTENSIONS and entropy >= DISGUISED_ENTROPY_THRESHOLD:
        return (Verdict.CRITICAL,
                f"Extension {ext} annoncée mais entropie de {entropy:.2f}/8 : "
                "contenu chiffré ou compressé déguisé en texte")

    if sig and sig["type"] in DANGEROUS_TYPES and entropy >= PACKED_ENTROPY_THRESHOLD:
        return (Verdict.MISMATCH,
                f"Exécutable à entropie {entropy:.2f}/8 : probablement packé "
                "(compressé ou chiffré pour gêner l'analyse statique)")

    return None

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
        return(Verdict.UNKNOWN, "Type réel non identifiable (signature absente de la base)")

    if ext == "":
        return (Verdict.NO_EXT, f"Fichier sans extension, type réel : {sig['type']}")

    if ext in sig["extensions"]:
        return (Verdict.OK, f"Extension cohérente avec le contenu ({sig['type']})")

    if sig["type"] in DANGEROUS_TYPES:
        return (Verdict.CRITICAL, f"L'extension {ext} masque un exécutable ({sig['type']})")

    return (Verdict.MISMATCH, f"L'extension {ext} ne correspond pas au contenu ({sig['type']})")

def scan_file(filepath, signatures, deep=True):
    """Analyse un fichier et retourne un dict de résultat."""
    try:
        sample = read_sample(filepath)
        size = os.path.getsize(filepath)
    except OSError as e:
        return {"path": filepath, "size": None, "header": None, "type": None,
                "entropy": None, "printable_ratio": None,
                "verdict": Verdict.ERREUR, "message": f"Lecture impossible : {e}"}

    header = sample[:HEADER_SIZE]
    entropy = shannon_entropy(sample)
    printable = printable_ratio(sample)

    sig = identify(header, signatures)

    if deep and sig and sig["type"] == "ZIP archive":
        sub = inspect_zip(filepath)
        if sub:
            sig = sub

    if sig is None:
        verdict, message = classify_unknown(filepath, printable)
    else:
        verdict, message = check_mismatch(filepath, sig)

    # L'heuristique ne peut qu'aggraver un verdict, jamais l'adoucir.
    finding = entropy_findings(get_extension(filepath), sig, entropy, len(sample))
    if finding and finding[0].exit_code > verdict.exit_code:
        verdict, message = finding

    return {"path": filepath,
            "size": size,
            "header": header.hex(" ").upper() if header else "",
            "type": sig["type"] if sig else None,
            "entropy": round(entropy, 2),
            "printable_ratio": round(printable, 3),
            "verdict": verdict,
            "message": message}

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

def to_export(result):
    """Copie du résultat avec le Verdict converti en chaîne, pour l'export."""
    return {**result, "verdict": result["verdict"].name} #crée une copie du dictionnaire en écrasant une seule clé (l'original reste intact).

def export_json(path, results, summary, targets, recursive, exit_code):
    report = {
        "tool": "file_identifier",
        "version": VERSION,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "targets": targets,
        "recursive": recursive,
        "summary": {v.name: n for v, n in summary.items()},
        "exit_code": exit_code,
        "results": [to_export(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

def export_csv(path, results):
    with open(path, "w", newline="", encoding="utf-8-sig") as f: #le module csv gère lui-même ses fins de ligne (évite \r de windows).
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(to_export(r) for r in results)

def inspect_zip(filepath):
    """Ouvre une archive ZIP et affine son type d'après les fichiers qu'elle contient.
    Retourne un dict {type, extension}, ou None si indéterminé ou archive illisible."""
    try: #Règle générale en analyse de fichiers hostiles : lire les métadonnées, jamais extraire.
        with zipfile.ZipFile(filepath) as z:
            names = set(z.namelist()) #Ne lit que le catalogue central de l'archive (car décompresser un ZIP inconnu expose aux zip bomb)
    except (zipfile.BadZipFile, OSError):
        return None

    for sub in ZIP_SUBTYPES:
        if all(marker in names for marker in sub["markers"]): #rend le test robuste (ex: un ZIP quelconque contenant par hasard un fichier mimetype ne sera pas pris pour un EPUB, il lui faut aussi META-INF/container.xml.)
            return sub
    return None
         
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
    parser.add_argument("--json", metavar="FICHIER",
                        help="écrire un rapport JSON")
    parser.add_argument("--csv", metavar="FICHIER",
                        help="écrire un rapport CSV")
    parser.add_argument("--no-deep", action="store_true",
                        help="ne pas inspecter l'intérieur des archives ZIP")
    args = parser.parse_args()

    signatures = load_signatures(args.db)
    files = collect_files(args.paths, args.recursive)

    results = []
    counts = {}
    worst = 0
    colors = enable_colors()

    for filepath in files:
        r = scan_file(filepath, signatures, deep=not args.no_deep)
        results.append(r)
        v = r["verdict"]
        counts[v] = counts.get(v, 0) + 1 #incrémente un compteur qui peut ne pas encore exister ; get renvoie 0 par défaut au lieu de lever une KeyError
        worst = max(worst, v.exit_code) #fait remonter la gravité maximale

        if args.quiet and v.exit_code == 0:
            continue
        print(colorize(v, v.label, colors) + " " + r["path"])
        print(f"{'':11}{r['message']}")

    resume = ", ".join(f"{n} {v.name}" for v, n in sorted(counts.items(), key=lambda kv: -kv[0].exit_code)) #Les membres de l'énumération sont triés par gravité décroissante, puis on construit une chaîne de résumé.
    print(f"\n{len(files)} fichier(s) analysé(s) - {resume or 'aucun résultat'}")

    if args.json:
        export_json(args.json, results, counts, args.paths, args.recursive, worst)
        print(f"Rapport JSON : {args.json}")
    if args.csv:
        export_csv(args.csv, results)
        print(f"Rapport CSV  : {args.csv}")

    sys.exit(worst)

if __name__ == "__main__": #pragma: no cover
    main()