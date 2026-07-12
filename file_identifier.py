import sys
import json

def load_signatures(db_path="signatures.json"):
    """Charge la base de signatures et convertit les magic en bytes."""
    with open(db_path, "r") as f:
        data= json.load(f)  #dictionary of one key: "signatures" and a list of values
    for sig in data["signatures"]: #item from the collection "sigs"
        sig["magic_bytes"] = bytes.fromhex(sig["magic"]) #conversion of bytes from hex
    return data["signatures"]

def read_header(filepath, num_bytes=16):
    """Lit les premiers octets d'un fichier en mode binaire."""
    with open(filepath, "rb") as f: #rb read binary
        return f.read(num_bytes) #f.read(16)=retourne un objet bytes pas string
    
if __name__ == "__main__":
    sigs= load_signatures() #complete list of dictionaries
    print(f"{len(sigs)} signatures chargées")
    for s in sigs:
        print(f" {s['type']}: {s['magic_bytes'].hex(' ').upper()}")
    path = sys.argv[1]
    header = read_header(path)
    # .hex(" ") affiche les octets séparés par des espaces.
    print(f"Header de {path}: {header.hex(' ').upper()}") #.hex converti en hexa

