import sys

def read_header(filepath, num_bytes=16):
    """Lit les premiers octets d'un fichier en mode binaire."""
    with open(filepath, "rb") as f: #rb read binary
        return f.read(num_bytes) #f.read(16)=retourne un objet bytes pas string
    
if __name__ == "__main__":
    path = sys.argv[1]
    header = read_header(path)
    # .hex(" ") affiche les octets séparés par des espaces.
    print(f"Header de {path}: {header.hex(' ').upper()}") #.hex converti en hexa
    
