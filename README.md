# File Identifier — détection de fichiers déguisés

Outil d'analyse qui identifie le type réel d'un fichier à partir de son en-tête binaire et signale les extensions mensongères.

## Le problème

Un attaquant qui veut faire exécuter un binaire à sa victime le renomme rarement `malware.exe`. Il l'appelle `photo_vacances.jpeg`. L'extension n'est qu'une convention de nommage : elle n'a aucune autorité sur le contenu réel du fichier, et rien n'empêche de la falsifier.

Le contenu, lui, ne ment pas. La plupart des formats commencent par une séquence d'octets fixe — le *magic number* — qui identifie le type de manière fiable : `FF D8 FF` pour un JPEG, `4D 5A` pour un exécutable Windows, `25 50 44 46` (`%PDF`) pour un PDF.

Cet outil lit ces octets, en déduit le type réel, et le confronte à l'extension déclarée.

## Utilisation

```powershell
python file_identifier.py <chemin_du_fichier>
```

Exemple :

```
Fichier      : samples\photo_vacances.jpeg
Header       : 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
Type détecté : Windows executable (PE)
[CRITIQUE] L'extension .jpeg masque un exécutable (Windows executable (PE))
```

## Verdicts

| Verdict | Signification | Code de sortie |
|---|---|---|
| `OK` | L'extension correspond au contenu | 0 |
| `INFO` | Fichier sans extension, type réel identifié | 0 |
| `INCONNU` | Aucune signature connue ne correspond | 0 |
| `SUSPECT` | Incohérence extension / contenu | 1 |
| `CRITIQUE` | Un exécutable est masqué sous une autre extension | 2 |

Les codes de sortie suivent la convention Unix, ce qui permet d'enchaîner l'outil dans un script.

## Limites connues

**Les formats texte n'ont pas de magic number.** Un `.txt`, `.csv`, `.json`, `.py` ou `.log` commence par des octets arbitraires — ceux de son propre contenu. Aucune signature fixe n'existe, donc aucune détection par header n'est possible. Ces fichiers ressortent en `INCONNU`.

C'est un choix délibéré, pas un oubli : **l'absence de preuve n'est pas une preuve de mensonge.** Classer en `SUSPECT` tout ce que l'outil ne sait pas identifier reviendrait à noyer l'analyste sous les faux positifs — le mode de défaillance le plus courant des outils de détection n'est pas de rater une menace, c'est de crier si souvent que plus personne n'écoute.

À noter que le cas dangereux reste couvert : un fichier `.txt` dont le header est `4D 5A` sort bien en `CRITIQUE`. C'est le fichier *inidentifiable* qui échappe à la méthode, pas le fichier *malveillant*.

**Autres limites :**

- **Conteneurs ZIP** — `.docx`, `.xlsx`, `.pptx`, `.apk` et `.jar` partagent la signature `50 4B 03 04`. L'outil les identifie tous comme « ZIP archive » ; les distinguer suppose d'ouvrir l'archive et d'en lire le contenu.
- **Magic numbers à offset non nul** — certains formats (ISO, TAR, MP4) placent leur signature après les premiers octets. La base actuelle ne gère que l'offset 0.
- **Polyglottes** — un fichier peut être valide dans deux formats à la fois (un JPEG qui est aussi une archive ZIP). L'outil ne retiendra que la première correspondance.

## Piste d'amélioration

Une analyse heuristique du contenu (proportion d'octets imprimables, entropie de Shannon) permettrait de rattraper une partie des fichiers `INCONNU` : identifier un fichier comme « probablement du texte », et surtout repérer un `.txt` à haute entropie, signe de données chiffrées ou compressées déguisées.

## Tests

Créer les fichiers d'échantillon :

```powershell
# Un exécutable Windows (copie inoffensive)
Copy-Item C:\Windows\System32\notepad.exe samples\notepad.exe

# Le scénario de l'énoncé : un exécutable déguisé en image
Copy-Item samples\notepad.exe samples\photo_vacances.jpeg

# Un mismatch bénin : un PDF déguisé en archive
Copy-Item samples\un_pdf.pdf samples\archive.zip

# Un fichier sans extension
Copy-Item samples\un_pdf.pdf samples\rapport

# Un fichier vide (cas limite)
New-Item samples\vide.docx -ItemType File -Force

# Un fichier texte (aucune signature possible -> INCONNU attendu)
"hello world" | Out-File samples\note.txt
```

Lancer les tests :

```powershell
python file_identifier.py samples\photo_vacances.jpeg  # attendu : CRITIQUE (2)
python file_identifier.py samples\archive.zip          # attendu : SUSPECT  (1)
python file_identifier.py samples\rapport              # attendu : INFO     (0)
python file_identifier.py samples\une_image.JPEG       # attendu : OK       (0)
python file_identifier.py samples\un_document.docx     # attendu : OK       (0)
python file_identifier.py samples\note.txt             # attendu : INCONNU  (0)
python file_identifier.py samples\vide.docx            # attendu : INCONNU  (0)
```

Le code de sortie se consulte avec `$LASTEXITCODE` sous PowerShell, `echo $?` sous Linux.
