## Tests

Créer les fichiers d'échantillon :

```powershell
# Un exécutable Windows (copie inoffensive)
Copy-Item C:\Windows\System32\notepad.exe samples\notepad.exe

# Un fichier vide (cas limite)
New-Item samples\vide.docx -ItemType File -Force

# Un fichier texte (type absent de la base -> "inconnu" attendu)
"hello world" | Out-File samples\note.txt
```

Lancer les tests :

```powershell
python file_identifier.py samples\une_image.JPEG   # attendu : JPEG image
python file_identifier.py samples\document.docx    # attendu : ZIP archive
python file_identifier.py samples\notepad.exe      # attendu : Windows executable (PE)
python file_identifier.py samples\vide.docx        # attendu : (fichier vide) / inconnu
python file_identifier.py samples\note.txt         # attendu : inconnu
```