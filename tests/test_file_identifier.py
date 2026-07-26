import zipfile

import pytest
import csv
import json
import sys

from file_identifier import (
    Verdict,
    load_signatures,
    identify,
    check_mismatch,
    inspect_zip,
    scan_file,
    to_export,
    RESET,
    colorize,
    collect_files,
    export_json,
    export_csv,
    main,
)


@pytest.fixture #Permet de définir une fixture pour les tests, qui sera exécutée une fois par test qui la demande.
def signatures():
    """Base de signatures chargée une fois par test qui la demande."""
    return load_signatures()

@pytest.mark.parametrize("header, attendu", [ #Génère 6 tests paramétrés, chacun avec un header et le type attendu. (4 octets suffisent. Seul le header compte, donc pas besoin de vraies images.)
    (b"\xFF\xD8\xFF\xE0",         "JPEG image"),
    (b"\x89PNG\r\n\x1a\n",        "PNG image"),
    (b"MZ\x90\x00",               "Windows executable (PE)"),
    (b"\x7fELF\x02\x01\x01",      "Linux executable (ELF)"),
    (b"%PDF-1.4",                 "PDF document"),
    (b"PK\x03\x04",               "ZIP archive"),
])
def test_identify_formats_connus(header, attendu, signatures):
    assert identify(header, signatures)["type"] == attendu


def test_identify_fichier_vide(signatures):
    assert identify(b"", signatures) is None


def test_identify_format_inconnu(signatures):
    assert identify(b"hello world", signatures) is None

def _sig(type_, extensions):
    """Fabrique une signature minimale pour les tests."""
    return {"type": type_, "extensions": extensions}


def test_extension_coherente():
    verdict, _ = check_mismatch("photo.jpg", _sig("JPEG image", [".jpg", ".jpeg"]))
    assert verdict is Verdict.OK


def test_extension_en_majuscules():
    verdict, _ = check_mismatch("PHOTO.JPEG", _sig("JPEG image", [".jpg", ".jpeg"]))
    assert verdict is Verdict.OK


def test_executable_deguise_est_critique():
    verdict, _ = check_mismatch("photo.jpeg", _sig("Windows executable (PE)", [".exe"]))
    assert verdict is Verdict.CRITICAL


def test_mismatch_benin():
    verdict, _ = check_mismatch("archive.zip", _sig("PDF document", [".pdf"]))
    assert verdict is Verdict.MISMATCH


def test_fichier_sans_extension():
    verdict, _ = check_mismatch("rapport", _sig("PDF document", [".pdf"]))
    assert verdict is Verdict.NO_EXT


def test_type_non_identifie():
    verdict, _ = check_mismatch("note.txt", None)
    assert verdict is Verdict.UNKNOWN

def _make_zip(path, noms):
    """Crée une archive ZIP contenant les fichiers nommés."""
    with zipfile.ZipFile(path, "w") as z:
        for n in noms:
            z.writestr(n, "contenu")
    return str(path)


def test_inspect_zip_reconnait_docx(tmp_path):
    f = _make_zip(tmp_path / "a.zip", ["[Content_Types].xml", "word/document.xml"])
    assert inspect_zip(f)["type"] == "Word document (OOXML)"


def test_inspect_zip_apk_prioritaire_sur_jar(tmp_path):
    f = _make_zip(tmp_path / "a.zip",
                  ["AndroidManifest.xml", "classes.dex", "META-INF/MANIFEST.MF"])
    assert inspect_zip(f)["type"] == "Android package (APK)"


def test_inspect_zip_ordinaire(tmp_path):
    f = _make_zip(tmp_path / "a.zip", ["notes.txt", "photo.png"])
    assert inspect_zip(f) is None


def test_inspect_zip_archive_corrompue(tmp_path):
    f = tmp_path / "casse.zip"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 50)   #header valide, contenu invalide
    assert inspect_zip(str(f)) is None

def test_scan_executable_deguise_en_image(tmp_path, signatures):
    f = tmp_path / "photo_vacances.jpeg"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
    r = scan_file(str(f), signatures)
    assert r["verdict"] is Verdict.CRITICAL
    assert r["type"] == "Windows executable (PE)"


def test_scan_docx_legitime(tmp_path, signatures):
    f = _make_zip(tmp_path / "rapport.docx", ["word/document.xml"])
    assert scan_file(f, signatures)["verdict"] is Verdict.OK


def test_option_no_deep(tmp_path, signatures):
    f = _make_zip(tmp_path / "rapport.docx", ["word/document.xml"])
    assert scan_file(f, signatures, deep=True)["verdict"] is Verdict.OK
    assert scan_file(f, signatures, deep=False)["verdict"] is Verdict.MISMATCH


def test_scan_fichier_vide(tmp_path, signatures):
    f = tmp_path / "vide.docx"
    f.write_bytes(b"")
    assert scan_file(str(f), signatures)["verdict"] is Verdict.UNKNOWN


def test_scan_header_tronque(tmp_path, signatures):
    f = tmp_path / "court.png"
    f.write_bytes(b"\x89PNG")   # 4 octets, la signature PNG en fait 8
    assert scan_file(str(f), signatures)["verdict"] is Verdict.UNKNOWN

def test_to_export_convertit_le_verdict():
    original = {"path": "x", "verdict": Verdict.CRITICAL}
    exporte = to_export(original)
    assert exporte["verdict"] == "CRITICAL"
    assert original["verdict"] is Verdict.CRITICAL   # l'original n'est pas modifié

def test_scan_dossier_produit_une_erreur(tmp_path, signatures):
    """Ouvrir un dossier en lecture binaire doit être capté, pas propagé."""
    assert scan_file(str(tmp_path), signatures)["verdict"] is Verdict.ERREUR


def test_collect_files_non_recursif(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    sous = tmp_path / "sous"
    sous.mkdir()
    (sous / "b.txt").write_text("x")
    assert len(collect_files([str(tmp_path)])) == 1


def test_collect_files_recursif(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    sous = tmp_path / "sous"
    sous.mkdir()
    (sous / "b.txt").write_text("x")
    assert len(collect_files([str(tmp_path)], recursive=True)) == 2


def test_collect_files_chemin_inexistant(tmp_path):
    assert collect_files([str(tmp_path / "fantome")]) == []


def test_colorize_inactif():
    assert colorize(Verdict.CRITICAL, "texte", False) == "texte"


def test_colorize_actif():
    sortie = colorize(Verdict.CRITICAL, "texte", True)
    assert sortie.startswith(Verdict.CRITICAL.color)
    assert sortie.endswith(RESET)


def test_export_json_relu(tmp_path, signatures):
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4" + b"\x00" * 300)
    resultats = [scan_file(str(f), signatures)]
    sortie = tmp_path / "rapport.json"

    export_json(str(sortie), resultats, {Verdict.OK: 1}, [str(f)], False, 0)

    data = json.loads(sortie.read_text(encoding="utf-8"))
    assert data["summary"] == {"OK": 1}
    assert data["results"][0]["verdict"] == "OK"
    assert data["exit_code"] == 0


def test_export_csv_relu(tmp_path, signatures):
    f = tmp_path / "doc.pdf"
    f.write_bytes(b"%PDF-1.4" + b"\x00" * 300)
    sortie = tmp_path / "rapport.csv"

    export_csv(str(sortie), [scan_file(str(f), signatures)])

    lignes = sortie.read_text(encoding="utf-8-sig").splitlines()
    lues = list(csv.DictReader(lignes))
    assert len(lues) == 1
    assert lues[0]["verdict"] == "OK"


@pytest.mark.parametrize("contenu, code_attendu", [
    (b"%PDF-1.4" + b"\x00" * 300, 0),   # PDF nomme .pdf
    (b"PK\x03\x04" + b"\x00" * 300, 1), # ZIP nomme .pdf
    (b"MZ\x90\x00" + b"\x00" * 300, 2), # PE nomme .pdf
])
def test_main_codes_de_sortie(tmp_path, monkeypatch, contenu, code_attendu):
    f = tmp_path / "fichier.pdf"
    f.write_bytes(contenu)
    monkeypatch.setattr(sys, "argv", ["file_identifier.py", str(f)])

    with pytest.raises(SystemExit) as sortie:
        main()

    assert sortie.value.code == code_attendu