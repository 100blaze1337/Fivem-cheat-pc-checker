import os
import sys
import subprocess
import ctypes
import time
from pathlib import Path
from colorama import Fore, init

# COLORAMA
try:
    import colorama
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "colorama"])
init(autoreset=True)

# ADMIN
def is_running_as_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin_and_exit():
    try:
        python_exe = sys.executable
        try:
            script = os.path.abspath(__file__)
        except NameError:
            print(Fore.RED + "[!] Impossible de trouver le chemin du script pour relancer.")
            return False
        # PARAMETRES
        args = [f'"{script}"'] + [f'"{a}"' for a in sys.argv[1:]]
        params = " ".join(args)
        # ShellExecuteW
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", python_exe, params, None, 1)
        return int(ret) > 32
    except Exception as e:
        print(Fore.RED + f"[!] Erreur lors du relancement en admin : {e}")
        return False

# ASCII
ASCII = r"""
                   ______  ___   _____   _____________  __   ________  ________________ __ __________ 
                  / __ \ \/ / | / /   | / ___/_  __/\ \/ /  / ____/ / / / ____/ ____/ //_// ____/ __ \
                 / / / /\  /  |/ / /| | \__ \ / /    \  /  / /   / /_/ / __/ / /   / ,<  / __/ / /_/ /
                / /_/ / / / /|  / ___ |___/ // /     / /  / /___/ __  / /___/ /___/ /| |/ /___/ _, _/ 
               /_____/ /_/_/ |_/_/  |_/____//_/     /_/   \____/_/ /_/_____/\____/_/ |_/_____/_/ |_|  
"""

# LISTE
SUSPECT_NAMES = [
    "loader_prod.exe", "loader.cfg", "updated.exe", "settings.cock", "password_is_eulen",
    "Susano", "visualstudio.exe", "eclipse.exe", "excel.exe", "filezilla.exe", "explorer.exe", "firefox.exe",
    "wordpad.exe", "acrobat.exe", "winword.exe", "teams.exe", "notepad.exe", "paint.exe",
    "premiere.exe", "putty.exe", "dwm.exe", "iexplore.exe", "outlook.exe", "photoshop.exe", "gimp.exe", "skype.exe",
    "obs.exe", "thunderbird.exe", "microsoftpowerpoint.exe", "notepad++.exe", "microsoftedge.exe",
    "loader.exe", "updated.exe","firefox_beta.exe","move.exe","yarn.exe","chrome.exe","cry.dat","fixer.bat","epicgameslauncher.exe"
    "keyser","phaze","microsoftoutlook.exe","settings.cock","loader_3.4.4.exe","imgui.ini"
]

SUSPECT_LOWER = [s.lower() for s in SUSPECT_NAMES]
SUSPECT_BASES = []
for s in SUSPECT_LOWER:
    if '.' in s:
        SUSPECT_BASES.append(s.rsplit('.', 1)[0])
    else:
        SUSPECT_BASES.append(s)

# EXT
ALLOWED_EXTS = {'.exe', '.dll', '.bat', '.py', '.json', '.ini', '.cfg', '.pf'}

# FICHIERS
from string import ascii_uppercase

def list_all_drives():
    drives = []
    for letter in ascii_uppercase:
        drive_path = Path(f"{letter}:/")
        if drive_path.exists():
            drives.append(drive_path)
    return drives

# FONCTION SCAN ALL DOSSIERS
FOLDERS_TO_SCAN = list_all_drives()


# FICHIERS A SCAN V2
USER = Path.home()
SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))

FOLDERS_TO_SCAN = []
PREFETCH = SYSTEM_ROOT / "Prefetch"
if PREFETCH.exists():
    FOLDERS_TO_SCAN.append(PREFETCH)
# AppData
FOLDERS_TO_SCAN.append(USER / "AppData")
FOLDERS_TO_SCAN.append(USER / "Desktop")
FOLDERS_TO_SCAN.append(USER / "Downloads")
FOLDERS_TO_SCAN.append(USER / "Documents")
FOLDERS_TO_SCAN.append(USER / "Pictures")
FOLDERS_TO_SCAN.append(USER / "Videos")

# FICHIERS A NE PAS SCAN
EXCLUDE_PATHS = set()
pf = Path("C:/Program Files")
pf86 = Path("C:/Program Files (x86)")
if pf.exists():
    EXCLUDE_PATHS.add(pf.resolve())
if pf86.exists():
    EXCLUDE_PATHS.add(pf86.resolve())

# HELPER
def path_is_excluded(path: Path) -> bool:
    try:
        rp = path.resolve()
    except Exception:
        rp = path
    for ex in EXCLUDE_PATHS:
        try:
            if str(rp).lower().startswith(str(ex).lower()):
                return True
        except Exception:
            continue
    return False

def match_filename(name: str) -> str:
    nl = name.lower()
    for pat in SUSPECT_LOWER:
        if pat in nl:
            return pat
    # .pf PREFETCH
    for base in SUSPECT_BASES:
        if base and base in nl:
            return base
    return None

def report_found(item: Path, matched: str):
    global_found[0] += 1
    print(Fore.GREEN + f"[+] {item.name} (motif trouvé: '{matched}') trouvé dans : " + Fore.MAGENTA + str(item.parent) + Fore.WHITE + " | " + Fore.RED + item.name)

# LOGIQUE DU SCAN
def scan_folder_root_and_depth1(folder: Path):
    try:
        if not folder.exists():
            return
        if path_is_excluded(folder):
            return

        # ROOT
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    try:
                        if not entry.is_file():
                            continue
                        name = entry.name
                        ext = Path(name).suffix.lower()
                        if ext not in ALLOWED_EXTS:
                            continue
                        matched = match_filename(name)
                        if matched:
                            report_found(Path(entry.path), matched)
                    except PermissionError:
                        continue
                    except Exception:
                        continue
        except PermissionError:
            pass
        except Exception:
            pass

        # SOUS DOSSIERS
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    try:
                        if not entry.is_dir():
                            continue
                        sub = Path(entry.path)
                        if path_is_excluded(sub):
                            continue
                        # LISTE TOUT LES FICHIERS
                        try:
                            with os.scandir(sub) as it2:
                                for e2 in it2:
                                    try:
                                        if not e2.is_file():
                                            continue
                                        name2 = e2.name
                                        ext2 = Path(name2).suffix.lower()
                                        if ext2 not in ALLOWED_EXTS:
                                            continue
                                        matched2 = match_filename(name2)
                                        if matched2:
                                            report_found(Path(e2.path), matched2)
                                    except PermissionError:
                                        continue
                                    except Exception:
                                        continue
                        except PermissionError:
                            continue
                        except Exception:
                            continue
                    except PermissionError:
                        continue
                    except Exception:
                        continue
        except Exception:
            pass
    except Exception:
        pass

# admin fonction
if not is_running_as_admin():
    # Windows Message
    print(Fore.MAGENTA + "PC CHECKER - élévation requise (UAC va s'ouvrir).")
    print(Fore.MAGENTA + "Une nouvelle fenêtre s'ouvrira pour exécuter le scan en mode administrateur.")
    ok = relaunch_as_admin_and_exit()
    if ok:
        print(Fore.CYAN + "Demande d'élévation lancée. La fenêtre actuelle va se fermer.")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Impossible de relancer en admin. Fermez et relancez manuellement en tant qu'administrateur.")
        sys.exit(1)

# MESSAGE ACCEUIL
print(Fore.MAGENTA + ASCII)
print(Fore.MAGENTA + "                                           PC CHECKER - 100blaze")
print(Fore.MAGENTA + "                                      https://discord.gg/dynastyrp\n")
print(Fore.MAGENTA + "Le scan automatique ne démarrera qu'après appui sur ENTRÉE...\n")
try:
    input(Fore.MAGENTA + "[-] Appuyez sur " + Fore.WHITE + "ENTRÉE" + Fore.MAGENTA + " pour lancer le scan automatique")
except Exception:
    pass

# SCAN FONCTION
global_found = [0]

print(Fore.MAGENTA + "\n[-] Démarrage du scan (name-only, depth=1)...\n")
for fld in FOLDERS_TO_SCAN:
    try:
        print(Fore.MAGENTA + f"[~] Scan du disque/chemin : {fld}")
        scan_folder_root_and_depth1(Path(fld))
    except Exception:
        continue

time.sleep(0.2)
if global_found[0] == 0:
    print(Fore.GREEN + f"\n[-] Scan terminé, {global_found[0]} résultat(s) trouvé(s).")
else:
    print(Fore.RED + f"\n[-] Scan terminé, {global_found[0]} résultat(s) trouvé(s).")

try:
    input(Fore.MAGENTA + "\n[-] Appuyez sur " + Fore.WHITE + "ENTRÉE" + Fore.MAGENTA + " pour fermer le programme")
except Exception:
    pass
