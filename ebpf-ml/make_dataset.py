# ce script extrait les identifiants de session des fichiers de données# et exécute preprocess.py pour chaque session détectée.

import os
import re
import subprocess

DATA_DIR = "data"

pattern = re.compile(r".*_data_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2})\.csv$")
session_ids = set()

# Extraire les session_id
for filename in os.listdir(DATA_DIR):
    match = pattern.match(filename)
    if match:
        session_ids.add(match.group(1))

print("Sessions détectées :", session_ids)

# Lancer preprocess.py pour chaque session
for session in session_ids:
    cmd = [
        "python3", "preprocess.py",
        "--data-dir", DATA_DIR,
        "--session-id", session,
        "--window-size", "1",
    ]

    print(f"Exécution : {' '.join(cmd)}")
    subprocess.run(cmd)
# Note: Assurez-vous que preprocess.py est dans le même répertoire que ce script ou ajustez le chemin en conséquence.