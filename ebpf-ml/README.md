# ebpf-ml (squelette)

Prototype modulaire pour collecte eBPF et export de features destinées à l'entraînement ML.


## Objectifs
- Modularité : activer/désactiver modules via CLI.
- Agrégation par fenêtre (configurable).
- Export CSV prêt pour entraînement.


## Dépendances
- python3, sudo
- bcc (python3-bcc)
- pip packages listés dans requirements.txt


## Quickstart
1. Installer dépendances : `sudo apt install bpfcc-tools python3-bcc`
2. Installer pip : `pip3 install -r requirements.txt`
3. Lancer  : sudo python3 core.py --modules (noms des modules separés par des virgules) --duration (durée en secondes)
   Exemple : sudo python3 core.py --modules cpu,exec,network,privilege,process_lifecycle --duration 30


## La version de BCC sur laquelle le programme a déjà été testé est 
BCC version: 0.29.1

## Pour verifier la version de BCC installée sur votre OS en utilisant 

python3 -c "import bcc; print(f'BCC version: {bcc.version}')"


