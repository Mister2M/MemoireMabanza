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
3. Lancer (root) :
`sudo python3 core.py --enable exec,network --window 5 --out ebpf_features.csv`
