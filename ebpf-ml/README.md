# ebpf-ml

Prototype modulaire de collecte eBPF/BCC pour générer des CSV de télémétrie système, puis construire un dataset exploitable pour l'entraînement de modèles ML.

## Ce que fait le projet

- active un sous-ensemble de modules eBPF via la CLI
- collecte les événements système pendant une durée donnée
- exporte un CSV par module dans `data/`
- agrège ensuite ces CSV en features temporelles pour l'analyse et l'entraînement

## Modules disponibles

- `cpu` : temps CPU observé via `sched:sched_switch`
- `exec` : exécutions de binaires via les tracepoints `execve` et `execveat`
- `network` : activité réseau via `sendto`, `recvfrom`, `connect`
- `privilege` : événements liés aux privilèges (`setuid`, `chmod`, `capset`, etc.)
- `process_lifecycle` : création et fin de processus

## Prérequis

- Linux avec support eBPF
- `sudo`
- Python 3
- BCC installé côté système

## Installation

Sous Debian/Ubuntu, la commande à utiliser est :

```bash
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```


Installez ensuite les dépendances Python du projet :

```bash
pip3 install -r requirements.txt
```


## Vérification de l'installation BCC

Vérifier que la binding Python correcte est bien disponible :

```bash
python3 -c "from bcc import BPF; print('BCC Python binding OK')"
```

Si cette commande échoue alors qu'un paquet `bcc` est présent dans un environnement Conda ou virtuel, désactivez cet environnement et utilisez le Python système qui voit `python3-bpfcc`.

Version BCC déjà testée dans ce projet :

```text
0.29.1
```

## Lancement de la collecte

Exemple complet :

```bash
sudo python3 core.py --modules cpu,exec,network,privilege,process_lifecycle --duration 30
```

Paramètres :

- `--modules` : liste de modules séparés par des virgules
- `--duration` : durée de collecte en secondes

Exemple minimal :

```bash
sudo python3 core.py --modules cpu,exec --duration 10
```

Les fichiers CSV sont générés automatiquement dans le dossier `data/`.

## Construction du dataset

Pour agréger les CSV d'une session donnée :

```bash
python3 preprocess.py --data-dir data --session-id 2026-03-28_10-15-30 --window-size 1
```

Pour traiter les sessions détectées dans `data/` :

```bash
python3 make_dataset.py
```

Le dataset final est écrit sous la forme :

```text
data/dataset_autoencoder_<session_id>.csv
```

## Structure du dépôt

```text
.
├── core.py
├── preprocess.py
├── make_dataset.py
├── modules/
├── examples/
└── data/
```

## Remarques utiles

- les modules eBPF nécessitent généralement des privilèges élevés, d'où l'usage de `sudo`
- la compilation BPF dépend du noyau et de ses en-têtes ; si besoin, vérifiez `linux-headers-$(uname -r)`
- en cas d'erreur d'import `bcc`, vérifiez d'abord qu'un paquet pip ou Conda ne masque pas `python3-bpfcc`

