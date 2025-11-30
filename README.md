### La version de BCC sur laquelle le programme a déjà été testé
BCC version: 0.29.1

### Pour verifier la version de BCC installée sur votre OS
python3 -c "import bcc; print(f'BCC version: {bcc.__version__}')"

### Pour exécuter tous les modules(i.e cpu, exec, network,privilege, process_lifecycle) pendant une durée de 30 secondes
sudo python3 core.py --modules cpu,exec,network,privilege,process_lifecycle --duration 30
