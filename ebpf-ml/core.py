#!/usr/bin/env python3
# core.py - orchestrateur modulaire eBPF -> CSV
# Supporte modules BPF (BPF_PROGRAM + parse_event) et modules classe (ProcessLifecycleModule).
#
# Usage:
#   sudo python3 core.py --modules cpu,exec,network,privilege,process_lifecycle --duration 60

import argparse
import importlib
import os
import time
import csv
import threading
from datetime import datetime
from typing import Optional

from bcc import BPF

DATA_DIR = "data"

def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

def timestamp_str():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

class BPFModuleWrapper:
    """
    Wrapper pour modules BPF 'classiques' :
    - module must provide BPF_PROGRAM (string)
    - PERF_MAP (optional, default 'events')
    - PROVIDED_FIELDS (optional list of strings)
    - parse_event(bpf, data) -> dict (must include optional keys 'pid' and 'comm')
    - attach(bpf) (optional) to attach kprobes/tracepoints after BPF compilation
    """
    def __init__(self, name, module):
        self.name = name
        self.module = module
        self.bpf: Optional[BPF] = None
        self.perf_map = getattr(module, "PERF_MAP", "events")
        self.provided_fields = list(getattr(module, "PROVIDED_FIELDS", []))
        self.filepath = None
        self.csv_file = None
        self.csv_writer = None
        # CORRECTION: FORCER l'utilisation de PROVIDED_FIELDS si défini
        self.feature_fields = list(self.provided_fields) if self.provided_fields else []
        self.header_written = False
        self._first_event_seen = False

    def setup(self):
        # compile BPF
        prog = getattr(self.module, "BPF_PROGRAM", None)
        if not prog:
            print(f"[!] Module {self.name} n'expose pas BPF_PROGRAM. Ignoré.")
            return False
        try:
            self.bpf = BPF(text=prog)
        except Exception as e:
            print(f"[!] Erreur compilation BPF pour module {self.name}: {e}")
            return False

        # call optional attach(bpf)
        attach_fn = getattr(self.module, "attach", None)
        if callable(attach_fn):
            try:
                attach_fn(self.bpf)
            except Exception as e:
                # non fatal: certains modules n'ont pas besoin d'attach, d'autres gèrent tracepoints dans BPF_PROGRAM
                print(f"[i] attach() pour {self.name} a levé : {e} (continuation)")

        # prepare CSV file
        ensure_data_dir()
        fname = f"{self.name}_data_{timestamp_str()}.csv"
        self.filepath = os.path.join(DATA_DIR, fname)
        try:
            self.csv_file = open(self.filepath, "w", newline="")
            self.csv_writer = csv.writer(self.csv_file)
            # initial header: timestamp,pid,comm + provided_fields (if any)
            header = ["timestamp", "pid", "comm"] + self.feature_fields
            self.csv_writer.writerow(header)
            self.csv_file.flush()
            self.header_written = True
            print(f"[+] Module {self.name}: CSV -> {self.filepath}")
        except Exception as e:
            print(f"[!] Erreur création CSV pour {self.name}: {e}")
            return False

        # open perf buffer - CORRECTION ICI (vérification plus permissive)
        map_found = False
        try:
            # Essayer différentes méthodes pour trouver la map
            if self.perf_map in self.bpf:
                map_found = True
            elif hasattr(self.bpf, self.perf_map):
                map_found = True
            else:
                # Dernière tentative: essayer d'accéder directement
                try:
                    _ = self.bpf[self.perf_map]
                    map_found = True
                except:
                    map_found = False
        except Exception as e:
            print(f"[i] Vérification map {self.perf_map} a levé: {e}")

        if not map_found:
            print(f"[!] Perf map '{self.perf_map}' non trouvé dans BPF pour module {self.name}.")
            print(f"[i] Maps disponibles: {list(self.bpf)}")
            # On continue quand même, car parfois la map existe mais n'est pas listée
            print(f"[i] Continuation malgré l'absence de la map...")

        # register callback
        def _cb(cpu, data, size, mod=self.module, wrapper=self):
            try:
                payload = mod.parse_event(wrapper.bpf, data)
                if not isinstance(payload, dict):
                    print(f"[!] parse_event du module {self.name} doit renvoyer dict, obtenu {type(payload)}")
                    return
                
                # CORRECTION: Gestion améliorée des champs
                if not wrapper._first_event_seen:
                    wrapper._first_event_seen = True
                    print(f"[DEBUG] Premier événement {wrapper.name} - clés: {list(payload.keys())}")
                    
                    # Si PROVIDED_FIELDS est défini, on l'utilise directement
                    if not wrapper.feature_fields and wrapper.provided_fields:
                        wrapper.feature_fields = list(wrapper.provided_fields)
                        print(f"[DEBUG] Utilisation PROVIDED_FIELDS: {wrapper.feature_fields}")
                    # Sinon, on infère depuis le payload
                    elif not wrapper.feature_fields:
                        keys = [k for k in payload.keys() if k not in ("pid", "comm", "timestamp", "tid")]
                        wrapper.feature_fields = sorted(keys)
                        print(f"[DEBUG] Inférence des champs: {wrapper.feature_fields}")
                        # Réécrire l'en-tête
                        try:
                            wrapper.csv_file.seek(0)
                            wrapper.csv_file.truncate()
                            wrapper.csv_writer.writerow(["timestamp", "pid", "comm"] + wrapper.feature_fields)
                            wrapper.csv_file.flush()
                            print(f"[DEBUG] En-tête réécrit pour {wrapper.name}")
                        except Exception as e:
                            print(f"[!] Erreur réécriture header CSV pour {wrapper.name}: {e}")

                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                pid = payload.get("pid", "")
                comm = payload.get("comm", "")
                # build feature row with wrapper.feature_fields order
                row_values = [payload.get(k, "") for k in wrapper.feature_fields]
                wrapper.csv_writer.writerow([ts, pid, comm] + row_values)
                wrapper.csv_file.flush()
            except Exception as e:
                print(f"[!] Exception dans callback module {self.name}: {e}")

        try:
            # Essayer d'ouvrir le buffer même si la map n'a pas été trouvée
            self.bpf[self.perf_map].open_perf_buffer(_cb)
            print(f"[+] Buffer perf '{self.perf_map}' ouvert avec succès")
        except Exception as e:
            print(f"[!] Impossible d'ouvrir perf buffer '{self.perf_map}' pour module {self.name}: {e}")
            return False

        return True

    def poll(self, timeout_ms=100):
        if not self.bpf:
            return
        try:
            # poll will dispatch callbacks for the perf buffers opened on this BPF instance
            self.bpf.perf_buffer_poll(timeout=timeout_ms)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            # non-fatal, continue
            print(f"[i] poll() module {self.name} a levé: {e}")

    def cleanup(self):
        try:
            if self.csv_file:
                self.csv_file.close()
                print(f"[✓] CSV fermé pour module {self.name}: {self.filepath}")
        except Exception:
            pass

class ClassModuleRunner:
    """
    Wrapper to run 'class' style modules, e.g. ProcessLifecycleModule that manages its own CSV writing.
    Expects module to define a class named 'ProcessLifecycleModule' or similar; we try to instantiate the first class we find.
    """
    def __init__(self, name, module):
        self.name = name
        self.module = module
        self.instance = None
        self.thread = None

    def setup_and_start(self):
        # find a runnable class (heuristic)
        cls = getattr(self.module, "ProcessLifecycleModule", None)
        if cls is None:
            # try generic 'Module' or other common names
            for attr in dir(self.module):
                obj = getattr(self.module, attr)
                if isinstance(obj, type):
                    # choose first class that isn't builtin
                    if obj.__module__ == self.module.__name__:
                        cls = obj
                        break
        if cls is None:
            print(f"[!] Aucun ProcessLifecycleModule trouvé dans {self.name}. Ignoré.")
            return False
        try:
            # try instantiate without args; if it requires args user must adapt module
            self.instance = cls()
        except Exception as e:
            print(f"[!] Impossible d'instancier la classe du module {self.name}: {e}")
            return False
        # run in a background thread
        def _run():
            try:
                self.instance.start()
            except KeyboardInterrupt:
                pass
            except Exception as e:
                print(f"[!] Exception dans thread module {self.name}: {e}")

        self.thread = threading.Thread(target=_run, daemon=True, name=f"mod-{self.name}")
        self.thread.start()
        print(f"[+] Module classe {self.name} démarré en thread.")
        return True

    def cleanup(self):
        # best-effort cleanup: if instance has cleanup method call it
        try:
            if self.instance and hasattr(self.instance, "cleanup"):
                self.instance.cleanup()
        except Exception:
            pass
        print(f"[✓] Module classe {self.name} arrêté (thread may be daemon).")

def load_module_by_name(name):
    """
    Importe modules.<name>_module et retourne wrapper approprié (BPFModuleWrapper or ClassModuleRunner)
    """
    modpath = f"modules.{name}_module"
    try:
        module = importlib.import_module(modpath)
    except ModuleNotFoundError:
        print(f"[!] Module python '{modpath}' introuvable.")
        return None

    # if module defines BPF_PROGRAM and parse_event -> BPF module
    if hasattr(module, "BPF_PROGRAM") and hasattr(module, "parse_event"):
        return BPFModuleWrapper(name, module)
    # if module provides ProcessLifecycleModule or similar -> class module
    if any(hasattr(module, c) for c in ("ProcessLifecycleModule", "ProcessLifecycle")):
        return ClassModuleRunner(name, module)

    # If module is a hybrid (e.g. provided earlier), handle BPF_PROGRAM even without parse_event (not ideal)
    if hasattr(module, "BPF_PROGRAM"):
        if not hasattr(module, "parse_event"):
            print(f"[!] Module {name} expose BPF_PROGRAM mais pas parse_event; module ignoré.")
            return None

    print(f"[!] Module {name} a une interface non reconnue. Il doit exposer BPF_PROGRAM & parse_event ou être une classe ProcessLifecycleModule.")
    return None

def main():
    parser = argparse.ArgumentParser(description="Collecteur eBPF modulaire (core)")
    parser.add_argument("--modules", required=True, help="virgule-separated module names sans suffixe '_module' (ex: cpu,exec,network,privilege,process_lifecycle)")
    parser.add_argument("--duration", type=int, default=30, help="durée de collecte en secondes")
    args = parser.parse_args()

    names = [n.strip() for n in args.modules.split(",") if n.strip()]
    if not names:
        print("[!] Aucun module spécifié.")
        return

    wrappers = []
    class_runners = []

    print(f"[=] Initialisation modules: {names}")
    for name in names:
        wrapper = load_module_by_name(name)
        if wrapper is None:
            print(f"[!] Skip module {name}")
            continue
        # If wrapper is BPFModuleWrapper: call setup()
        if isinstance(wrapper, BPFModuleWrapper):
            ok = wrapper.setup()
            if ok:
                wrappers.append(wrapper)
            else:
                print(f"[!] Echec setup module {name}; skip.")
        else:
            # ClassModuleRunner: setup_and_start
            ok = wrapper.setup_and_start()
            if ok:
                class_runners.append(wrapper)
            else:
                print(f"[!] Echec démarrage module classe {name}; skip.")

    if not wrappers and not class_runners:
        print("[!] Aucun module actif. Fin.")
        return

    print(f"[=] Démarrage collecte pour {args.duration} secondes.")
    start = time.time()
    try:
        while time.time() - start < args.duration:
            # poll each BPF wrapper (this will dispatch callbacks)
            for w in list(wrappers):
                w.poll(timeout_ms=100)
            # small sleep to avoid busy loop
            time.sleep(0.01)
    except KeyboardInterrupt:
        print("\n[!] Arrêt demandé par l'utilisateur (Ctrl-C)")

    print("[=] Nettoyage modules...")
    for w in wrappers:
        try:
            w.cleanup()
        except Exception:
            pass
    for r in class_runners:
        try:
            r.cleanup()
        except Exception:
            pass

    print("[✓] Collecte terminée.")

if __name__ == "__main__":
    main()
