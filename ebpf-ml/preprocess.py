#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
preprocess.py
--------------
Ce module agrège les données brutes eBPF par fenêtres temporelles,
en transformant les événements en vecteurs de features numériques
prêts pour l'entraînement d'un autoencodeur.

REVISÉ: Ajout de features de diversité réseau (IP/Port).
"""

import os
import pandas as pd
import numpy as np
import glob
import re
from datetime import timedelta

# === Configuration ===
DATA_DIR = "data"  # Dossier contenant les CSV (aligné sur core.py)
OUTPUT_FILE = os.path.join(DATA_DIR, "dataset_autoencoder_features.csv")
# Taille de la fenêtre d’agrégation (ex: 10 secondes)
# Utilisation du format pandas Timedelta
WINDOW_SIZE = '10s'  
# Colonnes qui sont des identifiants (ID) ou des catégories brutes.
# Les colonnes numériques qui NE DOIVENT PAS être agrégées (somme/moyenne) y vont.
# Note : mode, daddr, dport sont laissés hors d'ID_COLS pour être agrégés numériquement
ID_COLS = ['pid', 'ppid', 'uid', 'target_uid', 'filename', 'comm', 'event_type', 'module']


def read_all_csv():
    """Lit tous les CSV, ajoute le nom du module et concatène en un seul DataFrame."""
    all_dfs = []
    
    base_dir = DATA_DIR if os.path.isabs(DATA_DIR) else os.path.join(os.getcwd(), DATA_DIR)
    csv_files = glob.glob(os.path.join(base_dir, "*.csv"))
    
    if not csv_files:
        print(f"[-] Aucun fichier CSV trouvé dans {base_dir}.")
        return None

    print(f"[+] Lecture et fusion de {len(csv_files)} fichiers CSV...")

    for f in csv_files:
        try:
            match = re.search(r'(\w+)_data', os.path.basename(f))
            module_name = match.group(1) if match else "unknown"

            df = pd.read_csv(f, dtype={'daddr': 'Int64', 'dport': 'Int64'}) # Gérer les types Int pour daddr/dport
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
            df = df.dropna(subset=["timestamp"])

            # Renommer les colonnes numériques pour éviter les conflits lors de la fusion
            for col in df.columns:
                # La vérification est plus robuste: on vérifie que la colonne n'est pas un ID et est numérique
                if col not in ['timestamp'] + ID_COLS and df[col].dtype in ['int64', 'float64', 'Int64']:
                    df.rename(columns={col: f"{module_name}_{col}"}, inplace=True)
            
            df['module'] = module_name
            all_dfs.append(df)
            
        except Exception as e:
            print(f"[Erreur lecture {os.path.basename(f)}]: {e}")
            
    if not all_dfs:
        return None
    
    merged_df = pd.concat(all_dfs, ignore_index=True)
    merged_df.sort_values(by="timestamp", inplace=True)
    merged_df.set_index("timestamp", inplace=True)
    print(f"[+] Fusion de {len(merged_df)} événements réussie.")
    return merged_df

def create_numeric_features(df_full: pd.DataFrame, window_size: str) -> pd.DataFrame:
    """Crée des features numériques (somme, moyenne, écart-type) pour les métriques."""
    print("[.] Création des features numériques (somme/moyenne)...")
    
    # Filtrer les colonnes qui sont numériques et ne sont pas des IDs
    numeric_cols = [col for col in df_full.columns 
                    if df_full[col].dtype in ['int64', 'float64', 'Int64'] and col not in ID_COLS]
    
    # Définir les agrégations: la somme est critique pour le temps CPU et les octets
    agg_funcs = {col: ['sum', 'mean', 'std'] for col in numeric_cols}
    
    agg_numeric = df_full.groupby(pd.Grouper(freq=window_size)).agg(agg_funcs)
    agg_numeric.columns = ['_'.join(col).strip() for col in agg_numeric.columns.values]
    agg_numeric.fillna(0, inplace=True)
    
    # Nettoyage des noms de colonnes pour la somme
    agg_numeric.rename(columns=lambda x: x.replace('_sum', '_TOTAL'), inplace=True)
    
    return agg_numeric

def create_categorical_features(df_full: pd.DataFrame, window_size: str) -> pd.DataFrame:
    """Crée des features basées sur le comptage (fréquence) des événements catégoriels."""
    print("[.] Création des features de comptage et catégorielles...")

    # 1. Total des événements dans la fenêtre
    event_counts = df_full.groupby(pd.Grouper(freq=window_size))['module'].count().rename('TOTAL_EVENT_COUNT')

    # 2. Comptage des types d'événements critiques (Event Type)
    df_temp = df_full.copy()
    df_temp['event_type'] = df_temp['event_type'].fillna('NA').astype(str)

    # OHE sur l'event_type et agrégation par somme (COMPTE)
    ohe_events = pd.get_dummies(df_temp, columns=['event_type'], prefix='type')
    ohe_agg = ohe_events.filter(regex='^type_').groupby(pd.Grouper(freq=window_size)).sum()
    ohe_agg.fillna(0, inplace=True)
    ohe_agg.columns = [col.replace('type_event_type_', 'COUNT_') for col in ohe_agg.columns]

    # 3. Comptage des PIDs et Binarisation (diversité)
    unique_pid_count = df_full.groupby(pd.Grouper(freq=window_size))['pid'].nunique().rename('COUNT_UNIQUE_PIDS').fillna(0)
    
    # 4. Comptage des fichiers exécutés par le 'exec_module' (Hashing Trick)
    exec_files = df_full[df_full['module'] == 'exec'].copy()
    bin_agg = pd.DataFrame(index=event_counts.index) # DataFrame de base

    if 'filename' in exec_files.columns:
        exec_files['filename'] = exec_files['filename'].astype(str).fillna('')
        exec_files['filename_hash'] = exec_files['filename'].apply(lambda x: hash(x) % 100) # 100 buckets
        
        ohe_filenames = pd.get_dummies(exec_files, columns=['filename_hash'], prefix='BIN_HASH')
        bin_agg = ohe_filenames.filter(regex='^BIN_HASH_').groupby(pd.Grouper(freq=window_size)).sum()
        bin_agg = bin_agg.reindex(event_counts.index, fill_value=0) # Aligner l'index
    
    # 5. NOUVEAU: Comptage des destinations uniques par le 'network_module'
    network_events = df_full[df_full['module'] == 'network'].copy()
    if not network_events.empty:
        # Note : Daddr et Dport sont des IDs binaires, le comptage d'uniques est pertinent.
        unique_dst_ip_count = network_events.groupby(pd.Grouper(freq=window_size))['network_daddr'].nunique().rename('COUNT_UNIQUE_DST_IP').fillna(0)
        unique_dst_port_count = network_events.groupby(pd.Grouper(freq=window_size))['network_dport'].nunique().rename('COUNT_UNIQUE_DST_PORT').fillna(0)
    else:
        # S'assurer que les colonnes existent même si le module n'a rien généré
        idx = event_counts.index
        unique_dst_ip_count = pd.Series(0, index=idx, name='COUNT_UNIQUE_DST_IP')
        unique_dst_port_count = pd.Series(0, index=idx, name='COUNT_UNIQUE_DST_PORT')
        
    
    # Fusion des features catégorielles
    final_categorical = pd.concat([
        event_counts, 
        unique_pid_count, 
        ohe_agg, 
        bin_agg,
        unique_dst_ip_count, 
        unique_dst_port_count
    ], axis=1).fillna(0)
    
    # Nettoyage des colonnes dupliquées (si un index temporel vide s'était glissé)
    final_categorical = final_categorical.loc[:, ~final_categorical.columns.duplicated()]

    return final_categorical

def main():
    merged_df = read_all_csv()
    
    if merged_df is None or merged_df.empty:
        print("[!] Aucune donnée à traiter. Quitte.")
        return

    # --- Étape 1: Création des Features Numériques ---
    numeric_features_df = create_numeric_features(merged_df, WINDOW_SIZE)
    
    # --- Étape 2: Création des Features Catégorielles (Comptage/Diversité) ---
    categorical_features_df = create_categorical_features(merged_df, WINDOW_SIZE)

    # --- Étape 3: Fusion Finale ---
    final_features_df = pd.merge(
        numeric_features_df, 
        categorical_features_df, 
        left_index=True, 
        right_index=True, 
        how='outer'
    ).fillna(0)
    
    # --- Étape 4: Nettoyage Final et Sauvegarde ---
    if final_features_df.empty:
        print("[!] Aucune fenêtre d'agrégation n'a été produite. Quitte.")
        return

    os.makedirs(DATA_DIR, exist_ok=True)
    final_features_df.to_csv(OUTPUT_FILE)
    
    print("\n" + "="*50)
    print(f"[✓] Dataset agrégé sauvegardé dans : {OUTPUT_FILE}")
    print(f"[i] Durée de la fenêtre (WINDOW_SIZE) : {WINDOW_SIZE}")
    print(f"[i] Nombre total de fenêtres (échantillons) : {len(final_features_df)}")
    print(f"[i] Nombre total de features générées : {final_features_df.shape[1]}")
    print(f"Les features sont maintenant prêtes pour l'Autoencodeur.")
    print("="*50)


if __name__ == "__main__":
    # Nécessite pandas et numpy : pip install pandas numpy
    main()
