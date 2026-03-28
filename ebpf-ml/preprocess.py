import argparse
import glob
import os
from pathlib import Path
from typing import Optional, List, Dict

import numpy as np
import pandas as pd


# ==========================
#   Utils génériques
# ==========================

def parse_timestamp(df: pd.DataFrame, ts_col: str = "timestamp") -> pd.DataFrame:
    """Convertit la colonne timestamp en datetime et la normalise."""
    df = df.copy()
    df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")
    df = df.dropna(subset=[ts_col])
    return df


def add_window_column(
    df: pd.DataFrame,
    ts_col: str = "timestamp",
    window_size_s: int = 1
) -> pd.DataFrame:
    """
    Ajoute une colonne 'window_start' correspondant
    au début de la fenêtre temporelle (floor par seconde ou multiple).
    """
    df = df.copy()
    # ex: "1S", "2S", ...
    freq = f"{window_size_s}S"
    df["window_start"] = df[ts_col].dt.floor(freq)
    return df


def shannon_entropy(series: pd.Series) -> float:
    """Calcule l'entropie de Shannon d'une série catégorielle."""
    if series.empty:
        return 0.0
    value_counts = series.value_counts(normalize=True, dropna=True)
    p = value_counts.values
    return float(-(p * np.log2(p + 1e-12)).sum())


# ==========================
#   CPU
# ==========================

def aggregate_cpu(
    cpu_df: pd.DataFrame,
    window_size_s: int = 1
) -> pd.DataFrame:
    """
    Agrège les données CPU par fenêtre temporelle.
    Colonnes attendues :
      - timestamp
      - pid
      - comm
      - cpu_ns
    """
    if cpu_df is None or cpu_df.empty:
        return pd.DataFrame()

    df = parse_timestamp(cpu_df)
    df = add_window_column(df, window_size_s=window_size_s)

    grouped = df.groupby("window_start")

    features = pd.DataFrame(index=grouped.size().index)
    features.index.name = "window_start"

    features["cpu_events"] = grouped.size()
    features["cpu_time_sum"] = grouped["cpu_ns"].sum()
    features["cpu_time_mean"] = grouped["cpu_ns"].mean()
    features["cpu_time_max"] = grouped["cpu_ns"].max()
    features["cpu_unique_pids"] = grouped["pid"].nunique()
    features["cpu_unique_comms"] = grouped["comm"].nunique()

    # Entropie sur les noms de processus
    features["cpu_entropy_comm"] = grouped["comm"].apply(shannon_entropy)

    return features.reset_index()


# ==========================
#   EXEC
# ==========================

def aggregate_exec(
    exec_df: pd.DataFrame,
    window_size_s: int = 1
) -> pd.DataFrame:
    """
    Agrège les données d'exécution de binaires.
    Colonnes attendues :
      - timestamp
      - pid
      - comm
      - ppid
      - filename
    """
    if exec_df is None or exec_df.empty:
        return pd.DataFrame()

    df = parse_timestamp(exec_df)
    df = add_window_column(df, window_size_s=window_size_s)

    grouped = df.groupby("window_start")

    features = pd.DataFrame(index=grouped.size().index)
    features.index.name = "window_start"

    features["exec_count"] = grouped.size()
    features["exec_unique_binaries"] = grouped["filename"].nunique()

    # exécutions dans /tmp
    features["exec_tmp_count"] = grouped["filename"].apply(
        lambda s: s.fillna("").str.startswith("/tmp").sum()
    )

    # exécutions de shells
    shell_names = {"sh", "bash", "zsh", "dash"}
    features["exec_shell_count"] = grouped["comm"].apply(
        lambda s: s.isin(shell_names).sum()
    )

    # exécutions liées à l'outillage de package (apt, dpkg, etc.)
    def count_pkg_mgmt(filenames: pd.Series) -> int:
        txt = filenames.fillna("").astype(str)
        return int(
            txt.str.contains("apt").sum()
            + txt.str.contains("dpkg").sum()
        )

    features["exec_pkg_mgmt_count"] = grouped["filename"].apply(count_pkg_mgmt)

    # entropie sur les chemins de fichiers exécutés
    features["exec_entropy_filename"] = grouped["filename"].apply(shannon_entropy)

    return features.reset_index()


# ==========================
#   Process Lifecycle
# ==========================

def aggregate_process_lifecycle(
    pl_df: pd.DataFrame,
    window_size_s: int = 1
) -> pd.DataFrame:
    """
    Agrège les événements de vie de processus.
    Colonnes attendues :
      - timestamp
      - event (FORK | EXIT)
      - pid
      - ppid
      - uid
      - comm
    """
    if pl_df is None or pl_df.empty:
        return pd.DataFrame()

    df = parse_timestamp(pl_df)
    df = add_window_column(df, window_size_s=window_size_s)

    grouped = df.groupby("window_start")

    def count_event(series: pd.Series, value: str) -> int:
        return int((series == value).sum())

    features = pd.DataFrame(index=grouped.size().index)
    features.index.name = "window_start"

    features["proc_events"] = grouped.size()

    features["fork_count"] = grouped["event"].apply(
        lambda s: count_event(s, "FORK")
    )
    features["exit_count"] = grouped["event"].apply(
        lambda s: count_event(s, "EXIT")
    )
    features["proc_churn"] = features["fork_count"] - features["exit_count"]

    # forks par root
    def fork_uid0(g: pd.DataFrame) -> int:
        mask = (g["event"] == "FORK") & (g["uid"] == 0)
        return int(mask.sum())

    features["fork_uid0"] = grouped.apply(fork_uid0)

    # forks de shells
    shell_names = {"sh", "bash", "zsh", "dash"}
    def fork_shell(g: pd.DataFrame) -> int:
        mask = (g["event"] == "FORK") & (g["comm"].isin(shell_names))
        return int(mask.sum())

    features["fork_shell"] = grouped.apply(fork_shell)

    # diversité et entropie sur les commandes
    features["proc_unique_commands"] = grouped["comm"].nunique()
    features["proc_entropy_commands"] = grouped["comm"].apply(shannon_entropy)

    return features.reset_index()


# ==========================
#   Network
# ==========================

def aggregate_network(
    net_df: pd.DataFrame,
    window_size_s: int = 1
) -> pd.DataFrame:
    """
    Agrège les événements réseau.
    Colonnes attendues :
      - timestamp
      - pid
      - comm
      - src_ip
      - src_port
      - dst_ip
      - dst_port
      - bytes
    """
    if net_df is None or net_df.empty:
        return pd.DataFrame()

    df = parse_timestamp(net_df)
    df = add_window_column(df, window_size_s=window_size_s)

    grouped = df.groupby("window_start")

    features = pd.DataFrame(index=grouped.size().index)
    features.index.name = "window_start"

    features["net_event_count"] = grouped.size()
    features["net_unique_pids"] = grouped["pid"].nunique()
    features["net_bytes_sum"] = grouped["bytes"].sum()
    features["net_bytes_mean"] = grouped["bytes"].mean()
    features["net_bytes_max"] = grouped["bytes"].max()

    features["net_unique_dst_port"] = grouped["dst_port"].nunique()
    features["net_entropy_dst_ports"] = grouped["dst_port"].apply(shannon_entropy)

    # IP inconnues / nulles
    def count_unknown_ip(ips: pd.Series) -> int:
        txt = ips.fillna("").astype(str)
        return int((txt == "0.0.0.0").sum())

    features["net_unknown_dst_ip_count"] = grouped["dst_ip"].apply(count_unknown_ip)

    # ports suspects (exemple)
    suspicious_ports = {22, 23, 3389, 4444, 5555}
    def suspicious_ports_flag(ports: pd.Series) -> int:
        ports_clean = ports.fillna(0).astype(int)
        return int(ports_clean.isin(suspicious_ports).any())

    features["net_suspicious_ports_flag"] = grouped["dst_port"].apply(
        suspicious_ports_flag
    )

    return features.reset_index()


# ==========================
#   Privilege
# ==========================

def aggregate_privilege(
    priv_df: pd.DataFrame,
    window_size_s: int = 1
) -> pd.DataFrame:
    """
    Agrège les événements liés aux privilèges.
    Colonnes attendues :
      - timestamp
      - pid
      - comm
      - event_type (ex: exec_uid, fchmodat, ...)
      - target_uid
      - mode
      - filename
    """
    if priv_df is None or priv_df.empty:
        return pd.DataFrame()

    df = parse_timestamp(priv_df)
    df = add_window_column(df, window_size_s=window_size_s)

    grouped = df.groupby("window_start")

    features = pd.DataFrame(index=grouped.size().index)
    features.index.name = "window_start"

    features["priv_event_count"] = grouped.size()

    # événements touchant root
    features["priv_uid0_count"] = grouped["target_uid"].apply(
        lambda s: int((s == 0).sum())
    )

    # chmod / modifications dans /tmp
    def tmp_mod_count(g: pd.DataFrame) -> int:
        txt = g["filename"].fillna("").astype(str)
        return int(txt.str.startswith("/tmp").sum())

    features["priv_tmp_mod_count"] = grouped.apply(tmp_mod_count)

    # fichiers .sh modifiés
    def script_mod_count(g: pd.DataFrame) -> int:
        txt = g["filename"].fillna("").astype(str)
        return int(txt.str.endswith(".sh").sum())

    features["priv_script_mod_count"] = grouped.apply(script_mod_count)

    # permissions "fortes" (>= 0o700 -> 448 en décimal)
    def suspicious_perm_flag(modes: pd.Series) -> int:
        modes_clean = modes.fillna(0).astype(int)
        return int((modes_clean >= 448).any())

    features["priv_suspicious_permission_flag"] = grouped["mode"].apply(
        suspicious_perm_flag
    )

    # entropie sur les chemins
    features["priv_entropy_filename"] = grouped["filename"].apply(shannon_entropy)

    return features.reset_index()


# ==========================
#   Orchestration globale
# ==========================

def load_latest_file(data_dir: Path, pattern: str) -> Optional[pd.DataFrame]:
    """
    Charge le dernier fichier correspondant à un pattern donné
    (par ex. 'cpu_module_*.csv') dans data_dir.
    """
    files = sorted(glob.glob(str(data_dir / pattern)))
    if not files:
        return None
    latest = files[-1]
    return pd.read_csv(latest)


def build_dataset_for_session(
    data_dir: Path,
    session_id: Optional[str] = None,
    window_size_s: int = 1,
) -> pd.DataFrame:
    """
    Construit le dataset final pour l'autoencoder à partir
    des fichiers CSV générés par les modules eBPF.

    Si session_id est fourni, on cherche:
      cpu_module_<session_id>.csv, etc.
    Sinon, on prend le dernier fichier pour chaque module.
    """
    data_dir = Path(data_dir)

    if session_id:
        cpu_df = pd.read_csv(data_dir / f"cpu_data_{session_id}.csv")
        exec_df = pd.read_csv(data_dir / f"exec_data_{session_id}.csv")
        net_df = pd.read_csv(data_dir / f"network_data_{session_id}.csv")
        pl_df = pd.read_csv(data_dir / f"process_lifecycle_data_{session_id}.csv")
        priv_df = pd.read_csv(data_dir / f"privilege_data_{session_id}.csv")
    else:
        cpu_df = load_latest_file(data_dir, "cpu_data_*.csv")
        exec_df = load_latest_file(data_dir, "exec_data_*.csv")
        net_df = load_latest_file(data_dir, "network_data_*.csv")
        pl_df = load_latest_file(data_dir, "process_lifecycle_data_*.csv")
        priv_df = load_latest_file(data_dir, "privilege_data_*.csv")

    # Agrégation par module
    cpu_feat = aggregate_cpu(cpu_df, window_size_s=window_size_s)
    exec_feat = aggregate_exec(exec_df, window_size_s=window_size_s)
    pl_feat = aggregate_process_lifecycle(pl_df, window_size_s=window_size_s)
    net_feat = aggregate_network(net_df, window_size_s=window_size_s)
    priv_feat = aggregate_privilege(priv_df, window_size_s=window_size_s)

    # Fusion progressive sur window_start
    dfs: List[pd.DataFrame] = [
        cpu_feat,
        exec_feat,
        pl_feat,
        net_feat,
        priv_feat,
    ]
    dfs = [d for d in dfs if d is not None and not d.empty]

    if not dfs:
        raise RuntimeError("Aucun module n'a fourni de données agrégées.")

    dataset = dfs[0]
    for d in dfs[1:]:
        dataset = dataset.merge(d, on="window_start", how="outer")

    # Remplissage des NaN par 0 (pas d'événements dans la fenêtre)
    for col in dataset.columns:
        if col != "window_start":
            dataset[col] = dataset[col].fillna(0)

    # Tri chronologique
    dataset = dataset.sort_values("window_start").reset_index(drop=True)

    return dataset


def save_dataset(
    dataset: pd.DataFrame,
    data_dir: Path,
    session_id: Optional[str] = None,
) -> Path:
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    if session_id is None:
        # petit fallback si pas de session id fourni
        session_id = "default"

    out_path = data_dir / f"dataset_autoencoder_{session_id}.csv"
    dataset.to_csv(out_path, index=False)
    return out_path


# ==========================
#   Entrée CLI
# ==========================

def main():
    parser = argparse.ArgumentParser(
        description="Feature engineering pour eBPF-ML (dataset autoencoder)."
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="data",
        help="Répertoire contenant les CSV des modules eBPF.",
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Identifiant de session (suffixe des fichiers module_xxxx).",
    )
    parser.add_argument(
        "--window-size",
        type=int,
        default=1,
        help="Taille de la fenêtre temporelle en secondes.",
    )

    args = parser.parse_args()

    data_dir = Path(args.data_dir)

    dataset = build_dataset_for_session(
        data_dir=data_dir,
        session_id=args.session_id,
        window_size_s=args.window_size,
    )

    out_path = save_dataset(dataset, data_dir=data_dir, session_id=args.session_id)
    print(f"Dataset autoencoder sauvegardé dans : {out_path}")


if __name__ == "__main__":
    main()

