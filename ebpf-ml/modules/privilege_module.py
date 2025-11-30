# modules/privilege_module.py
# ---------------------------
# Module eBPF pour détecter changements de privilèges et opérations liées
# (setuid/setgid/setresuid/setresgid, capset, chmod/fchmodat, exec uid after exec).
#
# Expose :
#   PERF_MAP = "priv_events"
#   PROVIDED_FIELDS = ["event_type", "target_uid", "mode", "filename"]
#   BPF_PROGRAM, parse_event(bpf,data), attach(bpf) optional

PERF_MAP = "priv_events"
PROVIDED_FIELDS = ["event_type", "target_uid", "mode", "filename"]

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct priv_event_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];

    u8 etype;       /* 1=setuid,2=setgid,3=setresuid,4=setresgid,5=capset,6=chmod,7=fchmodat,8=exec_uid */
    u32 target_uid; /* target uid/gid where applicable */
    u32 mode;       /* file mode for chmod/fchmodat */
    char filename[256];
};

BPF_PERF_OUTPUT(priv_events);

/* Helper: safe read current task's parent tgid */
static inline u32 get_ppid_tgid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;
    struct task_struct *p = task->real_parent;
    if (!p)
        return 0;
    return p->tgid;
}

/* setuid */
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 1;
    /* args->uid exists in many kernels; fallback to 0 if not */
    ev.target_uid = (u32)args->uid;
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* setgid */
TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 2;
    ev.target_uid = (u32)args->gid;
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* setresuid (ruid, euid, suid) : capture ruid as representative */
TRACEPOINT_PROBE(syscalls, sys_enter_setresuid) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 3;
    ev.target_uid = (u32)args->ruid;
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* setresgid */
TRACEPOINT_PROBE(syscalls, sys_enter_setresgid) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 4;
    ev.target_uid = (u32)args->rgid;
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* capset: flag the event (arguments are pointers in many ABI) */
TRACEPOINT_PROBE(syscalls, sys_enter_capset) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 5;
    ev.target_uid = 0;
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* chmod(pathname, mode) */
TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 6;
    ev.mode = (u32)args->mode;
    /* args->filename is a user pointer on many kernels; safe-read if present */
    if (args->filename)
        bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), args->filename);
    else
        ev.filename[0] = '\0';
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* fchmodat(dirfd, pathname, mode, flags) */
TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 7;
    ev.mode = (u32)args->mode;
    if (args->filename)
        bpf_probe_read_user_str(&ev.filename, sizeof(ev.filename), args->filename);
    else
        ev.filename[0] = '\0';
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}

/* After exec: capture the effective uid via bpf_get_current_uid_gid (no filename here) */
TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct priv_event_t ev = {};
    ev.ts_ns = bpf_ktime_get_ns();
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    ev.ppid = get_ppid_tgid();
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.etype = 8;
    u64 uid_gid = bpf_get_current_uid_gid();
    ev.target_uid = (u32)uid_gid;
    ev.filename[0] = '\0'; /* filename not available portably here */
    priv_events.perf_submit(args, &ev, sizeof(ev));
    return 0;
}
"""

# ---------- parse_event (userspace) ----------
def parse_event(bpf, data):
    """
    Retourne un dict standardisé pour core.py
    Champs: pid, comm, event_type, target_uid, mode, filename
    """
    ev = bpf[PERF_MAP].event(data)
    pid = int(getattr(ev, "pid", 0))
    comm = getattr(ev, "comm", b"").decode("utf-8", "replace").strip("\x00")

    etype = int(getattr(ev, "etype", 0))
    etype_map = {
        1: "setuid",
        2: "setgid",
        3: "setresuid",
        4: "setresgid",
        5: "capset",
        6: "chmod",
        7: "fchmodat",
        8: "exec_uid"
    }
    e_str = etype_map.get(etype, "unknown")

    target_uid = int(getattr(ev, "target_uid", 0))
    mode = int(getattr(ev, "mode", 0))
    filename = getattr(ev, "filename", b"").decode("utf-8", "replace").strip("\x00")

    return {
        "pid": pid,
        "comm": comm,
        "event_type": e_str,
        "target_uid": target_uid,
        "mode": mode,
        "filename": filename
    }

# optional attach helper (no-op; tracepoints in BPF_PROGRAM are self-contained)
def attach(bpf):
    return

