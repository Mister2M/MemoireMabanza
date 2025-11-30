# modules/cpu_module.py
# ---------------------
# Version corrigée - capture du nom du processus

PERF_MAP = "cpu_events"
PROVIDED_FIELDS = ["cpu_ns"]

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct cpu_event_t {
    u64 ts_ns;
    u32 pid;
    u64 delta_ns;
    char comm[TASK_COMM_LEN];  // AJOUT: nom du processus
};

BPF_PERF_OUTPUT(cpu_events);
BPF_HASH(start_ts, u32, u64);

TRACEPOINT_PROBE(sched, sched_switch) {
    u32 prev_pid = args->prev_pid;
    u32 next_pid = args->next_pid;
    u64 now = bpf_ktime_get_ns();

    /* Pour le processus qui sort (prev) */
    u64 *t = start_ts.lookup(&prev_pid);
    if (t) {
        u64 delta = now - *t;
        if (delta > 0) {
            struct cpu_event_t ev = {};
            ev.ts_ns = now;
            ev.pid = prev_pid;
            ev.delta_ns = delta;
            bpf_get_current_comm(&ev.comm, sizeof(ev.comm));  // AJOUT
            cpu_events.perf_submit(args, &ev, sizeof(ev));
        }
        start_ts.delete(&prev_pid);
    }

    /* Pour le processus qui entre (next) */
    start_ts.update(&next_pid, &now);

    return 0;
}
"""

def parse_event(bpf, data):
    """
    Version corrigée avec capture du nom du processus
    """
    evt = bpf[PERF_MAP].event(data)
    
    pid = int(getattr(evt, "pid", 0))
    delta = int(getattr(evt, "delta_ns", 0))
    comm = getattr(evt, "comm", b"").decode("utf-8", "replace").strip("\x00")

    return {
        "pid": pid,
        "comm": comm,  # MAINTENANT REMPLI !
        "cpu_ns": delta
    }
