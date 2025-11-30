# modules/exec_module.py
# ----------------------
# Version avec syscall tracepoints

PERF_MAP = "exec_events"
PROVIDED_FIELDS = ["ppid", "filename"]

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_data_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(exec_events);

// Trace multiple exec syscalls
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = id >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        data.ppid = task->real_parent->tgid;
    }
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // args->filename dans execve
    if (args->filename) {
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    }
    
    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    struct exec_data_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    
    data.ts_ns = bpf_ktime_get_ns();
    data.pid = id >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task && task->real_parent) {
        data.ppid = task->real_parent->tgid;
    }
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // args->filename dans execveat
    if (args->filename) {
        bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)args->filename);
    }
    
    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

def parse_event(bpf, data):
    evt = bpf[PERF_MAP].event(data)
    
    pid = int(getattr(evt, "pid", 0))
    ppid = int(getattr(evt, "ppid", 0))
    comm = getattr(evt, "comm", b"").decode("utf-8", "replace").strip("\x00")
    filename = getattr(evt, "filename", b"").decode("utf-8", "replace").strip("\x00")

    return {
        "pid": pid,
        "comm": comm,
        "ppid": ppid,
        "filename": filename
    }

def attach(bpf):
    return
