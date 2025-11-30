# modules/test_module.py
import ctypes as ct

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct test_event_t {
    u32 pid;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

int trace_open(struct pt_regs *ctx) {
    struct test_event_t ev = {};
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}
"""

class TestEvent(ct.Structure):
    _fields_ = [("pid", ct.c_uint), ("comm", ct.c_char * 16)]

def parse_event(bpf, data, size=0):
    try:
        if isinstance(data, int):
            return None
        evt = TestEvent.from_buffer_copy(data)
        return {"pid": evt.pid, "comm": evt.comm.decode().strip("\x00")}
    except:
        return None

def attach(bpf):
    bpf.attach_kprobe(event="__x64_sys_open", fn_name="trace_open")
    print("[i] test_module: attached trace_open to __x64_sys_open")
