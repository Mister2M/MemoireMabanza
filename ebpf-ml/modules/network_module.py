# modules/network_module.py
# -------------------------
# Module réseau compatible avec core.py
# Tracer les activités réseau via les syscalls sendto, recvfrom, connect

import socket
import struct

PERF_MAP = "events"
PROVIDED_FIELDS = ["src_ip", "src_port", "dst_ip", "dst_port", "bytes"]

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/socket.h>

struct net_event_t {
    u32 pid;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u64 bytes;
};

BPF_PERF_OUTPUT(events);

static int read_sockaddr(struct sockaddr *addr, u32 *ip, u16 *port) {
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), addr);
    *ip = sa.sin_addr.s_addr;
    *port = sa.sin_port;
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct net_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    struct sockaddr *addr = (struct sockaddr *)args->addr;
    if (addr) { 
        read_sockaddr(addr, &evt.daddr, &evt.dport); 
    }
    evt.bytes = args->len;
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    struct net_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    struct sockaddr *addr = (struct sockaddr *)args->addr;
    if (addr) { 
        read_sockaddr(addr, &evt.saddr, &evt.sport); 
    }
    evt.bytes = args->size;
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct net_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    if (addr) { 
        read_sockaddr(addr, &evt.daddr, &evt.dport); 
    }
    evt.bytes = 0; // connect n'a pas de bytes directement
    events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

def parse_event(bpf, data):
    """
    Convertit un événement BPF en dict compatible core.py.
    Interface standard : parse_event(bpf, data) -> dict
    """
    evt = bpf[PERF_MAP].event(data)
    
    # Conversion des adresses IP
    src_ip = socket.inet_ntoa(struct.pack("I", evt.saddr)) if evt.saddr != 0 else "0.0.0.0"
    dst_ip = socket.inet_ntoa(struct.pack("I", evt.daddr)) if evt.daddr != 0 else "0.0.0.0"
    
    # Conversion des ports (network byte order to host byte order)
    src_port = socket.ntohs(evt.sport)
    dst_port = socket.ntohs(evt.dport)
    
    # Récupération du nom du processus
    comm = getattr(evt, "comm", b"").decode("utf-8", "replace").strip("\x00")
    
    return {
        "pid": int(evt.pid),
        "comm": comm,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "bytes": int(evt.bytes)
    }

# Pas besoin de fonction attach() car on utilise TRACEPOINT_PROBE
