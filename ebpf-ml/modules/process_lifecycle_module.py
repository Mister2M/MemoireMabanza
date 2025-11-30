from bcc import BPF
import os
import csv
from datetime import datetime

class ProcessLifecycleModule:
    def __init__(self, output_dir="./data"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        # Création du fichier CSV unique pour cette session
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_file = os.path.join(self.output_dir, f"process_lifecycle_{timestamp}.csv")

        # Initialiser CSV
        with open(self.csv_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "event", "pid", "ppid", "uid", "comm"])

        # Code eBPF pour suivre les événements de création et de fin de processus
        self.bpf_code = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        struct data_t {
            u64 ts;
            u32 pid;
            u32 ppid;
            u32 uid;
            char comm[TASK_COMM_LEN];
            char event[8];
        };

        BPF_PERF_OUTPUT(events);

        int trace_fork(struct tracepoint__sched__sched_process_fork *ctx) {
            struct data_t data = {};
            data.ts = bpf_ktime_get_ns();
            data.pid = ctx->child_pid;
            data.ppid = ctx->parent_pid;
            data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            __builtin_strncpy(data.event, "FORK", 8);
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        int trace_exit(struct tracepoint__sched__sched_process_exit *ctx) {
            struct data_t data = {};
            data.ts = bpf_ktime_get_ns();
            data.pid = bpf_get_current_pid_tgid() >> 32;
            data.ppid = 0; // PPID non dispo ici
            data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            __builtin_strncpy(data.event, "EXIT", 8);
            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """

        # Charger le code eBPF
        self.bpf = BPF(text=self.bpf_code)
        self.bpf.attach_tracepoint(tp="sched:sched_process_fork", fn_name="trace_fork")
        self.bpf.attach_tracepoint(tp="sched:sched_process_exit", fn_name="trace_exit")

        self.bpf["events"].open_perf_buffer(self._handle_event)

    def _handle_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        row = [timestamp, event.event.decode(), event.pid, event.ppid, event.uid, event.comm.decode()]
        
        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(row)

        print(f"[ProcessLifecycle] {timestamp} - {event.event.decode()} PID={event.pid} ({event.comm.decode()})")

    def start(self):
        print("[ProcessLifecycleModule] Surveillance du cycle de vie des processus en cours...")
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("[ProcessLifecycleModule] Arrêt demandé par l'utilisateur.")

