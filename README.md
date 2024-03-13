# go-ebpf-timer

This is a simple set of programs to demonstrate the use of eBPF timers. It uses [cilium/ebpf](https://github.com/cilium/ebpf) to interract with eBPF subsystem, and based on [this](https://github.com/cilium/ebpf/tree/main/examples/fentry) [cilium/ebpf](https://github.com/cilium/ebpf) example.

The high-level idea is that we will initialize a timer inside an `fentry` program that is attached to the `security_file_fcntl` kernel function. This will call a function every second until we terminate the main program. We make sure that the timer will be only initialized once even if the `fentry` program is triggered more than once.

In order to trigger our eBPF program, we will use a simple program that does an `fcntl` system call to a temporary file.

## Example output:

### Terminal 1

Build and load the eBPF program. Next we wait for any output.

```bash
$ go generate  ./... &&  go run -exec sudo .
Compiled /home/apapag/go-ebpf-timer/bpf_bpfel.o
Stripped /home/apapag/go-ebpf-timer/bpf_bpfel.o
Wrote /home/apapag/go-ebpf-timer/bpf_bpfel.go
Compiled /home/apapag/go-ebpf-timer/bpf_bpfeb.o
Stripped /home/apapag/go-ebpf-timer/bpf_bpfeb.o
Wrote /home/apapag/go-ebpf-timer/bpf_bpfeb.go
2024/03/13 08:46:37 Comm             PID      TGID
2024/03/13 08:46:42 fcntl 61982    61982                  <-- first call of "go run ./fcntl/"
2024/03/13 08:46:48 fcntl 62089    62089                  <-- second call of "go run ./fcntl/"
^C2024/03/13 08:46:54 received signal, exiting..
```

### terminal 2

Trigger our eBPF program (twice) by issuing an `fcntl` system call to a temporary file.

```bash
$ go run ./fcntl/
Running fcntl system call on /tmp/fcntl-2144782883
$ go run ./fcntl/
Running fcntl system call on /tmp/fcntl-2476336141
```

### Terminal 3

Check for eBPF messages.

```bash
$ cat /sys/kernel/debug/tracing/trace_pipe
           <...>-61982   [007] ....1 88204.445824: bpf_trace_printk: timer initialized  <-- first call of "go run ./fcntl/"
          <idle>-0       [007] ..s.. 88205.445843: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88206.445872: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88207.445902: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88208.445922: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88209.445950: bpf_trace_printk: timer_callback: 0
           <...>-62089   [002] ....1 88210.182905: bpf_trace_printk: timer already initialized  <-- second call of "go run ./fcntl/"
          <idle>-0       [007] ..s.. 88210.445979: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88211.445998: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88212.446021: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88213.446064: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88214.446081: bpf_trace_printk: timer_callback: 0
          <idle>-0       [007] ..s.. 88215.446104: bpf_trace_printk: timer_callback: 0
^C
```

## Test Platform

This is tested on a Linux kernel 6.5 with Go 1.22.