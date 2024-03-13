//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define TASK_COMM_LEN 16

// flags allowed in bpf_timer_init
#define CLOCK_REALTIME	0
#define CLOCK_MONOTONIC	1
#define CLOCK_BOOTTIME	7

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct mapval {
	struct bpf_timer timer;
	struct bpf_spin_lock lock;
	u64 initialized;
};

// we use a map to store the timer
// this is an array of 1 element
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct mapval);
	__uint(max_entries, 1);
} timer_map SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u8 comm[16];
	u32 pid;
	u32 tgid;
};
struct event *unused __attribute__((unused));

// callback for the timer
static int timer_cb(void *map, u32 *key, struct mapval *v)
{
	long ret;

	bpf_printk("timer_callback: %u", *key);

	// start the timer again
	// it will call the callback after 1 second
	// second parameter is the interval in nanoseconds
	ret = bpf_timer_start(&v->timer, 1000000000llu, 0);
	if (ret) {
		bpf_printk("error: timer_callback: timer_start: %ld", ret);
		return 0;
	}

	return 0;
}

SEC("fentry/security_file_fcntl")
int BPF_PROG(security_file_fcntl, struct file *file, unsigned int cmd, unsigned long arg)
{
	u64 pid_tgid, initialized;
	struct mapval *v;
	struct event *e;
	int zero = 0;
	long ret;

	// filter out unrelated calls to fcntl system call
	// these are some random values that should match the
	// values in ./fcntl/main.go
	if (cmd != 5674 || arg != 3454)
		return 0;

	// get the value from the map that contains the timer
	v = bpf_map_lookup_elem(&timer_map, &zero);
	if (!v)
		return 0;

	// this could be also done with atomics
	// but we use bpf_spin_lock as an example
	bpf_spin_lock(&v->lock);
	initialized = v->initialized;
	if (!v->initialized)
		v->initialized = 1;
	bpf_spin_unlock(&v->lock);

	if (!initialized) {
		// initialize the timer
		ret = bpf_timer_init(&v->timer, &timer_map, CLOCK_MONOTONIC);
		if (ret) {
			bpf_printk("error: timer_init: %ld", ret);
			return 0;
		}

		// set the callback for the timer
		ret = bpf_timer_set_callback(&v->timer, timer_cb);
		if (ret) {
			bpf_printk("error: timer_set_callback: %ld", ret);
			return 0;
		}

		// start the timer
		// it will call the callback after 1 second
		// second parameter is the interval in nanoseconds
		ret = bpf_timer_start(&v->timer, 1000000000llu, 0);
		if (ret) {
			bpf_printk("error: timer_start: %ld", ret);
			return 0;
		}

		bpf_printk("timer initialized");
	} else {
		bpf_printk("timer already initialized");
	}

	// reserve space in the ring buffer to send the event to user space
	e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!e)
		return 0;

	// set the process comm
	bpf_get_current_comm(&e->comm, TASK_COMM_LEN);

	// get process pid and tgid and set them to the event
	pid_tgid = bpf_get_current_pid_tgid();
	e->tgid = pid_tgid >> 32;
	e->pid = (u32)pid_tgid;

	// submit the event to the user
	bpf_ringbuf_submit(e, 0);

	return 0;
}
