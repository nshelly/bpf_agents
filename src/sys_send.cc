// Begin - BPF syntax
#include "helpers.h"
#include "asm-generic/int-ll64.h"
#include <netinet/in.h>

#define PT_REGS_RC(ctx)		0

// End - BPF syntax

#include <uapi/linux/ptrace.h>
#include <net/sock.h>

struct pid_fd {
    u64 pid_tgid;
    u64 fd;
};

BPF_HASH(socket_pids);
BPF_HASH(currsock, u64, struct sock *);
BPF_HASH(pid_to_curr_fd);
BPF_HASH(network_fds, struct pid_fd);

// separate data structs for ipv4 and ipv6
struct send_data_t {
    // XXX: switch some to u32's when supported
    u64 ts_us;
    u64 pid;
    u64 tgid;
    u64 ppid;
    u64 sockfd;
    u64 len;
    u64 flags;
    u64 saddr;
    u64 sport;
    u64 daddr;
    u64 dport;
    char parent_task[TASK_COMM_LEN];
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(tcp_v4_connect_return_events);
BPF_PERF_OUTPUT(bind_events);
BPF_PERF_OUTPUT(accept_events);
BPF_PERF_OUTPUT(inet_csk_accept_return_events);
BPF_PERF_OUTPUT(accept_return_events);
BPF_PERF_OUTPUT(send_events);
BPF_PERF_OUTPUT(sendmsg_events);
BPF_PERF_OUTPUT(sendmmsg_events);
BPF_PERF_OUTPUT(recvmsg_events);
BPF_PERF_OUTPUT(sendto_events);
BPF_PERF_OUTPUT(recv_events);
BPF_PERF_OUTPUT(recvfrom_events);
BPF_PERF_OUTPUT(recvfrom_return_events);
BPF_PERF_OUTPUT(write_events);
BPF_PERF_OUTPUT(read_events);
BPF_PERF_OUTPUT(read_return_events);
BPF_PERF_OUTPUT(close_events);
BPF_PERF_OUTPUT(socket_events);
BPF_PERF_OUTPUT(socket_return_events);
BPF_PERF_OUTPUT(shutdown_events);


// Get last 32 bits (PID), upper is tgid.  Can also just do this in userspace.
#define bpf_get_current_pid() bpf_get_current_pid_tgid() & 0xffffffff
#define bpf_get_current_tgid() bpf_get_current_pid_tgid() >> 32


static int is_network_fd(int fd) {
    struct pid_fd network_data;
    network_data.pid_tgid = bpf_get_current_pid_tgid();
    network_data.fd = (u64) fd;
    u64 *found = network_fds.lookup(&network_data);
    return found != NULL;
}

static void
get_thread_metadata(struct send_data_t *send_data) {
    // Updates metadata to pass to userspace
    send_data->pid = bpf_get_current_pid();
    send_data->tgid = bpf_get_current_tgid();


    struct task_struct *task;
    struct task_struct *real_parent_task;
    u64 ppid;

    task = (struct task_struct *)bpf_get_current_task();

    /** XXX Something wrong is here? */
    bpf_probe_read(&real_parent_task,
                   sizeof(real_parent_task),
                   &task->real_parent);

    bpf_probe_read(&send_data->parent_task,
                   sizeof(send_data->parent_task),
                   &real_parent_task->comm);

    bpf_probe_read(&ppid,
                   sizeof(ppid),
                   &real_parent_task->pid);

//    bpf_trace_printk("real_parent_task: %s, real_parent_pid: %s\n",
//                     real_parent_task, ppid);
    send_data->ppid = ppid & 0xffffffff;
    send_data->ts_us = bpf_ktime_get_ns() / 1000,
    bpf_get_current_comm(&send_data->task, sizeof(send_data->task));
}

// Returns 0 if we should filter (updated by BCC-logic), otherwise 1
static int apply_filter(struct send_data_t *send_data) {
//    FILTER PORT
//    FILTER PID
//    FILTER OUT COMM
    return 1;
}

int trace_connect_entry(struct pt_regs *ctx,
                        int sockfd, const struct sockaddr *addr,
                        size_t addrlen)
{
    if (!is_network_fd(sockfd)) {
        return 0;
    }

    if (addr->sa_family != AF_INET) {
        return 0;
     }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

    send_data.sockfd = (u64)sockfd;

    struct sockaddr_in *ipv4 = NULL;
    bpf_probe_read(&ipv4, sizeof(ipv4), &addr);

    u16 dfamily = 0;
    u32 daddr = 0;
    u16 dport = 0;
    bpf_probe_read(&dfamily, sizeof(dfamily), &ipv4->sin_family);
    bpf_probe_read(&daddr, sizeof(daddr), &ipv4->sin_addr.s_addr);
    bpf_probe_read(&dport, sizeof(dport), &ipv4->sin_port);

    send_data.daddr = daddr;
    send_data.dport = ntohs(dport);

    bpf_trace_printk("connect: %s pid: %d\n",
                     send_data.task, send_data.pid);
    bpf_trace_printk("connect: %s (sa_family: %d, sin_family: %d)\n",
                     send_data.task, addr->sa_family, dfamily);
    bpf_trace_printk("-> %x:%d\n",
                     ntohl(daddr), ntohs(dport));
    connect_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
};

int trace_connect_v4_entry(struct pt_regs *ctx, int *sk)
{
    u64 pid = bpf_get_current_pid_tgid();
//    FILTER_PID

    // stash the sock ptr for lookup on return
    struct sock *skp = (struct sock *) sk;
    currsock.update(&pid, &skp);

    return 0;
};


int trace_connect_v4_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock.lookup(&pid_tgid);
    if (skpp == 0) {
        return 0;   // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock._delete(&pid_tgid);
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    struct sock *skp = *skpp;
    send_data.sockfd = 0;

    u16 dport = 0;
    bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
    u16 sport = 0;
    bpf_probe_read(&sport, sizeof(sport), &skp->__sk_common.skc_num);

    bpf_probe_read(&send_data.saddr, sizeof(u32),
        &skp->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&send_data.daddr, sizeof(u32),
        &skp->__sk_common.skc_daddr);
    send_data.sport = bpf_ntohs(sport);
    send_data.dport = bpf_ntohs(dport);
//        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
    bpf_trace_printk("connect_return: -> %x:%d\n",
                     ntohl(send_data.daddr), ntohs(dport));

//    } else /* 6 */ {
//        struct ipv6_data_t data6 = {.pid = pid, .ipver = ipver};
//        data6.ts_us = bpf_ktime_get_ns() / 1000;
//        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
//            &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
//        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
//            &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
//        data6.dport = ntohs(dport);
//        bpf_get_current_comm(&data6.task, sizeof(data6.task));
////        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));data6

    tcp_v4_connect_return_events.perf_submit(ctx, &send_data, sizeof(send_data));
    currsock._delete(&pid_tgid);
    return 0;
}

int trace_inet_csk_accept_return(struct pt_regs *ctx)
{
    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
//    if (newsk == NULL) {
//        return 0;
//    }
    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

    // check this is TCP
    u8 protocol = 0;
    // workaround for reading the sk_protocol bitfield:
    bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
    if (protocol != IPPROTO_TCP)
        return 0;

    // pull in details
    u16 family = 0, sport = 0, dport = 0;
    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
    bpf_probe_read(&sport, sizeof(sport), &newsk->__sk_common.skc_num);
    bpf_probe_read(&dport, sizeof(dport), &newsk->__sk_common.skc_dport);
    send_data.sport = sport;
    send_data.dport = dport;

    bpf_probe_read(&send_data.saddr, sizeof(u32),
                   &newsk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&send_data.daddr, sizeof(u32),
                   &newsk->__sk_common.skc_daddr);
    bpf_get_current_comm(&send_data.task, sizeof(send_data.task));
    inet_csk_accept_return_events.perf_submit(ctx, &send_data, sizeof(send_data));

    return 0;
}

int trace_send_entry(struct pt_regs *ctx, int sockfd,
                     const void *buf, size_t len, int flags)
{
    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

    send_data.len = len;
    send_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
};



//int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
//                      struct msghdr *msg, size_t size)
//{
//    u32 pid = bpf_get_current_pid_tgid();
//
//    u16 dport = 0, family = sk->__sk_common.skc_family;
//    u64 *val, zero = 0;
//
//    if (family == AF_INET) {
//        struct ipv4_key_t ipv4_key = {.pid = pid};
//        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
//        ipv4_key.daddr = sk->__sk_common.skc_daddr;
//        ipv4_key.lport = sk->__sk_common.skc_num;
//        dport = sk->__sk_common.skc_dport;
//        ipv4_key.dport = ntohs(dport);
//        val = ipv4_send_bytes.lookup_or_init(&ipv4_key, &zero);
//        (*val) += size;
//
//    }
//
//    return 0;
//}

int trace_sendmsg_entry(struct pt_regs *ctx,
                        int fd, const struct msghdr *msg,
                        int flags)
{
    if (!is_network_fd(fd)) {
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

//    bpf_trace_printk("comm: %s\n", send_data.task);

//    u64 sockfd = fd;
//    u64 *found = network_fds.lookup(&sockfd);
//    if (!found) {
//        return 0;   // missed entry
//    }
    struct sockaddr *msg_name = NULL;
    bpf_probe_read(&msg_name, sizeof(msg_name), &msg);

    u16 sa_family;
    bpf_probe_read(&sa_family, sizeof(sa_family), &msg_name->sa_family);
//    bpf_trace_printk("sendmsg: sa_family: %d\n", sa_family);

//    u16 sa_len = 0;
//    bpf_probe_read(&sa_len, sizeof(sa_len), &msg_name->sa_len);
//    bpf_trace_printk("sa_len: %d\n", sa_len);
//    if (protocol != IPPROTO_TCP)
//        return 0;
//    u64 *sa_family;
//    bpf_probe_read(&sa_family, sizeof(sa_family), &msg_name->sa_family);
//    if (sa_family != AF_UNSPEC) {
//        bpf_trace_printk("sendmsg: sa_family: %d\n", sa_family);
//        sendmsg_events.perf_submit(ctx, &send_data, sizeof(send_data));
//    }
    if (sa_family != 0) {
        sendmsg_events.perf_submit(ctx, &send_data, sizeof(send_data));
    }

    return 0;
};


int trace_sendmmsg_entry(struct pt_regs *ctx, int fd)
{
    if (!is_network_fd(fd)) {
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

//    struct sockaddr *msg_name = NULL;
//    bpf_probe_read(&msg_name, sizeof(msg_name), &msg);
//
//    u16 sa_family;
//    bpf_probe_read(&sa_family, sizeof(sa_family), &msg_name->sa_family);
//
//    if (sa_family != 0) {
//        sendmmsg_events.perf_submit(ctx, &send_data, sizeof(send_data));
//    }
    sendmmsg_events.perf_submit(ctx, &send_data, sizeof(send_data));

    return 0;
};


int trace_recvmsg_entry(struct pt_regs *ctx,
                        int fd, struct msghdr *msg, int flags)
{
    if (!is_network_fd(fd)) {
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)fd;
    send_data.flags = (u64) flags;

    struct sockaddr *msg_name = NULL;
    bpf_probe_read(&msg_name, sizeof(msg_name), &msg);

    u16 sa_family;
    bpf_probe_read(&sa_family, sizeof(sa_family), &msg_name->sa_family);
    if (sa_family != 0) {
        recvmsg_events.perf_submit(ctx, &send_data, sizeof(send_data));
    }
    return 0;
};

int trace_recv_entry(struct pt_regs *ctx,
                     int sockfd, void *buf, size_t len, int flags) {
    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)sockfd;
    send_data.len = len;
    recv_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}

int trace_recvfrom_entry(struct pt_regs *ctx,
                         int fd, void *buf, size_t len, int flags,
                         struct sockaddr *addr, int *fromlen) {
    if (!is_network_fd(fd)) {
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)fd;
    send_data.len = len;

    recvfrom_events.perf_submit(ctx, &send_data, sizeof(send_data));

    // Keep track of sockfd for noting read call
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 sockfd = (u64)fd;
    pid_to_curr_fd.insert(&pid_tgid, &sockfd);
    return 0;
}


//
//static
//send_data_t get_bytes_returned(struct pt_regs *ctx) {
//    /* Clean up here */
//    return NULL;
//}

int trace_recvfrom_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *fd = pid_to_curr_fd.lookup(&pid_tgid);
    if (fd == 0) {
        return 0; // missed entry (not a network read)
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = *fd;
    send_data.len = (u64)PT_REGS_RC(ctx);
    recvfrom_return_events.perf_submit(ctx, &send_data, sizeof(send_data));

    pid_to_curr_fd._delete(&pid_tgid);
    return 0;
}



int trace_sendto_entry(struct pt_regs *ctx,
                       int sockfd, void * buff, size_t len, unsigned flags,
                       struct sockaddr *addr, int addr_len) {
    if (!is_network_fd(sockfd)) {
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)sockfd;
    send_data.len = len;

//    if (!addr) {
//        return 1;
//    }

//    if (addr->sa_family != AF_INET) {
//        return 0;
//    }

//    char *sa_data = addr->sa_data;
//    struct sockaddr_in *ipv4 = NULL;
//    if (bpf_probe_read(&ipv4, sizeof(ipv4), &addr) == 0) {
//        bpf_trace_printk("successful got addr\n");
//    };
//
//
//    if (addr->sa_family == AF_INET) {
//        u16 sa_family = 0;
//        u32 daddr = 0;
//        u16 dport = 0;
//        bpf_probe_read(&sa_family, sizeof(sa_family), &ipv4->sin_family);
//        if (bpf_probe_read(&daddr, sizeof(daddr), &ipv4->sin_addr.s_addr)) {
//            bpf_trace_printk("error: ");
//        }
//
//        if (bpf_probe_read(&dport, sizeof(dport), &ipv4->sin_port)) {
//            bpf_trace_printk("error: ");
//        }
//
//        bpf_trace_printk("sendto: %s (sa_family: %d, sin_family: %d",
//                         send_data.task, addr->sa_family, sa_family);
//        bpf_trace_printk("sendto: -> %x:%d\n",
//                         bpf_ntohl(daddr), bpf_ntohs(dport));
//    } else {
//        bpf_trace_printk("sendto: %s, %d bytes, (sa_family: %d)\n",
//                         send_data.task, len, addr->sa_family);
//    }

    sendto_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}


int trace_write_entry(struct pt_regs *ctx,
                      int fd, const void *buf, size_t len) {

    if (!is_network_fd(fd)) {
        return 0;   // missed entry
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)fd;
    send_data.len = len;
    write_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}


int trace_read_entry(struct pt_regs *ctx,
                     int fd, const void *buf, size_t len) {
    if (!is_network_fd(fd)) {
        return 0;   // missed entry
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)fd;
    send_data.len = len;
    read_events.perf_submit(ctx, &send_data, sizeof(send_data));

    // Keep track of sockfd for noting read call
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 sockfd = (u64)fd;
    pid_to_curr_fd.insert(&pid_tgid, &sockfd);
    return 0;
}

int trace_read_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *fd = pid_to_curr_fd.lookup(&pid_tgid);
    if (fd == 0) {
        return 0; // missed entry (not a network read)
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = *fd;
    send_data.len = (u64)PT_REGS_RC(ctx);

    read_return_events.perf_submit(ctx, &send_data, sizeof(send_data));
    pid_to_curr_fd._delete(&pid_tgid);
    return 0;
}


struct event_t {
    int pid;
    int tgid;
};

int trace_socket_entry(struct pt_regs *ctx,
                       int domain, int type, int protocol) {
    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

    bpf_trace_printk("Domain: %d, type: %d, protocol: %d\n",
                     domain, type, protocol);
    send_data.len = (u64)domain;
    send_data.flags = (u64)type;
    if (domain != PF_INET) {
        return 0;
    }

    // Only keep track of sockets that are PF_INET (can add more later)
    u64 val = 1;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    socket_pids.insert(&pid_tgid, &val);

    socket_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}

int trace_socket_return(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!socket_pids.lookup(&pid_tgid)) {
        return 0;
    } else {
//        socket_pids._delete(&pid_tgid);
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

    struct pid_fd net_data;
    send_data.sockfd = (u64)PT_REGS_RC(ctx);
    net_data.fd = (u64)PT_REGS_RC(ctx);
    net_data.pid_tgid = pid_tgid;
    u64 val = 1;
    network_fds.insert(&net_data, &val);
    socket_return_events.perf_submit(ctx, &send_data, sizeof(send_data));
}

int trace_close_entry(struct pt_regs *ctx, int fd) {
    if (!is_network_fd(fd)) {
        return 0;
    }

    struct pid_fd net_data;
    net_data.fd = (u64)fd;
    net_data.pid_tgid = bpf_get_current_pid_tgid();
    network_fds._delete(&net_data);

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)fd;
    close_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}

int trace_shutdown_entry(struct pt_regs *ctx, int fd) {
    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    shutdown_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}

int trace_accept_entry(struct pt_regs *ctx,
                       int sockfd, struct sockaddr *addr, int *addrlen) {
    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)sockfd;

    accept_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}

int trace_accept_return(struct pt_regs *ctx)
{
    int fd = PT_REGS_RC(ctx);
    if (fd < 0) {
        // Often times a EAGAIN (resource temp. unavailable)
        return -1;
    }

    struct pid_fd net_data;
    net_data.fd = (u64)fd;
    net_data.pid_tgid = bpf_get_current_pid_tgid();
    u64 val = 1;
    network_fds.insert(&net_data, &val);

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };
    send_data.sockfd = (u64)fd;

    accept_return_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}


int trace_bind_entry(struct pt_regs *ctx,
                     int sockfd, struct sockaddr *addr, int *addrlen) {

    if (!is_network_fd(sockfd)) {
        return 0;
    }

    struct send_data_t send_data = {};
    get_thread_metadata(&send_data);
    if (!apply_filter(&send_data)) {
        return 0;
    };

    struct sockaddr_in *ipv4 = NULL;
    bpf_probe_read(&ipv4, sizeof(ipv4), &addr);

    u16 family = 0;
    u32 s_addr = 0;
    u16 port = 0;
    bpf_probe_read(&family, sizeof(family), &ipv4->sin_family);
    bpf_probe_read(&addr, sizeof(addr), &ipv4->sin_addr.s_addr);
    bpf_probe_read(&port, sizeof(port), &ipv4->sin_port);

    send_data.saddr = s_addr;
    send_data.sport = ntohs(port);

    bind_events.perf_submit(ctx, &send_data, sizeof(send_data));
    return 0;
}


//int trace_inet_csk_accept_return(struct pt_regs *ctx)
//{
//    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
//    u32 pid = bpf_get_current_pid_tgid();
//
//    if (newsk == NULL)
//        return 0;
//
//    struct send_data_t send_data = {
//            .pid = pid,
//    };
//
//    // check this is TCP
//    u8 protocol = 0;
//    // workaround for reading the sk_protocol bitfield:
//    bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
//    if (protocol != IPPROTO_TCP)
//        return 0;
//
//    // pull in details
//    u16 family = 0, lport = 0;
//    bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
//    bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
//
//    if (family == AF_INET) {
//        struct ipv4_data_t data4 = {.pid = pid, .ip = 4};
//        data4.ts_us = bpf_ktime_get_ns() / 1000;
//        bpf_probe_read(&data4.saddr, sizeof(u32),
//                       &newsk->__sk_common.skc_rcv_saddr);
//        bpf_probe_read(&data4.daddr, sizeof(u32),
//                       &newsk->__sk_common.skc_daddr);
//        data4.lport = lport;
//        bpf_get_current_comm(&data4.task, sizeof(data4.task));
//        ipv4_events.perf_submit(ctx, &data4, sizeof(data4));
//
//    } else if (family == AF_INET6) {
//        struct ipv6_data_t data6 = {.pid = pid, .ip = 6};
//        data6.ts_us = bpf_ktime_get_ns() / 1000;
//        bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
//                       &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
//        bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
//                       &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
//        data6.lport = lport;
//        bpf_get_current_comm(&data6.task, sizeof(data6.task));
//        ipv6_events.perf_submit(ctx, &data6, sizeof(data6));
//    }
//    // else drop
//
//    return 0;
//}

