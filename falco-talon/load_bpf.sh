```
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/bpf.h>

int main(int argc, char **argv)
{
    int n;
    int bfd, pfd;
    struct bpf_insn *insn;
    union bpf_attr attr;
    char log_buf[4096];
    char buf[] = "\x95\x00\x00\x00\x00\x00\x00\x00";

    insn = (struct bpf_insn*)buf;
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insns = (unsigned long)insn;
    attr.insn_cnt = sizeof(buf) / sizeof(struct bpf_insn);
    attr.license = (unsigned long)"GPL";
    attr.log_size = sizeof(log_buf);
    attr.log_buf = (unsigned long)log_buf;
    attr.log_level = 1;
    attr.kern_version = 264656;

    pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    close(pfd);

    return 0;
}
```
