// Define _GNU_SOURCE to use GNU extensions, providing access to additional features and functionality.
#define _GNU_SOURCE

// Include standard header files for input-output, standard library, unix standards, system calls, file control, and BPF functions.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <linux/bpf.h>

// Main function of the program.
int main(int argc, char **argv)
{
    // Variable declarations.
    int n;
    int bfd, pfd; // File descriptors.
    struct bpf_insn *insn; // Pointer to BPF instruction structure.
    union bpf_attr attr; // Union for BPF attributes.
    char log_buf[4096]; // Buffer for logging.
    char buf[] = "\x95\x00\x00\x00\x00\x00\x00\x00"; // Buffer containing raw BPF bytecode.

    // Assign the buffer with bytecode to the BPF instruction pointer.
    insn = (struct bpf_insn*)buf;

    // Set attributes for the BPF program.
    attr.prog_type = BPF_PROG_TYPE_KPROBE; // Program type set to kprobe.
    attr.insns = (unsigned long)insn; // Pointer to the BPF instructions.
    attr.insn_cnt = sizeof(buf) / sizeof(struct bpf_insn); // Count of BPF instructions.
    attr.license = (unsigned long)"GPL"; // License of the BPF program.
    attr.log_size = sizeof(log_buf); // Size of the log buffer.
    attr.log_buf = (unsigned long)log_buf; // Pointer to the log buffer.
    attr.log_level = 1; // Log level.
    attr.kern_version = 264656; // Kernel version for compatibility.

    // Load the BPF program into the kernel using a system call.
    pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));

    // Close the file descriptor.
    close(pfd);

    // Exit the program.
    return 0;
}
