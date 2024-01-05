#!/bin/bash

# Define the BPF program
BPF_PROGRAM="example.c"
BPF_OBJECT="example.o"
LOADER_PROGRAM="loader.c"
LOADER_EXECUTABLE="loader"

# Write the BPF program to a file
cat << EOF > $BPF_PROGRAM
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/sys_clone")
int bpf_prog1(struct pt_regs *ctx) {
    bpf_printk("Hello, BPF World!\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
EOF

# Write the loader program to a file
cat << EOF > $LOADER_PROGRAM
#include <bpf/libbpf.h>

int main() {
    struct bpf_object *obj;

    // Load BPF object from file
    obj = bpf_object__open("$BPF_OBJECT");
    if (libbpf_get_error(obj))
        return 1;

    // Load BPF program into the kernel
    if (bpf_object__load(obj))
        return 1;

    // More code to attach the program, handle errors, etc.

    return 0;
}
EOF

# Compile the BPF program
clang -O2 -target bpf -c $BPF_PROGRAM -o $BPF_OBJECT

# Check if clang compilation succeeded
if [ $? -ne 0 ]; then
    echo "Failed to compile BPF program"
    exit 1
fi

# Compile the loader program
gcc $LOADER_PROGRAM -o $LOADER_EXECUTABLE -lbpf

# Check if gcc compilation succeeded
if [ $? -ne 0 ]; then
    echo "Failed to compile loader program"
    exit 1
fi

# Run the loader program with root privileges
sudo ./$LOADER_EXECUTABLE
