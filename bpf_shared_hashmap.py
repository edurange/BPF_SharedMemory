"""Initializes a hashmap containing a BST in kernel space and shares it with user space"""

import ctypes as ct
from ctypes import Structure, c_uint
import os
from bcc import BPF

class Node(Structure):
    _fields_ = [
        ("data", c_uint), 
        ("left_key", c_uint), 
        ("right_key", c_uint)
    ]

bpf_text = """
#include <uapi/linux/ptrace.h>

struct Node {
    u32 data;
    u32 left_key;
    u32 right_key;
};

BPF_HASH(shared_memory, u32, struct Node);
BPF_ARRAY(key_map, u32, 1);
BPF_PERF_OUTPUT(events);

int read_node_data(struct pt_regs *ctx) {
    u32 index = 0;
    u32 *node_key_ptr = key_map.lookup(&index);
    if (!node_key_ptr) return 0;
    
    u32 node_key = *node_key_ptr;
    struct Node *node = shared_memory.lookup(&node_key);
    if (node) {
        u32 data = node->data;
        events.perf_submit(ctx, &data, sizeof(data));
        return 1;
    }
    return 0;
}
"""

# Initialize BPF
b = BPF(text=bpf_text, cflags=["-Wno-duplicate-decl-specifier"])
b.attach_tracepoint(tp=b"syscalls:sys_enter_getpid", fn_name=b"read_node_data")

class BPFHashManager:
    def __init__(self):
        self.key_counter = 1
        self.key_map = b.get_table("key_map")
        self.shared_memory = b.get_table("shared_memory")
    
    def insert(self, data, left_key=0, right_key=0):
        node_key = self.key_counter
        self.key_counter += 1
        bpf_node = Node(data=data, left_key=left_key, right_key=right_key)
        self.shared_memory[ct.c_uint(node_key)] = bpf_node
        return node_key
    
    def print_hashmap(self):
        print("BPF Hash Map Contents:")
        for key, node in self.shared_memory.items():
            print(f"Key: {key.value}, Data: {node.data}, Left: {node.left_key}, Right: {node.right_key}")
    
    def trigger_read(self, node_key):
        self.key_map[ct.c_int(0)] = ct.c_uint(node_key)
        os.getpid()
        b.perf_buffer_poll(timeout=100)

def print_event(cpu, data, size):
    result = ct.cast(data, ct.POINTER(ct.c_uint)).contents
    print(f"Data read from BPF: {result.value}")

b["events"].open_perf_buffer(print_event)

# Example usage
if __name__ == "__main__":
    manager = BPFHashManager()

    # Build a tree
    root_key = manager.insert(50)
    left_key = manager.insert(30, right_key=manager.insert(40))
    right_key = manager.insert(70, left_key=manager.insert(60))
    
    # Update root with references to children
    root_node = Node(data=50, left_key=left_key, right_key=right_key)
    manager.shared_memory[ct.c_uint(root_key)] = root_node
    
    # Print the hashmap contents from userspace
    manager.print_hashmap()
    
    print("\n=== Demonstrating function calls in C ===")
    
    print("\n1. Reading root node:")
    manager.trigger_read(root_key)
    
    print("\n2. Reading left child:")
    manager.trigger_read(left_key)
    
    print("\n3. Reading right child:")
    manager.trigger_read(right_key)
    
    print("\n4. Reading a non-existent node:")
    manager.trigger_read(99)

"""
the key_map array will be replaced with ring buffer functionality in the final implementation
tree sorting is also not yet implemented
"""