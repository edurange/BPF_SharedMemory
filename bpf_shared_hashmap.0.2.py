from ctypes import Structure, c_uint
from bcc import BPF
from pybst.avltree import AVLTree
# from pybst.bstnode import BSTNode
import ctypes as ct

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


BPF_PERF_OUTPUT(search_events);
struct search_result_t {
    u32 value;
    u32 found;
};

int search_tree(u32 search_value) {
    u32 root_key = 1;
    u32 current_key = root_key;
    
    while (current_key != 0) {
        struct Node *current_node = shared_memory.lookup(&current_key);
        if (!current_node) {
            break;  // Node not found
        }
        
        if (current_node->data == search_value) {
            return 1;  // Value found
        } else if (search_value < current_node->data) {
            current_key = current_node->left_key;
        } else {
            current_key = current_node->right_key;
        }
    }
    
    return 0;  // Value not found
}

int trace_search(struct pt_regs *ctx, u32 search_value) {
    struct search_result_t result = {};
    result.value = search_value;
    result.found = search_tree(search_value);
    
    search_events.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
"""

b = BPF(text=bpf_text, cflags=["-Wno-duplicate-decl-specifier"])
shared_memory = b.get_table("shared_memory")

b.attach_kprobe(event="sys_getpid", fn_name="trace_search")

class SearchResult(ct.Structure):
    _fields_ = [
        ("value", ct.c_uint),
        ("found", ct.c_uint)
    ]
def print_search_event(cpu, data, size):

    event = ct.cast(data, ct.POINTER(SearchResult)).contents
    print(f"Search for {event.value}: {'Found' if event.found else 'Not found'}")

b["search_events"].open_perf_buffer(print_search_event)

class BPFAVLTree:
    def __init__(self):
        self.avl_tree = AVLTree()
        self.key_counter = 1
        self.node_map = {}

    def insert(self, data):
        node = self.avl_tree.insert(data)
        node_key = self.key_counter
        self.key_counter += 1
        self.node_map[node] = node_key
        self._update_bpf_tree()
        return node

    def _update_bpf_tree(self):
        if self.avl_tree.root:
            self._update_node_in_bpf(self.avl_tree.root)

    def _update_node_in_bpf(self, node):
        if not node:
            return 0

        if node in self.node_map:
            node_key = self.node_map[node]
        else:
            node_key = self.key_counter
            self.key_counter += 1
            self.node_map[node] = node_key

        left_key = self._update_node_in_bpf(node.left) if node.left else 0
        right_key = self._update_node_in_bpf(node.right) if node.right else 0
        bpf_node = Node(data=node.key, left_key=left_key, right_key=right_key)
        
        shared_memory[c_uint(node_key)] = bpf_node
        return node_key
    
    def print_tree(self):
        print("AVL Tree:")
        self._print_tree(self.avl_tree.root)
        print("\nBPF Hash Map Contents:")
        for key, node in shared_memory.items(): # type: ignore
            print(f"Key: {key.value}, Data: {node.data}, Left: {node.left_key}, Right: {node.right_key}")

    def _print_tree(self, node, level=0, prefix="Root: "):
        if node is not None:
            print(" " * (level * 4) + prefix + str(node.key))
            if node.left or node.right:
                if node.left:
                    self._print_tree(node.left, level + 1, "L--- ")
                else:
                    print(" " * ((level + 1) * 4) + "L--- None")
                if node.right:
                    self._print_tree(node.right, level + 1, "R--- ")
                else:
                    print(" " * ((level + 1) * 4) + "R--- None")

    def search(self, value):
        # Trigger the BPF search function by calling getpid (which triggers our kprobe) not ideal for realtime lookup
        import os
        os.getpid()
        b.perf_buffer_poll()

# Example usage
if __name__ == "__main__":
    # Create AVL tree
    avl_tree = BPFAVLTree()
    
    # Insert values
    values = [10, 20, 30, 40, 50, 25]
    for val in values:
        print(f"Inserting {val}")
        avl_tree.insert(val)
        avl_tree.print_tree()
        print("-" * 40)
    
    # Verify the tree is balanced (python)
    print("Final tree structure:")
    avl_tree.print_tree()
    
    # Verify BPF hash map contents (python)
    print("\nFinal BPF hash map:")
    for key, node in shared_memory.items(): # type: ignore
        print(f"Key: {key.value}, Data: {node.data}, Left: {node.left_key}, Right: {node.right_key}")
    
    # Perform searches in kernel
    print("Searching for values in tree:")
    for val in [10, 15, 20, 25, 100]:
        print(f"Searching for {val}...")
        avl_tree.search(val)