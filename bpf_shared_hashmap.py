from ctypes import Structure, c_uint
from bcc import BPF
from pybst.avltree import AVLTree
from pybst.bstnode import BSTNode

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
"""

b = BPF(text=bpf_text, cflags=["-Wno-duplicate-decl-specifier"])
shared_memory = b.get_table("shared_memory")

class BPFAVLTree:
    def __init__(self):
        self.avl_tree = AVLTree()
        self.key_counter = 1  # 0 = no child
        self.node_map = {}

    def insert(self, data):
        node = self.avl_tree.insert(data)
        node_key = self.key_counter
        self.key_counter += 1
        self.node_map[node] = node_key
        
        # Update the entire tree in BPF (simplest approach I could think of)
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
        
        # Update BPF hash map
        shared_memory[c_uint(node_key)] = bpf_node
        
        return node_key

    def print_tree(self):
        """Print the whole AVL tree structure"""
        print("AVL Tree:")
        self._print_tree(self.avl_tree.root)
        print("\nBPF Hash Map Contents:")
        for key, node in shared_memory.items():
            print(f"Key: {key.value}, Data: {node.data}, Left: {node.left_key}, Right: {node.right_key}")

    def _print_tree(self, node, level=0, prefix="Root: "):
        """Recursively print the tree structure"""
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
    
    # Verify the tree is balanced
    print("Final tree structure:")
    avl_tree.print_tree()
    
    # Verify BPF hash map contents
    print("\nFinal BPF hash map:")
    for key, node in shared_memory.items():
        print(f"Key: {key.value}, Data: {node.data}, Left: {node.left_key}, Right: {node.right_key}")
