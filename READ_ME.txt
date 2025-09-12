/*
EBPF resources: 
https://docs.ebpf.io

pybst resources:
https://pypi.org/project/pybst/
https://github.com/TylerSandman/py-bst/

1. "kernel space" will be used to represent any code run inside the bpf code
2. "userspace" will be used to represent any coe run outside of the kernel space, primarily in the main python file

currently, version 0.2 creates a hashmap with a binary search tree nested inside of it, then shares access to the python user environment
where it can be manipoulated and filled. Lookups can be performed in the kernel space, and can be called from userspace, but this is not fully tested. 
*/
