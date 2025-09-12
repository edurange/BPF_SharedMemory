/*
EBPF resources: 
https://docs.ebpf.io

pybst resources:
https://pypi.org/project/pybst/
https://github.com/TylerSandman/py-bst/

currently, version 0.2 creates a hashmap with a bst nested inside of it, then shares access to the python user environment
where it can be manipoulated and filled. Lookups can be performed in the kernel space, and can be called from userspace, but this is not fully tested. 
*/
