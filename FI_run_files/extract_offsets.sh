cd xen; nm -pa --format=sysv xen-syms | ./tools/symbols --xensyms --sysv --sort --all-symbols > ../var_list;
