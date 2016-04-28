all: lb.bpf

lb.bpf: lb.c
	clang-3.9 -Wall -emit-llvm -c lb.c -o - | llc-3.9 -march=bpf -filetype=obj -o lb.bpf
#	clang-3.9 -Wall hash_ports.c -target bpf -o hash_ports.bpf
