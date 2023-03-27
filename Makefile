all: tc_tunnel_kern.c xdp_tunnel_kern.c tunnel_user.c common.h
	clang -O2 -g -emit-llvm -c tc_tunnel_kern.c -o - | \
		llc -march=bpf -mcpu=probe -filetype=obj -o tc_tunnel_kern.o

	clang -O2 -g -emit-llvm -c xdp_tunnel_kern.c -o - | \
		llc -march=bpf -mcpu=probe -filetype=obj -o xdp_tunnel_kern.o

	clang -O2 -g tunnel_user.c -o tunnel_user -lbpf

clean:
	rm -f *.o 

.PHONY: all clean
