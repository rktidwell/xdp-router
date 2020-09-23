user :
	mkdir -p bin
	gcc -lbpf bpf/xdp_gateway_user.c -o bin/xdpgatewayinit

xdp_lan_handler:
	mkdir -p bin
	clang -S -O2 -Wall -target bpf -emit-llvm -Wno-compare-distinct-pointer-types -Wno-pointer-sign -Wunused-function -c -g -o xdp_udp_pass_kern.11 bpf/xdp_lan_handler_kern.c -o - | llc -march=bpf -filetype=obj -o bin/xdp_lan_handler.o

clean:
	rm -rf bin/*
