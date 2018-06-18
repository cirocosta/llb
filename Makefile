INGRESS_DEVICE  ?= "enp0s8"
EGRESS_DEVICE   ?= "docker0"
VERSION         ?= $(shell cat ./VERSION.txt)


build:
	go build \
		-ldflags "-X main.version=$(VERSION)" \
		-i \
		-o ./build/llb \
		-v
	clang -O2 -Wall -g \
		-target bpf \
		-c ./classifier/main.c \
		-o ./classifier/main.o
.PHONY: build


test:
	sudo env \
		'PATH=$(PATH)' \
		'GOPATH=$(GOPATH)' \
			go test ./... -v


fmt:
	find ./classifier -name "*.c" -o -name "*.h" | \
		xargs clang-format -style=file -i
	find ./bpf -name "*.c" -o -name "*.h" | \
		xargs clang-format -style=file -i
	go fmt ./...


debug: build
	llvm-objdump -S \
		-no-show-raw-insn \
		./classifier/main.o


logs:
	sudo tc exec bpf dbg


setup-tc: clean-tc build
	sudo tc qdisc add \
		dev $(INGRESS_DEVICE) \
		clsact
	sudo tc filter add \
		dev $(INGRESS_DEVICE) \
		ingress \
		bpf direct-action \
		object-file ./classifier/main.o section ingress
	sudo tc qdisc add \
		dev $(EGRESS_DEVICE) \
		clsact
	sudo tc filter add \
		dev $(EGRESS_DEVICE) \
		egress \
		bpf direct-action \
		object-file ./classifier/main.o section egress


clean-tc:
	sudo tc qdisc del \
		dev $(INGRESS_DEVICE) \
		clsact || true
	sudo tc qdisc del \
		dev $(EGRESS_DEVICE) \
		clsact || true
	sudo find /sys/fs/bpf/tc/globals \
		-name "llb_*" -type f -delete || true
