DEVICE  ?= "lo"
HOOK    ?= "ingress"
VERSION ?= $(shell cat ./VERSION.txt)


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
	llvm-objdump -S -no-show-raw-insn ./classifier/main.o


logs:
	sudo tc exec bpf dbg


setup-device: clean-device build
	sudo tc qdisc add \
		dev $(DEVICE) \
		clsact
	sudo tc filter add \
		dev $(DEVICE) \
		$(HOOK) \
		bpf da \
		obj ./classifier/main.o


clean-device:
	sudo tc qdisc del \
		dev $(DEVICE) \
		clsact || true
