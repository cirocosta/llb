DEVICE  ?= "lo"
HOOK    ?= "egress"


build:
	clang -O2 -Wall -g -target bpf -c ./classifier/main.c -o ./classifier/main.o
	clang -O2 -Wall -S -target bpf -c ./classifier/main.c -o ./classifier/main.S


fmt:
	find ./classifier -name "*.c" -o -name "*.h" | \
		xargs clang-format -style=file -i


debug: build
	llvm-objdump -S -no-show-raw-insn ./classifier/main.o


see-logs:
	sudo tc exec bpf dbg


setup-dev: build
	sudo tc qdisc add \
		dev $(DEVICE) \
		clsact
	sudo tc filter add \
		dev $(DEVICE) \
		$(HOOK) \
		bpf da \
		obj ./classifier/main.o


clean-dev:
	sudo tc qdisc del \
		dev $(DEVICE) \
		clsact
	sudo tc filter del \
		dev $(DEVICE) \
		ingress || true
	sudo tc filter del \
		dev $(DEVICE) \
		egress || true

