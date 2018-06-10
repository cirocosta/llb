DEVICE  ?= "lo"
HOOK    ?= "egress"


build:
	clang -O2 -Wall -g -target bpf -c default_cls.c -o default_cls.o
	clang -O2 -S -Wall -target bpf -c default_cls.c -o default_cls.S


fmt:
	find ./ -name "*.c" -o -name "*.h" | \
		xargs clang-format -style=file -i


debug: build
	llvm-objdump -S -no-show-raw-insn default_cls.o


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
		obj default_cls.o


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

