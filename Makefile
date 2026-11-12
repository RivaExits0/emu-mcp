CC := x86_64-linux-gnu-gcc
CFLAGS ?= -O0 -g -fno-pie -no-pie

BINARIES = tests/sample_x64 tests/hardtest_x64 tests/hooktest tests/abi_x64
# optional cross compiled binaries, they are built by the test suite on demand
CROSS_BINARIES = tests/abi_x86 tests/abi_arm tests/abi_arm64

all: $(BINARIES)

tests/sample_x64: tests/sample.c
	$(CC) $(CFLAGS) -o $@ $<

tests/hardtest_x64: tests/hardtest.c
	$(CC) $(CFLAGS) -o $@ $<

tests/hooktest: tests/hooktest.c
	$(CC) $(CFLAGS) -o $@ $<

tests/abi_x64: tests/abi.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	python3 -m pytest -q
	python3 tests/test_hard.py

demo: all
	python3 examples/demo.py

clean:
	rm -f $(BINARIES) $(CROSS_BINARIES)
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache

.PHONY: all test demo clean
