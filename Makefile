CC := x86_64-linux-gnu-gcc
CFLAGS ?= -O0 -g -fno-pie -no-pie

BINARIES = tests/sample_x64 tests/hardtest_x64 tests/hooktest

all: $(BINARIES)

tests/sample_x64: tests/sample.c
	$(CC) $(CFLAGS) -o $@ $<

tests/hardtest_x64: tests/hardtest.c
	$(CC) $(CFLAGS) -o $@ $<

tests/hooktest: tests/hooktest.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	python3 tests/test_emu.py
	python3 tests/test_hard.py
	python3 examples/demo.py

clean:
	rm -f $(BINARIES)

.PHONY: all test clean
