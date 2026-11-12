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
	python3 -m pytest -q
	python3 tests/test_hard.py

demo: all
	python3 examples/demo.py

clean:
	rm -f $(BINARIES)
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

.PHONY: all test demo clean
