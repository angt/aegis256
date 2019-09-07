CFLAGS=-march=native -O2

.PHONY: all
all: test
	./test

.PHONY: clean
clean:
	rm -f test
