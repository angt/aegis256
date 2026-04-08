CFLAGS = -march=native -Wall -O2 -g -fsanitize=address,undefined

all: clean test
	./test

clean:
	rm -f test

.PHONY: clean all
