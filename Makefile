CC = clang
CFLAGS = -Wall -Wextra -Werror -pedantic -std=gnu99

.PHONY: lib exe debug run run-debug clean

lib: bin/valkyky.o
exe: bin/valkyky
debug: bin/valkyky-deb

run: bin/valkyky
	./bin/valkyky
run-debug: bin/valkyky-deb
	lldb ./bin/valkyky-deb

bin/valkyky.o: valkyky.c
	$(CC) $(CFLAGS) -c -o $@ $<

bin/valkyky: valkyky.c
	$(CC) $(CFLAGS) -D VALKYKY_EXE -o $@ $<

bin/valkyky-deb: valkyky.c
	$(CC) $(CFLAGS) -D VALKYKY_EXE -glldb -o $@ $<

clean:
	@rm -rf ./bin
	@mkdir bin
