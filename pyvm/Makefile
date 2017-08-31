OBJCOPY=moxie-elf-objcopy
CC=moxie-elf-gcc
a.bin: main.o
	$(OBJCOPY) -O binary main.o a.bin
a.out: main.c
	$(CC) -mno-crt0 -nostartfiles -lc --entry main main.c -o a.out
	
main.o: main.c
	$(CC) -S main.c
	$(CC) -c main.c
clean:
	rm main.o main.s a.bin a.out

.PHONY: clean
