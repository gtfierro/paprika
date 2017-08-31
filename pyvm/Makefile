OBJCOPY=moxie-elf-objcopy
CC=moxie-elf-gcc
a.bin: main.o
	$(OBJCOPY) -O binary main.o a.bin
main.o: main.c
	$(CC) -S main.c
	$(CC) -c main.c
clean:
	rm main.o main.s a.bin

.PHONY: clean
