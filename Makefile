bf2am: bf2am.asm md5tab.inc
	nasm -f elf64 bf2am.asm -o bf2am.o
	ld -o bf2am bf2am.o

clean:
	rm -f bf2am bf2am.o
