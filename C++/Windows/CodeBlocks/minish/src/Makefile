SRC := minish.c linenoise.c
APP := minish
APP_CRYPT:= minish_crypted

all:
	gcc -std=c99 -g $(SRC) -o $(APP)

arm64:
	aarch64-none-linux-gnu-gcc -std=c99 -g $(SRC) -o $(APP)
	chmod 777 $(APP)
	~/make_gnos_elf_crypt.sh ./$(APP)
	cp ./$(APP_CRYPT) /share/344272/aarch64-none-linux-gnu/tools/$(APP)

mips:
	mips-rtl83xx-linux-gcc -std=c99 -g $(SRC) -o $(APP)
	chmod 777 $(APP)
	~/make_ib_elf_crypt.sh ./$(APP)
	cp ./$(APP_CRYPT) /share/344272/mips-rtl83xx-linux/tools/$(APP)

clean:
	rm -f $(APP) $(APP_CRYPT)
