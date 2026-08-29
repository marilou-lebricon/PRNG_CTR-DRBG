all : 
	cd src ; make

clean :
	cd src ; make clean
	rm -f test/run_tests

help :
	@echo "Usage :"
	@echo " make [all]\t\tBuild the software"
	@echo " make help\t\tDisplay this help"
	@echo " make clean\t\tDestroy Build Files"
	@echo " make test\t\tCompile and run the tests"

# La ligne ci-dessous est OBLIGATOIRE pour que 'make test' fonctionne
.PHONY : all clean help test

test:
	gcc -std=c11 -Wall -Wextra -g -Iinclude \
	    test/tests.c \
	    src/ctr_drbg.c src/aes.c src/sub_bytes.c src/shift_rows.c \
	    src/mix_columns.c src/add_round_key.c src/tables.c \
	    src/key_expansion.c -o test/run_tests -lm
	./test/run_tests