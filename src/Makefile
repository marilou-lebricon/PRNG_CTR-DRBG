INCLUDEDIR=../include
CFLAGS=-std=c11 -Wall -Wextra -g
CPPFLAGS=-I$(INCLUDEDIR)
CC = gcc

all: aes

aes: aes.o mix_columns.o add_round_key.o key_expansion.o shift_rows.o sub_bytes.o tables.o ctr_drbg.o main.o
	$(CC) $(CFLAGS) -o ../aes $^

aes.o: aes.c $(INCLUDEDIR)/aes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

mix_columns.o: mix_columns.c $(INCLUDEDIR)/mix_columns.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

add_round_key.o: add_round_key.c $(INCLUDEDIR)/add_round_key.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

key_expansion.o: key_expansion.c $(INCLUDEDIR)/key_expansion.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

shift_rows.o: shift_rows.c $(INCLUDEDIR)/shift_rows.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

sub_bytes.o: sub_bytes.c $(INCLUDEDIR)/sub_bytes.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

tables.o: tables.c $(INCLUDEDIR)/tables.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

ctr_drbg.o: ctr_drbg.c $(INCLUDEDIR)/ctr_drbg.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

main.o: main.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $^

clean :
	@rm -f *.o ../aes ../include/*.gch

help :
	@echo "Usage :"
	@echo " make [all]\t\tBuild the software"
	@echo " make help\t\tDisplay this help"

.PHONY : all clean help