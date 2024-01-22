CFLAGS=-Wall
LDLIBS=-lcrypto

all: dsdecrypt

dsdecrypt: dsdecrypt.o keys.o xex.o
