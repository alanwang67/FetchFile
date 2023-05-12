CC      = gcc
CFLAGS  = -g -fsigned-char
LDFLAGS = -l crypto
RM      = rm -f

default: all

all: fileRetriever

Hello: Hello.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o fileRetriever.c

clean veryclean:
	$(RM) fileRetriever
