# Compiler settings - Can be customized.
CC=g++
CFLAGS=-Wall -std=c++17
LIBS=-lpcap

# Makefile settings - the file name.
TARGET=main
SRC=main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
