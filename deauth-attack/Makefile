CC=g++
CFLAGS=-Wall -std=c++17
LIBS=-lpcap


TARGET=deauth-attack
SRC=main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET)
