CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lpcap

TARGET = monitor
SRC = monitor.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LIBS)

clean:
	rm -f $(TARGET) 