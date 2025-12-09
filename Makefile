CC = gcc
CFLAGS = -Wall -Wextra -g -I.
LDFLAGS = -lpcap

TARGET = cshark

SRCS = main.c interface.c parser.c display.c filter.c capture.c storage.c

OBJS = $(SRCS:.c=.o)

HEADERS = cshark.h interface.h parser.h display.h filter.h capture.h storage.h colors.h

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete!"
