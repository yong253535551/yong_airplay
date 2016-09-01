#SUBDIRS=crypto alac

#define make_subdir
# @for subdir in $(SUBDIRS) ; do \
# ( cd $$subdir && make $1) \
# done;
#endef

CROSS_COMPILE=
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar
LD = $(CROSS_COMPILE)ld
CFLAGS := -I$(PWD)/../../include
LDFLAGS = -Wall -O3
LDFLAGS += -L/usr/lib/x86_64-linux-gnu -L$(PWD)/../../lib
LDFLAGS += -lm -lavahi-client -lavahi-core -lavahi-common -lpthread -lao
TARGET = libshairplay_new.so
SRCS = $(wildcard *.c ./airplay/*.c ./alac/*.c ./avahi/*.c ./crypto/*.c ./dnssd/*.c ./http/*.c ./raop/*.c ./utils/*.c)
OBJS = $(SRCS:.c=.o)

all:$(TARGET)

%.o:%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@ $(CFLAGS)

$(TARGET):$(OBJS)  
	$(CC) -shared $(LDFLAGS) -o $@ $(OBJS) 
	@ cp $(TARGET) ../../lib/. 
#	$(call make_subdir , all)

#install:
#	$(call make_subdir , install)
 
#debug:
#	$(call make_subdir , debug)

clean:
	@ rm -f *.o ./alac/*.o ./avahi/*.o ./crypto/*.o ./dnssd/*.o ./http/*.o ./raop/*.o ./utils/*.o $(TARGET) ../../lib/$(TARGET)
#	$(call make_subdir , clean) 
