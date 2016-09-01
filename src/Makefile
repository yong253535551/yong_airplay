CC=gcc
NCLUDES :=
LDFLAGS := -Wl,-rpath=$(PWD)/../lib
LDFLAGS += -L/usr/lib/x86_64-linux-gnu -L$(PWD)/../lib -lshairplay_new -lm -lavahi-client -lavahi-core -lavahi-common -ldns_sd -lpthread -lao
CFLAGS := -I$(PWD)/../include
DFLAGS :=
LIBS :=

LIBRARY :=
BINS := shairplay
OBJS := shairplay.o

SUBDIRS=lib

define make_subdir
 @for subdir in $(SUBDIRS) ; do \
 ( cd $$subdir && make $1) \
 done;
endef

all: $(BINS)

$(BINS): $(OBJS)
	$(call make_subdir , all)
	$(CC) -o $@ $(OBJS) $(CFLAGS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(LDFLAGS) -c $*.c -o $*.o

install:
	$(call make_subdir , install)

clean:
	@rm -rf $(BINS) $(OBJS) $(LIBRARY)
	$(call make_subdir , clean) 
