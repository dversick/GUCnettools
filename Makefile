TOOLS=example
CFLAGS=-Wall

all:
	for i in $(TOOLS) ; do make -C $$i "CFLAGS=$(CFLAGS)"; done

clean:
	for i in $(TOOLS) ; do make -C $$i clean; done
	
