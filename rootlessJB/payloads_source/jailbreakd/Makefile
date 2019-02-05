TARGET  = jailbreakd
OUTDIR ?= ../../bootstrap/bins

CC      = xcrun -sdk iphoneos cc -arch arm64
LDID    = ldid2
CFLAGS  = -Wall -Wno-unused-variable -Wno-unused-function

.PHONY: all clean

all: $(OUTDIR)/$(TARGET)

DEBUG ?= 1
ifeq ($(DEBUG), 1)
    CFLAGS += -DJAILBREAKDDEBUG
else
    CFLAGS += -O2
endif

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(OUTDIR)/$(TARGET): *.c *.m | $(OUTDIR)
	$(CC) -o $@ $^ -framework Foundation -framework IOKit $(CFLAGS)
	$(LDID) -SEnt.plist $@
	tar --disable-copyfile -cvf ../../bootstrap/bins/jailbreakd.tar -C ../../bootstrap/bins/ jailbreakd
	rm $@

clean:
	rm -f $(OUTDIR)/$(TARGET)
