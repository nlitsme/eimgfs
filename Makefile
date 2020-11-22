MYPRJ=.

# pass  'M32=1'  on the make commandline for the 32-bit build with decompression support.

LDFLAGS=-g $(if $(M32),-m32)
CFLAGS=-g $(if $(M32),-m32) -Wall -std=c++1z -D_NO_RAPI

# osx10.15 no longer supports 32 bit code -> can't use dll's anymore.
CFLAGS+=$(if $(M32),,-D_NO_COMPRESS)
CFLAGS+=$(if $(D),-O0,-O3)

itslib=$(MYPRJ)/itslib
CFLAGS+=-I $(itslib)/include

dllload=$(MYPRJ)/dllloader
CFLAGS+=-I $(dllload)

# the macos homebrew openssl dir:
openssl=/usr/local/opt/openssl

CFLAGS+=-I $(openssl)/include
LDFLAGS+=-L$(openssl)/lib -lcrypto

CFLAGS+=-I/usr/local/include

PLATFORM := $(shell uname -s)
computil=$(MYPRJ)/CompressUtils
CFLAGS+=-I $(computil)

eimgfs: eimgfs.o stringutils.o debug.o $(if $(M32),dllloader.o)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) -c -o $@ $^ $(CFLAGS)

%.o: $(itslib)/src/%.cpp
	$(CXX) -c -o $@ $^ $(CFLAGS)

%.o: $(dllload)/%.cpp
	$(CXX) -c -o $@ $^ $(CFLAGS)

clean:
	$(RM) eimgfs $(wildcard *.o)
