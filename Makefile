MYPRJ=.


LDFLAGS=-g -m32
CFLAGS=-g -m32 -Wall -std=c++1z -D_NO_RAPI
CFLAGS+=$(if $(D),-O0,-O3)

itslib=$(MYPRJ)/itslib
CFLAGS+=-I $(itslib)/include

dllload=$(MYPRJ)/dllloader
CFLAGS+=-I $(dllload)

openssl=/usr/local/opt/openssl
CFLAGS+=-I $(openssl)/include

# note: make sure this points to a i386 / 32 bit version of libcrypto.dylib
#       *homebrew* no longer ships with 32 bit binaries. There is however
#       still a 32 bit libcrypto in /usr/lib ... not sure for how long,
#       apple may remove this any time. When that happens, you should probably
#       build your own 32 bit openssl library.
LDFLAGS+=/usr/lib/libcrypto.dylib

computil=$(MYPRJ)/CompressUtils
CFLAGS+=-I $(computil)

eimgfs: eimgfs.o stringutils.o debug.o dllloader.o
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) -c -o $@ $^ $(CFLAGS)

%.o: $(itslib)/src/%.cpp
	$(CXX) -c -o $@ $^ $(CFLAGS)

%.o: $(dllload)/%.cpp
	$(CXX) -c -o $@ $^ $(CFLAGS)

clean:
	$(RM) eimgfs $(wildcard *.o)
