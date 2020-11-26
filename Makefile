MYPRJ=.

# pass  'M32=1'  on the make commandline for the 32-bit build with decompression support.

LDFLAGS+=-g $(if $(M32),-m32)
CFLAGS+=-g $(if $(M32),-m32) -Wall -std=c++1z -D_NO_RAPI

# osx10.15 no longer supports 32 bit code -> can't use dll's anymore.
CFLAGS+=$(if $(M32),,-D_NO_COMPRESS)
CFLAGS+=$(if $(D),-O0,-O3)

itslib=$(MYPRJ)/itslib
CFLAGS+=-I $(itslib)/include

dllload=$(MYPRJ)/dllloader
CFLAGS+=-I $(dllload)

# find a suitable openssl dir.
sslv=$(firstword $(wildcard $(addsuffix /include/openssl/opensslv.h,/usr/local /opt/local $(wildcard /usr/local/opt/openssl*) /usr)))
dirname=$(dir $(patsubst %/,%,$1))
openssl=$(call dirname,$(call dirname,$(call dirname,$(sslv))))


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
