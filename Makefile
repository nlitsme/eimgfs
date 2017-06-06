MYPRJ=.


LDFLAGS=-g -m32
CFLAGS=-g -m32 -Wall -std=c++1z -D_NO_RAPI

itslib=$(MYPRJ)/itslib
CFLAGS+=-I $(itslib)/include

dllload=$(MYPRJ)/dllloader
CFLAGS+=-I $(dllload)

openssl=/usr/local/opt/openssl
CFLAGS+=-I $(openssl)/include
LDFLAGS+=-lcrypto

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
