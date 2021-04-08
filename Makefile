MYPRJ=.

# pass  'M32=1'  on the make commandline for the 32-bit build with decompression support.

LDFLAGS+=-g $(if $(M32),-m32)
CFLAGS+=-g $(if $(M32),-m32) -Wall -D_NO_RAPI
CXXFLAGS+=-std=c++1z 

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
	$(RM) -r build CMakeFiles CMakeCache.txt CMakeOutput.log

cmake:
	cmake -B build . $(if $(D),-DCMAKE_BUILD_TYPE=Debug,-DCMAKE_BUILD_TYPE=Release) $(CMAKEARGS)
	$(MAKE) -C build $(if $(V),VERBOSE=1)

vc:
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" -G"Visual Studio 16 2019" -B build .
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/amd64/MSBuild.exe" build/cpputils.sln -t:Rebuild


