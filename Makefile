CMAKEARGS+=$(if $(D),-DCMAKE_BUILD_TYPE=Debug,-DCMAKE_BUILD_TYPE=Release)
CMAKEARGS+=$(if $(COV),-DOPT_COV=1)
CMAKEARGS+=$(if $(PROF),-DOPT_PROF=1)
CMAKEARGS+=$(if $(LIBCXX),-DOPT_LIBCXX=1)
CMAKEARGS+=$(if $(M32),-A Win32 -DOPT_M32=1)
cmake:
	cmake -B build . $(CMAKEARGS)
	$(MAKE) -C build $(if $(V),VERBOSE=1)

clean:
	$(RM) eimgfs $(wildcard *.o)
	$(RM) -r build CMakeFiles CMakeCache.txt CMakeOutput.log

BOOST_LIBRARYDIR=$(if $(M32),$(BOOST_ROOT)/lib32-msvc-14.2,$(BOOST_ROOT)/lib64-msvc-14.2)
vc:
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" -G"Visual Studio 16 2019" -B build . $(CMAKEARGS)
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/MSBuild/Current/Bin/amd64/MSBuild.exe" build/*.sln -t:Rebuild



nmake:
	"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" -G"NMake Makefiles" -B build . $(CMAKEARGS)
	cd build ; nmake $(if $(V),VERBOSE=1)
