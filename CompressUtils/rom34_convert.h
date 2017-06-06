#ifndef __ROM34_CONVERT_H__
#define __ROM34_CONVERT_H__
#include <stdio.h>
#include "util/wintypes.h"
#if !defined(_WIN32) && !defined(__CYGWIN__)
#include "dllloader.h"
#endif
#include "compress_msgs.h"
//#include "stringutils.h"

//#define rom34trace(...) fprintf(stderr,__VA_ARGS__)
#define rom34trace(...)

class rom34_convert {

// prototypes of cecompressv3.dll and cecompressv4.dll
typedef uint32_t (*CECOMPRESS)(const unsigned char *lpbSrc, uint32_t cbSrc, uint8_t* lpbDest, uint32_t cbDest, uint16_t wStep, uint32_t dwPagesize);
typedef uint32_t (*CEDECOMPRESS)(const unsigned char *lpbSrc, uint32_t cbSrc, uint8_t*  lpbDest, uint32_t cbDest, uint32_t dwSkip, uint16_t wStep, uint32_t dwPagesize);

    HMODULE hDll3;
    CECOMPRESS compress3;
    CEDECOMPRESS decompress3;
    CEDECOMPRESS decompressRom3;

    HMODULE hDll4;
    CECOMPRESS compress4;
    CEDECOMPRESS decompress4;

public:
    rom34_convert()
    {
        loaddlls();
    }

    void loaddlls()
    {
        compress4= NULL;
        decompress4= NULL;
        hDll4= LoadLibrary("CECompressv4.dll");
        if (hDll4!=NULLMODULE && hDll4!=INVALID_HANDLE_VALUE) {
            compress4= (CECOMPRESS)GetProcAddress(hDll4, "CECompress");
            decompress4= (CEDECOMPRESS)GetProcAddress(hDll4, "CEDecompress");
        }
        else {
            hDll4= NULLMODULE;
            fprintf(stderr,"%08x: failed to load dll4\n", GetLastError());
        }

        compress3= NULL;
        decompress3= NULL;
        decompressRom3= NULL;
        hDll3= LoadLibrary("CECompressv3.dll");
        if (hDll3!=NULLMODULE && hDll3!=INVALID_HANDLE_VALUE) {
            compress3= (CECOMPRESS)GetProcAddress(hDll3, "CECompress");
            decompress3= (CEDECOMPRESS)GetProcAddress(hDll3, "CEDecompress");
            decompressRom3= (CEDECOMPRESS)GetProcAddress(hDll3, "CEDecompressROM");
        }
        else {
            hDll3= NULLMODULE;
            fprintf(stderr,"%08x: failed to load dll3\n", GetLastError());
        }
//      fprintf(stderr,"loaded rom3+rom4: %p %p\n", hDll3, hDll4);
    }
    // (de)compresses   {data|insize} ->  {out|outlength}, returns resulting size
    uint32_t DoCompressConvert(int dwType, uint8_t*out, uint32_t outlength, const uint8_t *in, uint32_t insize)
    {
        uint32_t res;
//      rom34trace("%d->\nin: %s\n", dwType, hexdump(in, insize).c_str());
        switch(dwType) {
        case ITSCOMP_ROM3_DECODE:
            rom34trace("rom34:dec3(%p, 0x%x, %p, 0x%x, 0, 1, 4096)\n", in, insize, out, outlength);
            rom34trace("rom34:in :%s\n", hexdump(in, insize).c_str());
            res= decompress3(in, insize, out, outlength, 0, 1, 4096);
            if (res!=0xFFFFFFFF)
            rom34trace("rom34:out:%s\n", hexdump(out, res).c_str());
            break;

        case ITSCOMP_ROM3_ENCODE:
            rom34trace("rom34:enc3(%p, 0x%x, %p, 0x%x, 0, 1, 4096)\n", in, insize, out, outlength);
            rom34trace("rom34:in :%s\n", hexdump(in, insize).c_str());
            res= compress3(in, insize, out, outlength, 1, 4096);
            if (res!=0xFFFFFFFF)
            rom34trace("rom34:out:%s\n", hexdump(out, res).c_str());
            break;

        case ITSCOMP_ROM4_DECODE:
            rom34trace("rom34:dec4(%p, 0x%x, %p, 0x%x, 0, 1, 4096)\n", in, insize, out, outlength);
            rom34trace("rom34:in :%s\n", hexdump(in, insize).c_str());
            res= decompress4(in, insize, out, outlength, 0, 1, 4096);
            if (res!=0xFFFFFFFF)
            rom34trace("rom34:out:%s\n", hexdump(out, res).c_str());
            break;

        case ITSCOMP_ROM4_ENCODE:
            rom34trace("rom34:enc4(%p, 0x%x, %p, 0x%x, 0, 1, 4096)\n", in, insize, out, outlength);
            rom34trace("rom34:in :%s\n", hexdump(in, insize).c_str());
            res= compress4(in, insize, out, outlength, 1, 4096);
            if (res!=0xFFFFFFFF)
            rom34trace("rom34:out:%s\n", hexdump(out, res).c_str());
            break;

        default:
            fprintf(stderr,"rom34cv: unknown type: %d\n", dwType);
            return 0xFFFFFFFF;
        }
//      rom34trace("->%08x\n", res);
//      if (res>0 && res<0x10000)
//          rom34trace("out: %s\n", hexdump(out, res).c_str());
        return res;
    }
};
#endif
