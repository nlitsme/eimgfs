#ifndef __LZXXPR_CONVERT_H__
#define __LZXXPR_CONVERT_H__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <util/wintypes.h>
#if !defined(_WIN32) && !defined(__CYGWIN__)
#include "dllloader.h"
#else
#define NULLMODULE NULL
#endif
#include "compress_msgs.h"
//#include "stringutils.h"

//#define lzxxprtrace(...) fprintf(stderr, __VA_ARGS__)
#define lzxxprtrace(...)

class lzxxpr_convert {

// prototypes of cecompr_nt.dll
typedef void* (*FNCompressAlloc)(uint32_t AllocSize);
typedef void (*FNCompressFree)(void* Address);
typedef uint32_t (*FNCompressOpen)( uint32_t dwParam1, uint32_t MaxOrigSize, FNCompressAlloc AllocFn, FNCompressFree FreeFn, uint32_t dwUnknown);
typedef uint32_t (*FNCompressConvert)( uint32_t stream, void* out, uint32_t outlength, void* in, uint32_t insize); 
typedef void (*FNCompressClose)( uint32_t stream);

public:
    lzxxpr_convert()
    {
        loaddlls();
//      fprintf(stderr, "lzxxpr_convert loaded\n");
    }

    // (de)compresses   {data|insize} ->  {out|outlength}, returns resulting size
    uint32_t DoCompressConvert(int dwType, uint8_t*out, uint32_t outlength, const uint8_t *data, uint32_t insize)
    {
        uint32_t stream=0;
        uint32_t res;
        uint8_t *in;

        FNCompressOpen CompressOpen= NULL;
        FNCompressConvert CompressConvert= NULL;
        FNCompressClose CompressClose= NULL;

        switch(dwType) {
        case ITSCOMP_XPR_DECODE:
            CompressOpen= XPR_DecompressOpen;
            CompressConvert= XPR_DecompressDecode;
            CompressClose= XPR_DecompressClose;
            break;
        case ITSCOMP_XPR_ENCODE:
            CompressOpen= XPR_CompressOpen;
            CompressConvert= XPR_CompressEncode;
            CompressClose= XPR_CompressClose;
            break;
        case ITSCOMP_XPH_DECODE:
            CompressOpen= XPH_DecompressOpen;
            CompressConvert= XPH_DecompressDecode;
            CompressClose= XPH_DecompressClose;
            break;
        case ITSCOMP_XPH_ENCODE:
            CompressOpen= XPH_CompressOpen;
            CompressConvert= XPH_CompressEncode;
            CompressClose= XPH_CompressClose;
            break;
        case ITSCOMP_LZX_DECODE:
            CompressOpen= LZX_DecompressOpen;
            CompressConvert= LZX_DecompressDecode;
            CompressClose= LZX_DecompressClose;
            break;
        case ITSCOMP_LZX_ENCODE:
            CompressOpen= LZX_CompressOpen;
            CompressConvert= LZX_CompressEncode;
            CompressClose= LZX_CompressClose;
            break;
        default:
            fprintf(stderr,"lzxxprcv: unknown type: %d\n", dwType);
            return 0xFFFFFFFF;
        }
        if (CompressOpen==NULL || CompressConvert==NULL || CompressClose==NULL) {
            return 0xFFFFFFFF;
        }
        if (CompressOpen) {
            stream= CompressOpen(0x10000, 0x1000, &Compress_AllocFunc, &Compress_FreeFunc, 0);
            if (stream==0 || stream==0xFFFFFFFF) {
                return 0xFFFFFFFF;
            }
        }

        in= new uint8_t[0x2000];
        memcpy(in, data, insize);

        lzxxprtrace("lzxxpr(%d):(%p, 0x%x, %p, 0x%x, 0, 1, 4096)\n", dwType, in, insize, out, outlength);
        lzxxprtrace("lzxxpr(%d):in :%s\n", dwType, hexdump(in, insize).c_str());
        res= CompressConvert(stream, out, outlength, in, insize);
        if (res!=0xFFFFFFFF)
        lzxxprtrace("lzxxpr(%d):out:%s\n", dwType, hexdump(out, res).c_str());
//      fprintf(stderr, "->%08x\n", res);
//      if (res>0 && res<0x10000)
//          fprintf(stderr, "out: %s\n", hexdump(out, res).c_str());

        delete in;

        if (CompressClose)
            CompressClose(stream);
        return res;
    }

    void loaddlls()
    {
        LZX_CompressClose= NULL;
        LZX_CompressEncode= NULL;
        LZX_CompressOpen= NULL;
        LZX_DecompressClose= NULL;
        LZX_DecompressDecode= NULL;
        LZX_DecompressOpen= NULL;

        XPR_CompressClose= NULL;
        XPR_CompressEncode= NULL;
        XPR_CompressOpen= NULL;
        XPR_DecompressClose= NULL;
        XPR_DecompressDecode= NULL;
        XPR_DecompressOpen= NULL;

        XPH_CompressClose= NULL;
        XPH_CompressEncode= NULL;
        XPH_CompressOpen= NULL;
        XPH_DecompressClose= NULL;
        XPH_DecompressDecode= NULL;
        XPH_DecompressOpen= NULL;

        hDllnt= LoadLibrary("cecompr_nt-v2.dll");
        if (hDllnt!=NULLMODULE && hDllnt!=INVALID_HANDLE_VALUE) {
            LZX_CompressClose= (FNCompressClose)GetProcAddress(hDllnt, "LZX_CompressClose");
            LZX_CompressEncode= (FNCompressConvert)GetProcAddress(hDllnt, "LZX_CompressEncode");
            LZX_CompressOpen= (FNCompressOpen)GetProcAddress(hDllnt, "LZX_CompressOpen");
            LZX_DecompressClose= (FNCompressClose)GetProcAddress(hDllnt, "LZX_DecompressClose");
            LZX_DecompressDecode= (FNCompressConvert)GetProcAddress(hDllnt, "LZX_DecompressDecode");
            LZX_DecompressOpen= (FNCompressOpen)GetProcAddress(hDllnt, "LZX_DecompressOpen");

            XPR_CompressClose= (FNCompressClose)GetProcAddress(hDllnt, "XPR_CompressClose");
            XPR_CompressEncode= (FNCompressConvert)GetProcAddress(hDllnt, "XPR_CompressEncode");
            XPR_CompressOpen= (FNCompressOpen)GetProcAddress(hDllnt, "XPR_CompressOpen");
            XPR_DecompressClose= (FNCompressClose)GetProcAddress(hDllnt, "XPR_DecompressClose");
            XPR_DecompressDecode= (FNCompressConvert)GetProcAddress(hDllnt, "XPR_DecompressDecode");
            XPR_DecompressOpen= (FNCompressOpen)GetProcAddress(hDllnt, "XPR_DecompressOpen");
        }
        else {
            hDllnt= NULLMODULE;
            fprintf(stderr,"%08x: failed to load cecompr_nt-v2.dll\n", GetLastError());
        }
        hDllnt2= LoadLibrary("cecompr_nt_xphxpr.dll");
        if (hDllnt2!=NULLMODULE && hDllnt2!=INVALID_HANDLE_VALUE) {
            XPH_CompressClose= (FNCompressClose)GetProcAddress(hDllnt2, "XPH_CompressClose");
            XPH_CompressEncode= (FNCompressConvert)GetProcAddress(hDllnt2, "XPH_CompressEncode");
            XPH_CompressOpen= (FNCompressOpen)GetProcAddress(hDllnt2, "XPH_CompressOpen");
            XPH_DecompressClose= (FNCompressClose)GetProcAddress(hDllnt2, "XPH_DecompressClose");
            XPH_DecompressDecode= (FNCompressConvert)GetProcAddress(hDllnt2, "XPH_DecompressDecode");
            XPH_DecompressOpen= (FNCompressOpen)GetProcAddress(hDllnt2, "XPH_DecompressOpen");
        }
        else {
            hDllnt2= NULLMODULE;
            fprintf(stderr,"%08x: failed to load cecompr_nt_xphxpr.dll\n", GetLastError());
        }

    }
    HMODULE hDllnt;
    HMODULE hDllnt2;
    FNCompressClose LZX_CompressClose;
    FNCompressConvert LZX_CompressEncode;
    FNCompressOpen LZX_CompressOpen;
    FNCompressClose LZX_DecompressClose;
    FNCompressConvert LZX_DecompressDecode;
    FNCompressOpen LZX_DecompressOpen;

    FNCompressClose XPR_CompressClose;
    FNCompressConvert XPR_CompressEncode;
    FNCompressOpen XPR_CompressOpen;
    FNCompressClose XPR_DecompressClose;
    FNCompressConvert XPR_DecompressDecode;
    FNCompressOpen XPR_DecompressOpen;

    FNCompressClose XPH_CompressClose;
    FNCompressConvert XPH_CompressEncode;
    FNCompressOpen XPH_CompressOpen;
    FNCompressClose XPH_DecompressClose;
    FNCompressConvert XPH_DecompressDecode;
    FNCompressOpen XPH_DecompressOpen;

#ifndef _WIN32
#define ALIGN_STACK  __attribute__((force_align_arg_pointer))
#else
#define ALIGN_STACK
#endif
static void* Compress_AllocFunc(uint32_t AllocSize) ALIGN_STACK
{
    void* p= malloc(AllocSize);

    //fprintf(stderr,"Compress_AllocFunc(%08lx) -> %08lx\n", AllocSize, p);

    return p;
}
static void Compress_FreeFunc(void* Address) ALIGN_STACK
{
    //fprintf(stderr,"Compress_FreeFunc(%08lx)\n", Address);
    free(Address);
}
};
#endif
