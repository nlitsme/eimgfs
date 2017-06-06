#ifndef __WIN32COMPRESS_SERVER_H__
#define __WIN32COMPRESS_SERVER_H__
#include "compress_msgs.h"
#include "lzxxpr_convert.h"
#include "rom34_convert.h"

//#define csvrlog(...) fprintf(stderr, __VA_ARGS__)
#define csvrlog(...)

class win32compress_link {
    lzxxpr_convert _lzxxpr;
    rom34_convert  _rom34;

public:
    win32compress_link()
    {
        csvrlog("linked: reqsize=%d, ressize=%d\n", (int)sizeof(compressrequest), (int)sizeof(compressresult));
    }
    ~win32compress_link()
    {
    }
    void loaddlls()
    {
        _lzxxpr.loaddlls();
        _rom34.loaddlls();
    }

    DWORD DoCompressConvert(int dwType, unsigned char*outdata, DWORD outlength, const unsigned char *indata, DWORD insize)
    {
        DWORD resultLen=0xFFFFFFFF;
        switch(dwType)
        {
case ITSCOMP_XPR_DECODE:
case ITSCOMP_XPR_ENCODE:
case ITSCOMP_XPH_DECODE:
case ITSCOMP_XPH_ENCODE:
case ITSCOMP_LZX_DECODE:
case ITSCOMP_LZX_ENCODE:
        resultLen= _lzxxpr.DoCompressConvert(dwType, outdata, outlength, indata, insize);
        break;
case ITSCOMP_ROM3_DECODE:
case ITSCOMP_ROM3_ENCODE:
case ITSCOMP_ROM4_DECODE:
case ITSCOMP_ROM4_ENCODE:
        resultLen= _rom34.DoCompressConvert(dwType, outdata, outlength, indata, insize);
        break;
        }

        return resultLen;
    }
};
#endif

