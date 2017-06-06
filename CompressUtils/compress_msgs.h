#ifndef __COMPRESS_IPC_H__
#define __COMPRESS_IPC_H__
#include <stdint.h>
enum { ITSCOMP_XPR_DECODE, ITSCOMP_XPR_ENCODE, ITSCOMP_LZX_DECODE, ITSCOMP_LZX_ENCODE, ITSCOMP_ROM3_DECODE, ITSCOMP_ROM3_ENCODE, ITSCOMP_ROM4_DECODE, ITSCOMP_ROM4_ENCODE, ITSCOMP_XPH_DECODE, ITSCOMP_XPH_ENCODE };
struct compressrequest {
        uint32_t dwType;
        uint32_t outlength;
        uint32_t insize;
};
struct compressresult {
        uint32_t resultLen;
};
#endif
