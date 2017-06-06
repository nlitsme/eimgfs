/* (C) 2003 XDA Developers  itsme@xs4all.nl
 *
 * $Header: /var/db/cvs/xda-devtools/itsutils/common/debug.h,v 1.12 2005/06/12 22:52:01 itsme Exp $
 */
#ifndef __DEBUG_H__

//#include <util/wintypes.h>
#include <stdint.h>
#include <string>
//#include "vectorutils.h"

#ifdef __cplusplus
extern "C" {
#endif
void DebugSocketSend(const char *buf);
void debug(const char *msg, ...);
void error(const char *msg, ...);
#ifdef __cplusplus
}
#endif

void error(uint32_t dwErrorCode, const char *msg, ...);
void vdebug(const char *msg, va_list ap);
void vwdebug(const WCHAR *msg, va_list ap);
void ceerror(const char *msg, ...);
void debugt(const char *msg, ...);

class CDebugWindow  {
public:
    virtual ~CDebugWindow() { }
    virtual void appendString(const TCHAR *str)=0;
};

#ifdef __cplusplus
extern "C" {
#endif
void DebugSetLogfile(const char *filename);
void DebugSetSocket(const char *ipaddr);
#ifdef _WIN32
void DebugRegisterWindow(CDebugWindow *wnd);
#endif
void DebugNoMessagebox();
void DebugMessagebox();
void DebugNoOutputDebugString();
void DebugOutputDebugString();
void DebugNoStdOut();
void DebugStdOut();
inline void UnbufferedStdOut() { setbuf(stdout, NULL); }
#ifdef __cplusplus
}
#endif

enum DumpUnitType {
    DUMPUNIT_BYTE,
    DUMPUNIT_WORD,
    DUMPUNIT_DWORD,
    DUMPUNIT_QWORD
};
inline int DumpUnitSize(DumpUnitType type) { return 1<<type; }

enum DumpFormat {
    DUMP_HEX_ASCII,     // [offset] 50 51 52 53 0d 0a 00 01  PQRS....
    DUMP_HEX,           // [offset] 50 51 52 53 0d 0a 00 01
    DUMP_ASCII,         // [offset] PQRS....
    DUMP_STRINGS,       // [offset] "PQRS",0d,0a,00,01
    DUMP_RAW,           // [offset] PQRS^M^J^@^A
    DUMP_HASH,          // just print hash of entire buffer
    DUMP_HASHES,        // print all known hash types
    DUMP_CRC32,         // print crc32 of entire buffer
    DUMP_SUM,           // print various sums of entire buffer
};
//#define HEXDUMP_WITH_OFFSET    (1<<20)
//#define HEXDUMP_SUMMARIZE      (1<<21)
//#define HEXDUMP_MOREFOLLOWS    (1<<22)

//[oldfmt] bits0-11 : units_per_line
//[oldfmt] bits12-13 : unittype
//[oldfmt] bits14-15 : ?
//[oldfmt] bits16-19 : format
//[oldfmt] bits20  with offset
//[oldfmt] bits21  summarize
//[oldfmt] bits22  morefollows
//[oldfmt] bits23-31 : ?

#define HEXDUMP_WITH_OFFSET    (1<<6)
#define HEXDUMP_SUMMARIZE      (1<<7)
#define HEXDUMP_MOREFOLLOWS    (1<<8)
// -- new format -> max 0x800000 unitsperline
// bits0-1 : unittype  : 0=byte, 1=word, 2=dword
// bits2-5 : format
// bits6  with offset
// bits7  summarize
// bits8  morefollows
// bits9-31 : units_per_line

#define MAXUNITSPERLINE (1<<(32-9))
inline uint32_t hexdumpflags(DumpUnitType unit, int units_per_line, DumpFormat format) {
    return static_cast<uint32_t>((units_per_line<<9) | (format<<2) | (unit));
}
inline DumpUnitType dumpunit_from_flags(uint32_t flags) { return static_cast<DumpUnitType>((flags)&3); }
inline DumpFormat dumpformat_from_flags(uint32_t flags) { return static_cast<DumpFormat>((flags>>2)&15); }
inline unsigned unitsperline_from_flags(uint32_t flags) { return static_cast<unsigned>(flags>>9); }

void writedumpline(int64_t llOffset, const std::string& line);
void bighexdump(int64_t llOffset, const uint8_t *data, size_t size, uint32_t flags=hexdumpflags(DUMPUNIT_BYTE, 16, DUMP_HEX_ASCII)|HEXDUMP_WITH_OFFSET|HEXDUMP_SUMMARIZE);

template<typename T, typename A>
inline void bighexdump(int64_t llOffset, const std::vector<T, A>& data, uint32_t flags=hexdumpflags(DUMPUNIT_BYTE, 16, DUMP_HEX_ASCII)|HEXDUMP_WITH_OFFSET|HEXDUMP_SUMMARIZE)
{
    bighexdump(llOffset, (const uint8_t*)&data.front(), data.size()*sizeof(T), flags);
}
template<typename T, typename A>
inline void bighexdump(const std::vector<T, A>& data, uint32_t flags=hexdumpflags(DUMPUNIT_BYTE, 16, DUMP_HEX_ASCII)|HEXDUMP_SUMMARIZE)
{
    bighexdump(0, (const uint8_t*)&data.front(), data.size()*sizeof(T), flags);
}

#ifdef _WIN32_WCE
bool isSmartPhone();
#endif

#define __DEBUG_H__
#endif

