/* (C) 2003 XDA Developers  itsme@xs4all.nl
 *
 * $Header$
 */
#include <util/wintypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef _WIN32_WCE
#ifndef _NO_RAPI
#include <rapi.h>
#endif
#endif


// todo: change current 'debugflags' to a debuginfo struct,
//    in which then lastline, and offsets can be remembered
//    so we can fix the lastline, and broken lines in large dump issues.


#include "debug.h"        // declarations for this file.
#include "stringutils.h"
#include "vectorutils.h"

#ifndef WIN32
#include <errno.h>
#include <time.h>
#define _snprintf snprintf
#define _vsnprintf vsnprintf
#endif

#define DBG_OUTPUTDEBUGSTRING 1
#define DBG_MESSAGEBOX        2
#define DBG_DEBUGWINDOW       4
#define DBG_LOGFILE           8
#define DBG_STDOUT           16
#if !defined(WIN32)
#define DBG_WCHAROUTPUT (0)
#define DBG_CHAROUTPUT (DBG_LOGFILE|DBG_STDOUT)
#elif defined(_WIN32_WCE)
//  define these for wince use
#define DBG_WCHAROUTPUT (DBG_OUTPUTDEBUGSTRING|DBG_MESSAGEBOX|DBG_DEBUGWINDOW)
#define DBG_CHAROUTPUT (DBG_LOGFILE|DBG_STDOUT)
#else
#ifdef _UNICODE
//  define these for unicode desktop use
#define DBG_WCHAROUTPUT (DBG_OUTPUTDEBUGSTRING|DBG_MESSAGEBOX|DBG_DEBUGWINDOW)
#define DBG_CHAROUTPUT (DBG_LOGFILE|DBG_STDOUT)
#else
//  define these for non unicode desktop use
#define DBG_WCHAROUTPUT (0)
#define DBG_CHAROUTPUT (DBG_LOGFILE|DBG_STDOUT|DBG_OUTPUTDEBUGSTRING|DBG_MESSAGEBOX|DBG_DEBUGWINDOW)
#endif
#endif

std::string GetLogRootDir();

#define MAX_DEBUG_LENGTH 16384

int g_debugOutputFlags;
std::string g_logfilename;
#ifdef WIN32
HANDLE g_log_mutex= NULL;
#endif
CDebugWindow *g_debugWindow;


#ifdef _DEBUG_SOCKET

#include <winsock2.h>
static SOCKET g_debugsocket=INVALID_SOCKET;
static sockaddr_in g_debugaddr;

void DebugSetSocket(const char *ipaddr)
{
    if (ipaddr)
    {
        WSADATA wsaData;
        int rc= WSAStartup(WINSOCK_VERSION, &wsaData);
        if (rc) {
            error(rc, "WSAStartup");
            return;
        }
        debug("wsa: v=%04x - %04x  desc='%s'  stat='%s'  maxsock=%d  maxudp=%d vend=%08lx\n",
                wsaData.wVersion, wsaData.wHighVersion, wsaData.szDescription, wsaData.szSystemStatus, wsaData.iMaxSockets, wsaData.iMaxUdpDg, wsaData.lpVendorInfo);

        g_debugsocket= socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (g_debugsocket==INVALID_SOCKET) {
            error(WSAGetLastError(), "socket");
            return;
        }
        debug("socket=%08lx\n", g_debugsocket);

        g_debugaddr.sin_family= AF_INET;
        g_debugaddr.sin_port= htons(12345);
        // [HKLM\Comm\DTPT] DTPTSRV_ADDR
        g_debugaddr.sin_addr.s_addr= inet_addr("169.254.2.2");
    }
    else
    {
        int rc= closesocket(g_debugsocket);
        if (rc==SOCKET_ERROR) {
            error(WSAGetLastError(), "closesocket");
            return;
        }
        g_debugsocket= INVALID_SOCKET;
        rc= WSACleanup();
        if (rc==SOCKET_ERROR) {
            error(WSAGetLastError(), "WSACleanup");
            return;
        }
    }
    return;
}
void DebugSocketSend(const char *buf)
{
    if (g_debugsocket!=SOCKET_ERROR)
        sendto(g_debugsocket, buf, strlen(buf), 0, (SOCKADDR *)&g_debugaddr, sizeof(g_debugaddr));
}
#endif
void DebugSetLogfile(const char *filename)
{
    if (filename) {
#ifdef WIN32
        g_log_mutex= CreateMutex(NULL, false, NULL);
#endif
        if (filename[0]=='\\' || filename[0]=='/' || (isalpha(filename[0]) && filename[1]==':'))
            g_logfilename= filename;
        else
            g_logfilename= GetLogRootDir() + filename;
        g_debugOutputFlags |= DBG_LOGFILE;
        //MessageBox(0, _T("opening log"), ToTString(g_logfilename).c_str(), 0);
    }
    else {
        //MessageBox(0, _T("closing log"), _T("debug"), 0);
        g_debugOutputFlags &= ~DBG_LOGFILE;
#ifdef WIN32
        if (g_log_mutex && WaitForSingleObject(g_log_mutex, INFINITE)==WAIT_OBJECT_0) {
            CloseHandle(g_log_mutex);
            g_log_mutex= NULL;
        }
#endif
        g_logfilename.clear();
    }
}
void DebugRegisterWindow(CDebugWindow *wnd)
{
    if (wnd==NULL) {
        g_debugOutputFlags &= ~DBG_DEBUGWINDOW;
        g_debugWindow= wnd;
    }
    else {
        g_debugWindow= wnd;
        g_debugOutputFlags |= DBG_DEBUGWINDOW;
    }
}
void DebugNoStdOut()
{
    g_debugOutputFlags &= ~DBG_STDOUT;
}
void DebugStdOut()
{
    g_debugOutputFlags |= DBG_STDOUT;
}
void DebugNoMessagebox()
{
    g_debugOutputFlags &= ~DBG_MESSAGEBOX;
}
void DebugMessagebox()
{
    g_debugOutputFlags |= DBG_MESSAGEBOX;
}
void DebugNoOutputDebugString()
{
    g_debugOutputFlags &= ~DBG_OUTPUTDEBUGSTRING ;
}
void DebugOutputDebugString()
{
    g_debugOutputFlags |= DBG_OUTPUTDEBUGSTRING ;
}
void wdebugoutput(const WCHAR *wbuf)
{
#if DBG_WCHAROUTPUT&DBG_OUTPUTDEBUGSTRING
    if (g_debugOutputFlags&DBG_OUTPUTDEBUGSTRING) {
        int len= _tcslen(wbuf);
        for (int i= 0 ; i<len ; i+=512)
        {
            WCHAR smallbuf[513];
            wcsncpy(smallbuf, wbuf+i, 512);
            smallbuf[512]= 0;
            OutputDebugString(smallbuf);
        }
    }
#endif
#if DBG_WCHAROUTPUT&DBG_MESSAGEBOX
#ifndef _NO_WINDOWS
    if (g_debugOutputFlags&DBG_MESSAGEBOX) {
        MessageBox(0,wbuf,L"debug",0);
    }
#endif
#endif
#if DBG_WCHAROUTPUT&DBG_DEBUGWINDOW
    if (g_debugOutputFlags&DBG_DEBUGWINDOW && g_debugWindow) {
        g_debugWindow->appendString(wbuf);
    }
#endif
#if DBG_WCHAROUTPUT&DBG_STDOUT
    if (g_debugOutputFlags&DBG_STDOUT) {
        fputws(wbuf, stdout);
    }
#endif
#if DBG_WCHAROUTPUT&DBG_LOGFILE
    if (g_debugOutputFlags&DBG_LOGFILE) {
#ifdef WIN32
        if (WaitForSingleObject(g_log_mutex, INFINITE)==WAIT_OBJECT_0)
#endif
        {
            FILE *f= fopen(g_logfilename.c_str(), "a+");
            if (f) {
                fputws(wbuf, f);
                fclose(f);
            }
#ifdef WIN32
            ReleaseMutex(g_log_mutex);
#endif
        }
    }
#endif
}
void debugoutput(const char *buf)
{
#ifdef _DEBUG_SOCKET
    if (g_debugsocket!=SOCKET_ERROR)
    {
        int len= (int)strlen(buf);
        for (int i= 0 ; i<len ; i+=512)
        {
            char smallbuf[513];
            strncpy(smallbuf, buf+i, 512);
            smallbuf[512]= 0;
            DebugSocketSend(smallbuf);
        }
    }

#endif
#if DBG_CHAROUTPUT&DBG_OUTPUTDEBUGSTRING
    if (g_debugOutputFlags&DBG_OUTPUTDEBUGSTRING) {
        int len= (int)strlen(buf);
        for (int i= 0 ; i<len ; i+=512)
        {
            char smallbuf[513];
            strncpy(smallbuf, buf+i, 512);
            smallbuf[512]= 0;
            OutputDebugString(smallbuf);
        }
    }
#endif
#if DBG_CHAROUTPUT&DBG_MESSAGEBOX
#ifndef _NO_WINDOWS
    if (g_debugOutputFlags&DBG_MESSAGEBOX) {
        MessageBox(0,buf,"debug",0);
    }
#endif
#endif
#if DBG_CHAROUTPUT&DBG_DEBUGWINDOW
    if (g_debugOutputFlags&DBG_DEBUGWINDOW && g_debugWindow) {
        g_debugWindow->appendString(buf);
    }
#endif
#if DBG_CHAROUTPUT&DBG_STDOUT
    if (g_debugOutputFlags&DBG_STDOUT) {
        fputs(buf, stdout);
    }
#endif
#if DBG_CHAROUTPUT&DBG_LOGFILE
    if (g_debugOutputFlags&DBG_LOGFILE) {
#ifdef WIN32
        if (WaitForSingleObject(g_log_mutex, INFINITE)==WAIT_OBJECT_0)
#endif
        {
            FILE *f= fopen(g_logfilename.c_str(), "a+");
            if (f) {
                fputs(buf, f);
                fclose(f);
            }
#ifdef WIN32
            ReleaseMutex(g_log_mutex);
#endif
        }
    }
#endif
}
#ifdef WIN32
std::Wstring vwdebugmsg(const WCHAR *msg, va_list ap)
{
    std::Wstring wbuf; wbuf.resize(MAX_DEBUG_LENGTH);

    _vsnwprintf(stringptr(wbuf), wbuf.size(), msg, ap);
    wbuf.resize(wcslen(wbuf.c_str()));

    return wbuf;
}
#endif
std::string vdebugmsg(const char *msg, va_list ap)
{
    std::string buf; buf.resize(MAX_DEBUG_LENGTH);

    _vsnprintf(stringptr(buf), buf.size(), msg, ap);
    buf.resize(strlen(buf.c_str()));

    return buf;
}
#ifdef WIN32
void vwdebug(const WCHAR *msg, va_list ap)
{
    std::Wstring wbuf= vwdebugmsg(msg, ap);
    if (g_debugOutputFlags&DBG_CHAROUTPUT) {
        debugoutput(ToString(wbuf).c_str());
    }
    wdebugoutput(wbuf.c_str());
}
#endif

void vdebug(const char *msg, va_list ap)
{
    std::string buf= vdebugmsg(msg, ap);
#ifdef WIN32
    if (g_debugOutputFlags&DBG_WCHAROUTPUT) {
        wdebugoutput(ToWString(buf).c_str());
    }
#endif
    debugoutput(buf.c_str());
}

#ifdef WIN32
void wdebug(const WCHAR *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vwdebug(msg, ap);
    va_end(ap);
}
#endif
void debug(const char *msg, ...)
{
    va_list ap;

    va_start(ap, msg);
    vdebug(msg, ap);
    va_end(ap);
}

void verror(uint32_t dwErrorCode, const char *msg, va_list ap)
{
#ifdef WIN32
    // todo: make this charsize independent
    TCHAR* msgbuf;
    int rc= FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, dwErrorCode, 0, (TCHAR*) &msgbuf, 0, NULL);
    if (rc)
    {
#ifdef _UNICODE
        debug("ERROR: %hs - %ls\n", vdebugmsg(msg, ap).c_str(), msgbuf);
#else
        debug("ERROR: %hs - %hs\n", vdebugmsg(msg, ap).c_str(), msgbuf);
#endif
        LocalFree(msgbuf);
    }
    else
        debug("ERROR: %hs - UNKNOWNERROR: 0x%08lx\n", vdebugmsg(msg, ap).c_str(), dwErrorCode);
#else
    debug("ERROR(%08lx): %s\n", dwErrorCode, vdebugmsg(msg, ap).c_str());
#endif
}
void error(uint32_t dwErrorCode, const char *msg, ...)
{
#ifdef WIN32
    uint32_t dwSavedError= GetLastError();
#endif
    va_list ap;
    va_start(ap, msg);
    verror(dwErrorCode, msg, ap);
    va_end(ap);
#ifdef WIN32
    SetLastError(dwSavedError);
#endif
}

void error(const char *msg, ...)
{
#ifdef WIN32
    uint32_t dwSavedError= GetLastError();
#else
    uint32_t dwSavedError= errno;
#endif
    va_list ap;
    va_start(ap, msg);
    verror(dwSavedError, msg, ap);
    va_end(ap);
#ifdef WIN32
    SetLastError(dwSavedError);
#endif
}

#ifndef _WIN32_WCE
#ifndef _NO_RAPI
void ceerror(const char *msg, ...)
{
#ifdef WIN32
    uint32_t dwSavedError= GetLastError();
#endif
    va_list ap;
    va_start(ap, msg);

    uint32_t dwError= CeRapiGetError();
    if (!dwError)
        dwError= CeGetLastError();

    verror(dwError, msg, ap);
    va_end(ap);

#ifdef WIN32
    SetLastError(dwSavedError);
#endif
}
#endif
#endif

void debugt(const char *msg, ...)
{
#ifdef WIN32
    SYSTEMTIME now;
    GetLocalTime(&now);
    static uint32_t tLast;
    uint32_t tNow= GetTickCount();

    va_list ap;
    va_start(ap, msg);
    debug("TIMESTAMP: %04d-%02d-%02d %02d:%02d:%02d @%08x(+%4d) %08lx %hs", 
                now.wYear, now.wMonth, now.wDay,
                now.wHour, now.wMinute, now.wSecond, tNow, tNow-tLast,
                GetCurrentThreadId(),
                vdebugmsg(msg, ap).c_str());
    va_end(ap);
    tLast= tNow;
#else
    static time_t tLast;
    time_t tNow= time(NULL);
    va_list ap;
    va_start(ap, msg);
    debug("TIMESTAMP: %08x(+%4d) %s", 
                tNow, tNow-tLast,
                vdebugmsg(msg, ap).c_str());
    va_end(ap);
    tLast= tNow;
#endif
}

std::string dumponeunit(const uint8_t *p, size_t len, int unittype)
{
    switch(unittype) {
        case DUMPUNIT_BYTE: return stringformat("%02x", *p);
        case DUMPUNIT_WORD:
                if (len==1)
                    return stringformat("__%02x", *p);
                else
                    return stringformat("%04x", *(uint16_t*)p);
                break;
        case DUMPUNIT_DWORD:
                --unittype;
                if (len<=2)
                    return "____"+dumponeunit(p, len, unittype);
                else
                    return dumponeunit(p+2, len-2, unittype)+dumponeunit(p, 2, unittype);
                break;
        case DUMPUNIT_QWORD:
                --unittype;
                if (len<=4)
                    return "________"+dumponeunit(p, len, unittype);
                else
                    return dumponeunit(p+4, len-4, unittype)+dumponeunit(p, 4, unittype);
                break;

    }
    return "";
}
std::string hexdumpunit(const uint8_t *buf, size_t bytelen, DumpUnitType unittype)
{
    std::string str;

    str.reserve(bytelen*3);
    for (size_t i=0 ; i<bytelen ; i+=DumpUnitSize(unittype)) {
        if (!str.empty())
            str += " ";
        str += dumponeunit(buf+i, bytelen-i, unittype);
    }

    return str;
}


std::string dumpraw(const uint8_t *buf, size_t len, size_t &usedlen)
{
    std::string str((const char*)buf, len);
    str.resize(strlen(str.c_str()));
    size_t i= str.size();
    while (i<len && buf[i]==0) i++;

    usedlen= i;

    return str;
}
// todo: add 'summarize' option, to generate 'dup' constructs.
//       [DONE]make strings more readable, by breaking on NUL.
std::string dumpstrings(const uint8_t *buf, size_t len, size_t &usedlen)
{
    std::string result;
    bool bQuoted= false;
    bool bThisIsEolChar= false;
    std::string escaped= "\n\r\t";

    size_t i;
    for (i=0 ; i<len ; i++)
    {
        bool bNeedsEscape= escaped.find((char)buf[i])!=escaped.npos 
            || buf[i]=='\"' 
            || buf[i]=='\\';

        if (isprint(buf[i]) || bNeedsEscape) {
            if (!bQuoted) {
                if (!result.empty())
                    result += ",";
                result += "\"";
                bQuoted= true;
            }
            if (bNeedsEscape) {
                std::string escapecode;
                switch(buf[i]) {
                    case '\n': escapecode= "\\n"; break;
                    case '\r': escapecode= "\\r"; break;
                    case '\t': escapecode= "\\t"; break;
                    case '\"': escapecode= "\\\""; break;
                    case '\\': escapecode= "\\\\"; break;
                    default:
                       escapecode= stringformat("\\x%02x", buf[i]);
                }
                result += escapecode;
            }
            else {
                result += (char) buf[i];
            }
        }
        else {
            if (bQuoted) {
                result += "\"";
                bQuoted= false;
            }
            if (!result.empty())
                result += ",";
            result += stringformat("%02x", buf[i]);
        }
        if (i+1<len) {
            if (i==0)
                bThisIsEolChar = (buf[i]==0x0a || buf[i]==0x0d || buf[i]==0);

            bool bNextIsEolChar= (buf[i+1]==0x0a || buf[i+1]==0x0d || buf[i+1]==0);
            if (bThisIsEolChar && !bNextIsEolChar) {
                i++;
                break;
            }
            bThisIsEolChar= bNextIsEolChar;
        }
    }

    if (bQuoted) {
        result += "\"";
        bQuoted= false;
    }

    usedlen= i;

    return result;
}
void writedumpline(int64_t llOffset, const std::string& line)
{
    if (llOffset>>32) {
        // using extra variable to work around apparent compiler bug:
        // 'low' is passed to debug in eax:edx,  with xor eax,eax  to clear high part.
        // then in debug, the low value is read from 'rdx',  but the upper part of rdx
        // was _NOT_cleared.
        uint32_t low = static_cast<uint32_t>(llOffset);
        debug("%x%08x: %s\n", static_cast<uint32_t>(llOffset>>32), low, line.c_str());
    }
    else
        debug("%08x: %s\n", static_cast<uint32_t>(llOffset), line.c_str());
}
void bighexdump(int64_t llOffset, const uint8_t *data, size_t size, uint32_t flags/*=hexdumpflags(DUMPUNIT_BYTE, 16, DUMP_HEX_ASCII)*/)
{
    DumpUnitType dumpunittype= dumpunit_from_flags(flags);
    DumpFormat dumpformat= dumpformat_from_flags(flags);
    int unitsperline= unitsperline_from_flags(flags);
    bool bWithOffset= (flags&HEXDUMP_WITH_OFFSET)!=0;
    bool bSummarize= (flags&HEXDUMP_SUMMARIZE)!=0;

    bool bLastBlock= (flags&HEXDUMP_MOREFOLLOWS)==0;

    if (unitsperline==0)
        unitsperline= 0x1000;
    size_t bytesperline= unitsperline*DumpUnitSize(dumpunittype);

    if (dumpformat==DUMP_STRINGS || dumpformat==DUMP_RAW) {
        bytesperline= size;
    }

    std::string prevline;
    int nSameCount=0;

    for (size_t i=0 ; i<size ; i+=bytesperline) {
        // not using 'min' since msvc's header files are broken, and make it
        // quite hard to include them in an order as not to redefine 'min' in
        // an inconvenient way.

        size_t len= bytesperline; if (len > size-i) len= size-i;

        std::string line;
        if (dumpformat==DUMP_STRINGS) {
            line= dumpstrings(data+i, size-i, bytesperline);
        }
        if (dumpformat==DUMP_RAW) {
            line= dumpraw(data+i, size-i, bytesperline);
        }
        if (dumpformat==DUMP_HEX_ASCII || dumpformat==DUMP_HEX) {
            line= hexdumpunit(data+i, len, dumpunittype);
            if (len < bytesperline) {
                int charsinfullline= (2*DumpUnitSize(dumpunittype)+1)*unitsperline-1;
                line.append(charsinfullline-line.size(), ' ');
            }
        }
        if (dumpformat==DUMP_HEX_ASCII || dumpformat==DUMP_ASCII)  {
            if (!line.empty())
                line += "  ";
            line += asciidump(data+i, len);
            if (len < bytesperline) {
                line.append(bytesperline-len, ' ');
            }
        }

        if (dumpformat!=DUMP_RAW && bSummarize && line == prevline) {
            nSameCount++;
        }
        else {
            if (nSameCount==1)
                writedumpline(llOffset+i-bytesperline, prevline);
            else if (nSameCount>1) {
                debug("*  [ 0x%x lines ]\n", nSameCount);
            }
            nSameCount= 0;

            if (bWithOffset)
                writedumpline(llOffset+i, line);
            else if (dumpformat==DUMP_RAW)
                debug("%s", line.c_str());
            else
                debug("%s\n", line.c_str());
        }

        prevline= line;
    }
    if (nSameCount==1)
        writedumpline(llOffset+size-bytesperline, prevline);
    else if (nSameCount>1)
        debug("*  [ 0x%x lines ]\n", nSameCount);
    if (bLastBlock && nSameCount>0)
        writedumpline(llOffset+size, "");
}

bool isSmartphone()
{
#ifdef _WIN32_WCE
    TCHAR reply[256];

    if (!SystemParametersInfo(SPI_GETPLATFORMTYPE, sizeof(reply), reply, 0))
    {
        error("SystemParametersInfo(SPI_GETPLATFORMTYPE, LPTSTR)");
        return false;
    }
    return (_tcsicmp(reply, _T("SmartPhone"))==0);
#else
    return false;
#endif
}
#ifdef WIN32
uint32_t GetOsVersion()
{
    OSVERSIONINFO oi;

    oi.dwOSVersionInfoSize= sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&oi)) {
        error("GetVersionEx");
        return 0;
    }
    return (oi.dwMajorVersion<<16) | oi.dwMinorVersion;
}
std::string GetLogRootDir()
{
    OSVERSIONINFO oi;

    oi.dwOSVersionInfoSize= sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&oi)) {
        error("GetVersionEx");
        return "";
    }
#ifdef _WIN32_WCE
        if (isSmartphone()) {
            if (oi.dwMajorVersion==3)
                // sm2002
                return "\\IPSM\\";
            else if (oi.dwMajorVersion==4)
                // wm2003
                return "\\Storage\\";
            else if (oi.dwMajorVersion==5)
                // wm2005
                return "\\";
            else
                return "\\";
        }
        else {
            // pocketpc : use root
            return "\\";
        }
#else
        // win32 : use current directory
        return ".\\";
#endif
}
#else
std::string GetLogRootDir()
{
    return "./";
}

#endif
