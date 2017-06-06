#ifndef __DLLLOADER__H__
#define __DLLLOADER__H__

#include <util/wintypes.h>
#ifndef _WIN32
typedef uint32_t HANDLE;
typedef uint32_t HMODULE;
typedef uint32_t DWORD;
typedef int (*FARPROC)();
typedef uint8_t   BYTE;
typedef uint8_t*LPBYTE;
typedef uint16_t WORD;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef void VOID;
#endif

#define NULLMODULE  HMODULE(0)


#ifdef __cplusplus
extern "C" {
#endif
HMODULE MyLoadLibrary(const char*dllname);
#ifdef _WIN32_WCE
HMODULE MyLoadKernelLibrary(const char*dllname);
#endif
FARPROC MyGetProcAddress(HMODULE hModule, const char*procname);
bool MyFreeLibrary(HMODULE hModule);

#define ERROR_INVALID_HANDLE             6L
#define ERROR_GEN_FAILURE                31L
#define ERROR_MOD_NOT_FOUND              126L
#define ERROR_PROC_NOT_FOUND             127L
void MySetLastError(unsigned err);
unsigned MyGetLastError();

#ifdef __cplusplus
}
#endif

#ifndef _WIN32
#define LoadLibrary MyLoadLibrary
#define LoadKernelLibrary MyLoadKernelLibrary
#define GetProcAddress MyGetProcAddress
#define FreeLibrary MyFreeLibrary
#define SetLastError MySetLastError
#define GetLastError MyGetLastError
#endif


#endif
