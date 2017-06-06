/* Copyright 2005 xda-developers.com
 * All Rights Reserved
 *
 *  $Header$
 *
 */
#ifndef __FILEFUNCTIONS_H__

#include "vectorutils.h"
#include "stringutils.h"
#include "debug.h"
#include <string>
#ifndef _WIN32
#include <sys/stat.h>
#include <stdio.h>
#include <dirent.h>
typedef FILE* FFHANDLE;
#else
typedef HANDLE FFHANDLE;
#endif

template<typename T>
bool WriteFileData(const std::basic_string<T>& filename, const ByteVector& data)
{
    FFHANDLE h;
    if (!OpenFileForWriting(filename, h))
        return false;
#ifdef _WIN32
    DWORD wrote;
    if (data.size() && !WriteFile(h, &data[0], data.size(), &wrote, NULL))
    {
        CloseHandle(h);
        return false;
    }
    if (!CloseHandle(h))
    {
        error("WriteFileData: CloseHandle");
        return false;
    }

    return true;
#else
    if (data.size() && 1!=fwrite(&data[0], data.size(), 1, h)) {
        fclose(h);
        error("fwrite");
        return false;
    }
    if (fclose(h)) {
        error("fclose");
        return false;
    }
    return true;
#endif
}

template<typename T>
uint64_t GetFileSize(const std::basic_string<T>& path)
{
#ifdef _WIN32
    // "[A-Za-z]:"
    if (path.size()==2 && path[1]==':' && isalpha(path[0]))
        return AT_ISDIRECTORY;
    // "[A-Za-z]:[/\\]"
    if (path.size()==3 && (path[2]=='/' || path[2]=='\\') && path[1]==':' && isalpha(path[0]))
        return AT_ISDIRECTORY;
    WIN32_FIND_DATA wfd;
    FFHANDLE hFind = FindFirstFile( ToTString(path).c_str(), &wfd);
    if (INVALID_HANDLE_VALUE == hFind)
        return -1;

    FindClose( hFind);

    if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return -1;

    return (uint64_t(wfd.nFileSizeHigh)<<32) | wfd.nFileSizeLow;
#else
    struct stat st;
    if (stat(ToString(path).c_str(), &st))
        return -1;
    switch (st.st_mode&S_IFMT)
    {
        case S_IFDIR:
            return -1;
        case S_IFIFO:
        case S_IFSOCK:
            return -1;
    }

    return st.st_size;
#endif

}
// returns 64bit filepos, or -1
inline uint64_t GetFileSize(FFHANDLE h)
{
#ifdef _WIN32
    DWORD fsHigh;
    DWORD fsLow= GetFileSize(h, &fsHigh);
    if (fsLow==INVALID_FILE_SIZE && GetLastError())
        return uint64_t(-1);
    return ((uint64_t)fsHigh<<32)|(uint64_t)fsLow;
#else
    fpos_t orgpos;
    if (fgetpos(h, &orgpos)) {
        error("fgetpos");
        return uint64_t(-1);
    }
    if (fseeko(h, 0, SEEK_END)) {
        error("fseek");
        return uint64_t(-1);
    }
    off_t eofoff= ftello(h);
    if (eofoff==off_t(-1)) {
        error("ftello");
        return uint64_t(-1);
    }
    if (fsetpos(h, &orgpos)) {
        error("fseek");
        return uint64_t(-1);
    }
    return eofoff;
#endif
}
template<typename T, typename V>
bool LoadFileData(const std::basic_string<T>& filename, V& data, uint64_t off=0, size_t size=size_t(-1))
{
    FFHANDLE h;
    if (!OpenFileForReading(filename, h))
        return false;
#ifdef _WIN32
    DWORD fsHigh;
    DWORD fsLow= GetFileSize(h, &fsHigh);
    uint64_t eofpos=((uint64_t)fsHigh<<32)|(uint64_t)fsLow;

    if (off>eofpos) {
        debug("offset too large ( > 0x%Lx )\n", eofpos);
        CloseHandle(h);
        return false;
    }
    if (size==size_t(-1))
        size= size_t(eofpos-off);
    else if (size>size_t(eofpos-off))
        size= size_t(eofpos-off);
    data.resize(size/sizeof(V::value_type));

    LONG offHigh= LONG(off>>32);
    LONG offLow= LONG(off&0xFFFFFFFF);
    DWORD res= SetFilePointer(h, offLow, &offHigh, FILE_BEGIN);
    if (res==INVALID_SET_FILE_POINTER && GetLastError()!=NO_ERROR)
    {
        error("LoadFileData: invalid offset %x%08lx\n", offHigh, offLow);
        CloseHandle(h);
        return false;
    }

    DWORD read=0;
    if (!data.empty() && !ReadFile(h, &data[0], data.size()*sizeof(V::value_type), &read, NULL))
    {
        CloseHandle(h);
        return false;
    }
    data.resize(read/sizeof(V::value_type));
    if (!CloseHandle(h))
    {
        error("LoadFileData: CloseHandle");
        return false;
    }

#else
    if (fseeko(h, 0, SEEK_END)) {
        error("fseek");
        return false;
    }
    uint64_t eofpos= ftello(h);;
//  if (fgetpos(h, &eofpos)) {
//      error("fgetpos");
//      return false;
//  }
    if (off>eofpos) {
        debug("offset too large ( > 0x%Lx )\n", eofpos);
        fclose(h);
        return false;
    }
    if (fseeko(h, off, SEEK_SET)) {
        error("fseek");
        fclose(h);
        return false;
    }
    if (size==size_t(-1))
        size= eofpos-off;
    else if (size>size_t(eofpos-off))
        size= eofpos-off;
    data.resize(size/sizeof(typename V::value_type));
    if (!data.empty() && 1!=fread(&data[0], data.size()*sizeof(typename V::value_type), 1, h)) {
        fclose(h);
        error("fread");
        return false;
    }
    if (fclose(h)) {
        error("fclose");
        return false;
    }
#endif
    return true;
}
template<typename T>
bool LoadFileData(const T* filename, ByteVector& data, uint64_t off=0, size_t size=size_t(-1))
{
    return LoadFileData(std::basic_string<T>(filename), data, off, size);
}
bool ReadDword(FFHANDLE f, uint32_t &w);
bool ReadData(FFHANDLE f, ByteVector& data, size_t size=size_t(~0));
bool WriteData(FFHANDLE f, const ByteVector& data);
bool WriteDword(FFHANDLE f, uint32_t w);

#define AT_NONEXISTANT      1
#define AT_ISDIRECTORY      2
#define AT_ISFILE           3
#define AT_ISSTREAM         4

template<typename T>
int GetFileInfo(const std::basic_string<T>& path)
{
#ifdef _WIN32
    // "[A-Za-z]:"
    if (path.size()==2 && path[1]==':' && isalpha(path[0]))
        return AT_ISDIRECTORY;
    // "[A-Za-z]:[/\\]"
    if (path.size()==3 && (path[2]=='/' || path[2]=='\\') && path[1]==':' && isalpha(path[0]))
        return AT_ISDIRECTORY;
    WIN32_FIND_DATA wfd;
    FFHANDLE hFind = FindFirstFile( ToTString(path).c_str(), &wfd);
    if (INVALID_HANDLE_VALUE == hFind)
        return AT_NONEXISTANT;

    FindClose( hFind);

    if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return AT_ISDIRECTORY;

    return AT_ISFILE;
#else
    struct stat st;
    if (stat(ToString(path).c_str(), &st))
        return AT_NONEXISTANT;
    switch (st.st_mode&S_IFMT)
    {
        case S_IFDIR:
            return AT_ISDIRECTORY;
        case S_IFIFO:
        case S_IFSOCK:
            return AT_ISSTREAM;
    }

    return AT_ISFILE;
#endif
}

template<typename T>
bool CreateDirectory(const std::basic_string<T>& dirname)
{
#ifdef _WIN32
    if (!CreateDirectory(ToTString(dirname).c_str(), NULL))
        return false;
#else
    if (mkdir(ToString(dirname).c_str(), 0755))
        return false;
#endif
    return true;
}
template<typename T>
bool CreateDirPath(const T* path)
{
    return CreateDirPath(std::basic_string<T>(path));
}
template<typename T>
bool CreateDirPath(const std::basic_string<T>& dirname)
{
    T slashes[3]= { '\\', '/', 0};
    for (size_t i= dirname.find_first_of(slashes, 1) ; i!=dirname.npos ; i= dirname.find_first_of(slashes, i+1)) {
        std::basic_string<T> partialpath= dirname.substr(0, i);
        if (GetFileInfo(partialpath)==AT_NONEXISTANT
            && !CreateDirectory(partialpath)) {
            error("CreateDirectory([%d]%ls)", i, partialpath.c_str());
            return false;
        }
    }
    if (dirname.size()>1 && !CreateDirectory(dirname)) {
        error("CreateDirectory(%s)", dirname.c_str());
        return false;
    }
    return true;
}

// helper for dir_iterator
inline bool dont_recurse_dirs(const std::string& filename) { return false; }
inline bool do_recurse_dirs(const std::string& filename) { return true; }

// enumerate files and directories,
// void f(full_file_name)
// d(full_dir_name)  -> true -> recurse
//
// pass dont_recurse_dirs when you don't want to recurse
template<typename F, typename D>
bool dir_iterator(const std::string& path, F f, D d)
{
#ifdef _WIN32
    WIN32_FIND_DATA wfd;
    FFHANDLE hFind = FindFirstFile(ToTString(path+"\\*.*").c_str(), &wfd);
    if (INVALID_HANDLE_VALUE == hFind) {
        if (GetLastError()==ERROR_NO_MORE_FILES)
            return true;
        return false;
    }
    do {
        std::string entryname= ToString(wfd.cFileName);
        std::string fullname= path +"/" + entryname;
        if (!(wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            f(fullname);
        }
        else if (entryname=="." || entryname=="..")
            continue;
        else if (d(fullname)) {
            dir_iterator(fullname, f, d);
        }
    } while (FindNextFile(hFind, &wfd));
    FindClose(hFind);
#else
    DIR* dirp= opendir(path.c_str());
    if (dirp==NULL)
        return false;
    struct dirent *dp;
    while ((dp=readdir(dirp))!=NULL) {
        std::string name= dp->d_name;
        if (name=="." || name=="..")
            continue;
        std::string fullname= path+"/"+name;
        if (dp->d_type==DT_DIR && d(fullname)) {
            dir_iterator(fullname, f, d);
        }
        else if (dp->d_type==DT_REG)
            f(fullname);
        else {
            // not following symlinks
            // not handling devices/pipes
        }
    }
    closedir(dirp);
#endif
    return true;
}

template<typename T>
bool OpenFileForReading(const std::basic_string<T>& filename, FFHANDLE& handle)
{
#ifdef _WIN32
    FFHANDLE h= CreateFile(ToTString(filename).c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h==INVALID_HANDLE_VALUE || h==NULL)
    {
        error("CreateFile(%ls, READ)", filename.c_str());
        return false;
    }
    handle= h;

#else
    FILE *f= fopen(ToString(filename).c_str(), "r");
    if (f==NULL) {
        error("fopen(%s)", ToString(filename).c_str());
        return false;
    }
    handle= f;
#endif
    return true;
}
template<typename T>
bool OpenFileForWriting(const std::basic_string<T>& filename, FFHANDLE& handle)
{
#ifdef _WIN32
    FFHANDLE h= CreateFile(ToTString(filename).c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h==INVALID_HANDLE_VALUE || h==NULL)
    {
        error("CreateFile(%ls, WRITE)", filename.c_str());
        return false;
    }
    handle= h;
#else
    FILE *f= fopen(ToString(filename).c_str(), "w+");
    if (f==NULL) {
        error("fopen(%s)", ToString(filename).c_str());
        return false;
    }
    handle= f;
#endif
    return true;
}
template<typename T>
bool DeleteFile(const std::basic_string<T>& filename)
{
#ifdef _WIN32
    if (!DeleteFile(ToTString(filename).c_str())) {
        error("DeleteFile");
        return false;
    }
#else
    if (unlink(ToString(filename).c_str())) {
        error("unlink");
        return false;
    }
#endif
    return true;
}

inline void CloseFile(FFHANDLE h)
{
#ifdef _WIN32
    CloseHandle(h);
#else
    fclose(h);
#endif
}

uint64_t GetFilesystemFreeSpace(const std::string& path);

template<typename T>
bool is_absolute_path(const T& path)
{
    const typename T::value_type slash= '/';
    const typename T::value_type bslash= '\\';
    const typename T::value_type colon= ':';
    return (path.size() && (path[0]==slash || path[0]==bslash ))
       || (path.size()>1 && path[1]==colon);
}
template<typename T>
void trailingslash(T& path)
{
    const typename T::value_type slash= '/';
    const typename T::value_type bslash= '\\';
    const typename T::value_type separator= path.rfind(bslash)!=-1 ? bslash : slash;

    if (!path.empty() && path[path.size()-1]!=separator) {
        path += separator;
    }
}
template<typename T>
void notrailingslash(T& path)
{
    const typename T::value_type slash= '/';
    const typename T::value_type bslash= '\\';
    while (!path.empty() && (path[path.size()-1]==slash || path[path.size()-1]==bslash))
        path.resize(path.size()-1);
}

#define __FILEFUNCTIONS_H__
#endif

