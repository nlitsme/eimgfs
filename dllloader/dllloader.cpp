/*
 * dllloader: library for loading windows dlls on MacOS
 *
 * Note: Since the windows dll's we are loading contain 32-bit code,
 * The entire application needs to be 32-bit.
 * This means you have to compile with -m32.
 *
 */

// todo: research how to use 32bit windows dll's from 64bit macosx

// tool which exports 3 functions:
//   LoadLibrary
//   GetProcAddress
//   FreeLibrary

#include <stdint.h>

#include <stdio.h>
#ifndef _WIN32_WCE
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#else
#define errno GetLastError()
#endif

#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include "dllloader.h"

#ifdef _WIN32_WCE
#include "kernelmisc.h"
#endif

#ifdef _MSC_VER
#define stat _stat

#ifdef _WIN32_WCE
typedef uint32_t off_t;
#define fseeko fseek
#else
#define fseeko _fseeki64
#endif

#endif
#ifdef __GNUC__
#define __stdcall __attribute__((stdcall))
#endif

#define logmsg(...)

#ifdef __MACH__
#include <sys/mman.h>
#endif

class posixerror {
public:
    posixerror(const std::string& fn, const std::string& name)
        : _err(errno), _fn(fn), _name(name)
    {
    }
    ~posixerror()
    {
        fprintf(stderr,"ERROR: %d in %s(%s)\n", _err, _fn.c_str(), _name.c_str());
    }
private:
    // note: on windows this cannot be called '_errno'
    int _err;
    std::string _fn;
    std::string _name;
};
class loadererror {
public:
    loadererror(const std::string& msg)
        : _msg(msg)
    {
    }
    ~loadererror()
    {
        fprintf(stderr,"ERROR: %s\n", _msg.c_str());
    }
private:
    std::string _msg;
};
class unimplemented {
public:
    ~unimplemented() { fprintf(stderr,"ERROR: unimplemented\n"); }
};
unsigned g_lasterror;

unsigned MyGetLastError()
{
    return g_lasterror;
}
void MySetLastError(unsigned err)
{
    g_lasterror= err;
}

struct mzheader {
    char magic[2];
    uint16_t words[29];
    uint32_t lfanew;
};
struct peheader {
    char magic[4];
    uint16_t cpu;	//The CPU type
    uint16_t objcnt;	//Number of memory objects
    uint32_t timestamp;	//Time EXE file was created/modified
    uint32_t symtaboff;	//Offset to the symbol table

    uint32_t symcount;	//Number of symbols
    uint16_t opthdrsize;	//Optional header size
    uint16_t imageflags;	//Image flags
    // here the opthdr starts.
    uint16_t coffmagic;	//Coff magic number (usually 0x10b)
    uint8_t linkmajor;	//The linker major version number
    uint8_t linkminor;	//The linker minor version number
    uint32_t codesize;	//Sum of sizes of all code sections

    uint32_t initdsize;	//Sum of all initialized data size
    uint32_t uninitdsize;	//Sum of all uninitialized data size
    uint32_t entryrva;	//rva Relative virt. addr. of entry point
    uint32_t codebase;	//rva Address of beginning of code section

    uint32_t database;	//rva Address of beginning of data section
    uint32_t vbase;	//Virtual base address of module
    uint32_t objalign;	//Object Virtual Address align. factor
    uint32_t filealign;	//Image page alignment/truncate factor

    uint16_t osmajor;	//The operating system major ver. no.
    uint16_t osminor;	//The operating system minor ver. no.
    uint16_t usermajor;	//The user major version number
    uint16_t userminor;	//The user minor version number
    uint16_t subsysmajor;	//The subsystem major version number
    uint16_t subsysminor;	//The subsystem minor version number
    uint32_t res1;	//Reserved bytes - must be 0

    uint32_t vsize;	//Virtual size of the entire image
    uint32_t hdrsize;	//Header information size
    uint32_t filechksum;	//Checksum for entire file
    uint16_t subsys;	//The subsystem type
    uint16_t dllflags;	//DLL flags

    uint32_t stackmax;	//Maximum stack size
    uint32_t stackinit;	//Initial committed stack size
    uint32_t heapmax;	//Maximum heap size
    uint32_t heapinit;	//Initial committed heap size

    uint32_t res2;	//Reserved bytes - must be 0
    uint32_t hdrextra;	//Number of extra info units in header

    // followed by 'info' records.

    // offset=((uint8_t*)(&pe->coffmagic))+pe->opthdrsize
    // followed by o32 records
};
struct pe_info {
    uint32_t offset;
    uint32_t size;
};

struct o32_header {
    char name[8];
    uint32_t vsize;
    uint32_t rva;
    uint32_t psize;
    uint32_t dataptr;
    uint32_t realaddr;  // ptr to reloc info
    uint32_t access;
    uint32_t temp3;
    uint32_t flags;
};

class posixfile {
private:
    FILE *_f;
    std::string _name;
public:
    posixfile(const std::string& name)
        : _f(NULL)
    {
        _f= fopen(name.c_str(), "rb");
        if (_f==NULL)
            throw posixerror("fopen", name);
    }
    ~posixfile()
    {
        if (_f)
            fclose(_f);
    }
    void seek(off_t o, int whence=SEEK_SET)
    {
        if (-1==fseeko(_f, o, whence))
            throw posixerror("fseek", _name);
    }
    void readexact(void *p, size_t n)
    {
        int m=fread(p, n, 1, _f);
        //fprintf(stderr,"readx %08lx: %lu bytes in %p: %d\n", ftell(_f), n, p, m);
        if (1!=m)
            throw posixerror("fread", _name);
    }
    int readmax(void *p, size_t nmax)
    {
        int m=fread(p, 1, nmax, _f);
        //fprintf(stderr,"readm %08lx: %lu bytes in %p: %d\n", ftell(_f), nmax, p, m);
        if (m<0)
            throw posixerror("fread", _name);
        return m;
    }
};

class PEFileInfo {
    struct sectioninfo {
        sectioninfo() : fileoffset(0), filesize(0), virtualaddress(0), virtualsize(0) { }
        off_t fileoffset;
        size_t filesize;
        size_t virtualaddress;
        size_t virtualsize;
    };
    struct exportsymbol {
        exportsymbol() : ordinal(0), virtualaddress(0) { }
        std::string name;
        unsigned ordinal;
        unsigned virtualaddress;
    };
    struct importsymbol {
        importsymbol() : ordinal(0), virtualaddress(0) { }
        std::string dllname;
        std::string name;
        unsigned ordinal;
        unsigned virtualaddress;
    };
    struct relocinfo {
        relocinfo() : virtualaddress(0), type(0) { }
        size_t virtualaddress;
        int type;
    };
public:
    PEFileInfo(posixfile& f)
        : _f(f), _vbase(0), _cpu(0), _entryrva(0)
    {
        f.seek(0);
        mzheader mz;
        f.readexact(&mz, sizeof(mz));
        if (mz.magic[0]!='M' || mz.magic[1]!='Z')
            throw loadererror("invalid MZ header");
        if (mz.lfanew==0)
            throw "dos exe not supported";
        // read pe header
        f.seek(mz.lfanew);
        peheader pe;
        f.readexact(&pe, sizeof(pe));

        if (pe.magic[0]!='N' && pe.magic[1]!='E')
            throw loadererror("NE exe not supported");
        if (pe.magic[0]!='P' || pe.magic[1]!='E' || pe.magic[2]!=0 || pe.magic[3]!=0)
            throw loadererror("invalid PE header");
//      if (pe.cpu!=0x14c && pe.cpu!=0x1c0 && pe.cpu!=0x1c2)
//          throw loadererror("unsupported cpu");
        _cpu= pe.cpu;
        _entryrva= pe.entryrva;
        if (pe.coffmagic==0x20b)
            throw loadererror("PE32+ optheader not supported");
        if (pe.coffmagic!=0x10b)
            throw loadererror("invalid PE32 optheader");
        std::vector<pe_info> info(pe.hdrextra>0x10 ? 0x10 : pe.hdrextra);

        _vbase= pe.vbase;
        // read info records
        f.readexact(&info[0], sizeof(pe_info)*info.size());

#define PTR_DIFF(a,b)  ((uint8_t*)(&b)-(uint8_t*)(&a))
        // read o32 records
        f.seek(mz.lfanew+pe.opthdrsize+PTR_DIFF(pe.magic, pe.coffmagic));

        std::vector<o32_header> o32(pe.objcnt);

        f.readexact(&o32[0], sizeof(o32_header)*o32.size());
        _sections.resize(pe.objcnt);
        for (unsigned i=0 ; i<pe.objcnt ; i++)
        {
            _sections[i].fileoffset = o32[i].dataptr;
            _sections[i].filesize   = o32[i].psize;
            _sections[i].virtualaddress= _vbase+o32[i].rva;
            _sections[i].virtualsize= o32[i].vsize;
        }
#ifndef _WIN32_WCE
enum {
    EXP, IMP, RES, EXC, SEC, FIX
};
#endif
        if (info[EXP].size)
            read_export_table(info[EXP].offset, info[EXP].size);
        if (info[IMP].size)
            read_import_table(info[IMP].offset, info[IMP].size);
        if (info[FIX].size)
            read_reloc_table(info[FIX].offset, info[FIX].size);
    }

    unsigned sectioncount() const
    {
        return _sections.size();
    }
    const sectioninfo& sectionitem(unsigned i) const
    {
        return _sections[i];
    }

    unsigned importcount() const
    {
        return _imports.size();
    }
    const importsymbol& importitem(unsigned i) const
    {
        return _imports[i];
    }

    unsigned exportcount() const
    {
        return _exports.size();
    }
    const exportsymbol& exportitem(unsigned i) const
    {
        return _exports[i];
    }

    unsigned reloccount() const
    {
        return _relocs.size();
    }
    const relocinfo& relocitem(unsigned i) const
    {
        return _relocs[i];
    }

    size_t minvirtaddr() const
    {
        size_t a= 0;
        for (unsigned i=0 ; i<sectioncount() ; i++)
        {
            if (i==0 || _sections[i].virtualaddress<a)
                a= _sections[i].virtualaddress;
        }
        return a;
    }
    size_t maxvirtaddr() const
    {
        size_t a= 0;
        for (unsigned i=0 ; i<sectioncount() ; i++)
        {
            uint32_t sectionend = _sections[i].virtualaddress+std::max(_sections[i].virtualsize, _sections[i].filesize);
            if (i==0 || sectionend>a)
                a= sectionend;
        }
        return a;
    }
    uint16_t cpu() const { return _cpu; }
    uint32_t entryva() const { return _vbase+_entryrva; }
private:
    std::vector<sectioninfo> _sections;
    std::vector<importsymbol> _imports;
    std::vector<exportsymbol> _exports;
    std::vector<relocinfo> _relocs;

    posixfile& _f;
    uint32_t _vbase;
    uint16_t _cpu;
    uint32_t _entryrva;

    off_t rva2fileofs(uint32_t rva)
    {
        rva += _vbase;
        for (unsigned i=0 ; i<sectioncount() ; i++)
        {
            if (_sections[i].virtualaddress<=rva && rva<_sections[i].virtualaddress+_sections[i].virtualsize)
                return rva-_sections[i].virtualaddress+_sections[i].fileoffset;
        }
        fprintf(stderr,"ERROR:invalid offset 0x%x requested\n", rva);
        throw loadererror("invalid offset");
    }

    struct export_header {
        uint32_t flags;	// Export table flags, must be 0
        uint32_t timestamp;	// Time export data created
        uint16_t vermajor;	// Major version stamp
        uint16_t verminor;	// Minor version stamp
        uint32_t rva_dllname;	// [rva] Offset to the DLL name
        uint32_t ordbase;	// First valid ordinal
        uint32_t eatcnt;	// Number of EAT entries
        uint32_t namecnt;	// Number of exported names
        uint32_t rva_eat;	// [rva] Export Address Table offset
                                // first ordinal = ordbase
                                // size = eatcnt
        uint32_t rva_name;	// [rva] Export name pointers table off
                                // size = namecnt
        uint32_t rva_ordinal;	// [rva] Export ordinals table offset
                                // size = namecnt
    };
    template<typename T>
    void read_until_zero(uint32_t rva, std::vector<T>&v)
    {
        _f.seek(rva2fileofs(rva));
        int n=0;
        const unsigned chunksize= 256;
        do {
            v.resize(v.size()+chunksize);
            int sizeread= _f.readmax(&v.back()-chunksize+1, sizeof(T)*chunksize);
            n= sizeread/sizeof(T);
            v.resize(v.size()-chunksize+n);
            for (typename std::vector<T>::iterator i=v.end()-n ; i<v.end() ; i++) {
                if (*i==0) {
                    v.resize(i-v.begin());
                    return;
                }
            }
        } while (n>0);
    }

    std::string readstring(uint32_t rva)
    {
        std::vector<char> str;
        read_until_zero(rva, str);
        return std::string(str.begin(), str.end());
    }
    void read_export_table(uint32_t rva, uint32_t size)
    {
        _f.seek(rva2fileofs(rva));
        export_header exphdr;
        _f.readexact(&exphdr, sizeof(exphdr));

        // read export address table
        // entries: if in EXP area : forwarder string
        //          else : exported address
        std::vector<uint32_t> eatlist(exphdr.eatcnt);
        if (exphdr.eatcnt) {
            _f.seek(rva2fileofs(exphdr.rva_eat));
            _f.readexact(&eatlist[0], sizeof(uint32_t)*eatlist.size());
        }

        // read export name ptr table
        std::vector<uint32_t> entlist(exphdr.namecnt);
        if (exphdr.namecnt) {
            _f.seek(rva2fileofs(exphdr.rva_name));
            _f.readexact(&entlist[0], sizeof(uint32_t)*entlist.size());
        }

        // read export ordinal table
        std::vector<uint16_t> eotlist(exphdr.namecnt);
        if (exphdr.namecnt) {
            _f.seek(rva2fileofs(exphdr.rva_ordinal));
            _f.readexact(&eotlist[0], sizeof(uint16_t)*eotlist.size());
        }
        //fprintf(stderr,"read eot from %08lx: %d entries\n", exphdr.rva_ordinal, eotlist.size());

        //fprintf(stderr,"dllname=%s\n", readstring(exphdr.rva_dllname).c_str());

        _exports.resize(eatlist.size());
        for (unsigned i=0 ; i<eatlist.size() ; i++)
        {
            _exports[i].ordinal= i+exphdr.ordbase;
            if (eatlist[i]>=rva && eatlist[i]<rva+size) {
                // todo: handle forward
            }
            else {
                _exports[i].virtualaddress= _vbase+eatlist[i];
            }
        }
        for (unsigned i=0 ; i<entlist.size() ; i++)
        {
            if (eotlist[i]>=_exports.size()) {
                _exports.resize(eotlist[i]+1);
                _exports[eotlist[i]].ordinal= eotlist[i]+exphdr.ordbase;
            }
            _exports[eotlist[i]].name= readstring(entlist[i]);
        }
    }
struct import_header {
    uint32_t rva_lookup;
    uint32_t timestamp;
    uint32_t forwarder;
    uint32_t rva_dllname;
    uint32_t rva_address;
};
    bool isnull(import_header& h)
    {
        return h.rva_lookup==0 && h.timestamp==0 && h.forwarder==0 && h.rva_dllname==0 && h.rva_address==0;
    }
    void read_import_table(uint32_t rva, uint32_t size)
    {

        // read import directory
        for (int nimp=0 ; true ; nimp++) {
            import_header imphdr;
            _f.seek(rva2fileofs(rva)+sizeof(imphdr)*nimp);
            _f.readexact(&imphdr, sizeof(imphdr));
            if (isnull(imphdr))
                break;
            std::vector<uint32_t> ilt;
            // packed executables often have rva_lookup==0
            read_until_zero(imphdr.rva_lookup ? imphdr.rva_lookup : imphdr.rva_address, ilt);

            std::string impdllname;
            impdllname= readstring(imphdr.rva_dllname);

            for (unsigned i=0 ; i<ilt.size() ; i++)
            {
                importsymbol sym;
                sym.dllname= impdllname;
                sym.virtualaddress= _vbase+imphdr.rva_address+4*i;
                if (ilt[i]&0x80000000) {
                    sym.ordinal= ilt[i]&0x7fffffff;
                }
                else {
                    // todo: handle 'hint'
                    sym.name= readstring(ilt[i]+2);
                }

                _imports.push_back(sym);
            }
        }
    }
    void read_reloc_table(uint32_t rva, uint32_t size)
    {
        _f.seek(rva2fileofs(rva));
        uint32_t roff= rva;
        while (roff<rva+size)
        {
            struct relochdr {
                uint32_t page_rva;
                uint32_t size;
            };
            relochdr hdr;
            _f.readexact(&hdr, sizeof(hdr));

            std::vector<uint16_t> relocs((hdr.size-sizeof(hdr))/sizeof(uint16_t));
            if (relocs.size())
                _f.readexact(&relocs[0], hdr.size-sizeof(hdr));
            
            for (unsigned i=0 ; i<relocs.size() ; i++)
            {
                relocinfo r;
                r.virtualaddress= _vbase+hdr.page_rva+(relocs[i]&0xfff);
                r.type= relocs[i]>>12;
                _relocs.push_back(r);
            }
            roff += hdr.size;
        }
    }
};
typedef std::map<std::string,void*> name2ptrmap;
typedef std::map<uint32_t,void*> ord2ptrmap;
typedef std::vector<uint8_t> ByteVector;


typedef bool (*DLLENTRYPOINT)(HANDLE HMODULE, DWORD reason, void* reserved);

class DllModule {
private:
    posixfile _f;
    PEFileInfo _pe;
    uint32_t _baseaddr;
    uint32_t _base_va;
public:
    DllModule(const std::string& dllname, bool bRelocate)
        : _f(dllname), _pe(_f), _baseaddr(0)
    {
        _baseaddr= _pe.minvirtaddr();
        _base_va= _pe.minvirtaddr();
        load_sections();
        if (bRelocate) {
            relocate(reinterpret_cast<uint32_t>(&_data[0]));
            import();
        }
    }
    ~DllModule()
    {
    }
    void load_sections()
    {
        _data.resize(_pe.maxvirtaddr()-_pe.minvirtaddr());
        logmsg("dll:va range: %08lx - %08lx\n", _pe.minvirtaddr(), _pe.maxvirtaddr());
        // load sections
        for (unsigned i=0 ; i<_pe.sectioncount() ; i++)
        {
            logmsg("dll:loading %d: file:%08x:%08lx  va:%08lx, ofs:%08lx\n",
                    i, uint32_t(_pe.sectionitem(i).fileoffset), _pe.sectionitem(i).filesize,
                    _pe.sectionitem(i).virtualaddress, _pe.sectionitem(i).virtualaddress-_base_va);
            if (_pe.sectionitem(i).filesize) {
                _f.seek(_pe.sectionitem(i).fileoffset);
                _f.readexact(&_data[_pe.sectionitem(i).virtualaddress-_base_va], _pe.sectionitem(i).filesize);
            }
        }

        // process exports 
        for (unsigned i=0 ; i<_pe.exportcount() ; i++)
        {
            if (_pe.exportitem(i).name.empty())
                _exportsbyordinal[_pe.exportitem(i).ordinal]= &_data[_pe.exportitem(i).virtualaddress-_base_va];
            else
                _exportsbyname[_pe.exportitem(i).name]= &_data[_pe.exportitem(i).virtualaddress-_base_va];
            logmsg("dll:exp %d %08x ord %4d %s\n", i, _pe.exportitem(i).virtualaddress, _pe.exportitem(i).ordinal, _pe.exportitem(i).name.c_str());
        }

        // process imports
        for (unsigned i=0 ; i<_pe.importcount() ; i++)
        {
            logmsg("dll:import %d: %08x: ord %4d %s %s\n", i, _pe.importitem(i).virtualaddress, _pe.importitem(i).ordinal, _pe.importitem(i).dllname.c_str(), _pe.importitem(i).name.c_str());
        }
        // relocate
        logmsg("dll:%d relocs\n", _pe.reloccount());
        for (unsigned i=0 ; i<_pe.reloccount() ; i++)
        {
           // fprintf(stderr,"reloc %d: %08lx %d\n", i, _pe.relocitem(i).virtualaddress, _pe.relocitem(i).type);
        }
#ifdef __MACH__ 
#if MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_7

#define PAGE_MASK 0xFFF
        // make executable
        uint32_t dataaddr= (uint32_t)&_data[0];
        uint32_t pageofs0= dataaddr&PAGE_MASK;
        uint32_t pageofs1= (dataaddr+_data.size()+pageofs0)&PAGE_MASK;
        if (pageofs1)
            pageofs1= 0x1000-pageofs1;
        int rc= mprotect(&_data[0]-pageofs0, _data.size()+pageofs0+pageofs1, PROT_EXEC|PROT_READ|PROT_WRITE);
        if (rc) {
            printf("mprotect(%d)  %p:%08x -> %p:%08x\n", errno,
                    &_data[0], (int)_data.size(),
                    &_data[0]-pageofs0, (int)(_data.size()+pageofs0+pageofs1));
        }
#endif
#endif
    }

    // fixup types
#define IMAGE_REL_BASED_ABSOLUTE        0
#define IMAGE_REL_BASED_HIGH            1
#define IMAGE_REL_BASED_LOW             2
#define IMAGE_REL_BASED_HIGHLOW         3
#define IMAGE_REL_BASED_HIGHADJ         4
#define IMAGE_REL_BASED_MIPS_JMPADDR    5
#define IMAGE_REL_BASED_SECTION         6
#define IMAGE_REL_BASED_REL32           7
#define IMAGE_REL_BASED_MIPS_JMPADDR16  9
#define IMAGE_REL_BASED_IA64_IMM64      9
#define IMAGE_REL_BASED_DIR64          10
#define IMAGE_REL_BASED_HIGH3ADJ       11

    void relocate(uint32_t target)
    {
        uint32_t delta= target-_baseaddr;

        logmsg("dll:%08x: <", delta);
        // relocate
        for (unsigned i=0 ; i<_pe.reloccount() ; i++)
        {
            //fprintf(stderr,"relocating %08lx: %08x\n", _pe.relocitem(i).virtualaddress, *(uint32_t*)&_data[_pe.relocitem(i).virtualaddress-_base_va]);
            uint8_t *p= &_data[_pe.relocitem(i).virtualaddress-_base_va];
            switch(_pe.relocitem(i).type)
            {
                case IMAGE_REL_BASED_ABSOLUTE:   logmsg("A"); break;
                case IMAGE_REL_BASED_HIGH:       *(uint16_t*)p += delta>>16;    logmsg("H"); break;
                case IMAGE_REL_BASED_LOW:        *(uint16_t*)p += delta&0xFFFF; logmsg("L"); break;
                case IMAGE_REL_BASED_HIGHLOW:    *(uint32_t*)p += delta;        logmsg("-"); break;
                case IMAGE_REL_BASED_HIGHADJ:      throw unimplemented(); // ?? ... have to re-read description
                default:
                   fprintf(stderr,"ERROR: unhandled fixup type %d\n", _pe.relocitem(i).type);
                   throw unimplemented();
            }
        }
        _baseaddr= target;
        logmsg(">\n");

    }

#ifndef _WIN32
#define ALIGN_STACK  __attribute__((force_align_arg_pointer))
#else
#define ALIGN_STACK
#endif
#ifndef _WIN32_WCE
    static void undefined() ALIGN_STACK { fprintf(stderr,"unimported\n"); }
    static void *__stdcall LocalAlloc(int flag, int size) ALIGN_STACK { return malloc(size); }
    static void *__stdcall LocalFree(void *p) ALIGN_STACK { free(p); return NULL; }
    static void __stdcall SetLastError(uint32_t e) ALIGN_STACK { }
    static bool __stdcall DisableThreadLibraryCalls(void *hmod) ALIGN_STACK { return true; }
    static void dummy() ALIGN_STACK { }

    static void *alignedmalloc(int size) ALIGN_STACK { return malloc(size); }
    static void alignedfree(void *p) ALIGN_STACK { free(p); }
#endif
    void import()
    {
        for (unsigned i=0 ; i<_pe.importcount() ; i++)
        {
// DisableThreadLibraryCalls
// SetLastError
// __CppXcptFilter
// __dllonexit
// _adjust_fdiv
// _assert
// _except_handler3
// _initterm
// _onexit

            uint32_t *p= (uint32_t*)&_data[_pe.importitem(i).virtualaddress-_base_va];
#ifndef _WIN32_WCE
            // todo: add importer object, which knows where to find external functions
            if (_pe.importitem(i).name=="LocalAlloc") *p=(uint32_t)LocalAlloc;
            else if (_pe.importitem(i).name=="LocalFree") *p=(uint32_t)LocalFree;
            else if (_pe.importitem(i).name=="DisableThreadLibraryCalls") *p=(uint32_t)DisableThreadLibraryCalls;
            else if (_pe.importitem(i).name=="SetLastError") *p=(uint32_t)SetLastError;
            else if (_pe.importitem(i).name=="malloc") *p=(uint32_t)alignedmalloc;
            else if (_pe.importitem(i).name=="free") *p=(uint32_t)alignedfree;
            else if (_pe.importitem(i).name=="_adjust_fdiv") *p=(uint32_t)undefined;
            else *p=(uint32_t)dummy;
#else
            // ... replace some imports with kernel variants
#endif
            logmsg("dll:import %d: %08x:=%08x   ord %4d %s %s\n", i, _pe.importitem(i).virtualaddress, *p, _pe.importitem(i).ordinal, _pe.importitem(i).dllname.c_str(), _pe.importitem(i).name.c_str());
        }
    }
    void *getprocbyname(const char *procname) const
    {
        name2ptrmap::const_iterator i= _exportsbyname.find(procname);
        if (i==_exportsbyname.end()) {
            MySetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }
        return TranslateAddress((*i).second);
    }
    void *getprocbyordinal(unsigned ord) const
    {
        ord2ptrmap::const_iterator i= _exportsbyordinal.find(ord);
        if (i==_exportsbyordinal.end()) {
            MySetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }
        return TranslateAddress((*i).second);
    }

    void *TranslateAddress(const void*p) const
    {
        return reinterpret_cast<void*>(
                reinterpret_cast<uint32_t>(p)
                -reinterpret_cast<uint32_t>(&_data[0])
                +_baseaddr
                );
    }
    size_t size() const { return _data.size(); }
    const uint8_t* data() const { return &_data[0]; }

    DLLENTRYPOINT getentrypoint() const
    {
        logmsg("getep: eva=%08lx base=%08lx data=%08lx\n", _pe.entryva(), _base_va, &_data[_pe.entryva()-_base_va]);
        return reinterpret_cast<DLLENTRYPOINT>(TranslateAddress(&_data[_pe.entryva()-_base_va]));
    }
private:
    name2ptrmap _exportsbyname;
    ord2ptrmap _exportsbyordinal;
    ByteVector _data;
};
#ifndef _WIN32_WCE
bool fileexists(const std::string& path)
{
    struct stat st;
    if (-1==stat(path.c_str(), &st)) {
        if (errno==ENOENT)
            return false;
        throw posixerror("stat", path);
    }

    return (st.st_mode&S_IFMT)==S_IFREG;
}
#endif
std::string find_dll(const std::string& name)
{
#ifndef _WIN32_WCE
    if (fileexists(name))
        return name;
    std::string searchpath= getenv("PATH");
    char sepchar= (searchpath.find(';')!=searchpath.npos) ? ';' : ':';

    for (size_t i=searchpath.find(sepchar), j=0 ; j!=searchpath.npos ; j=i, i=searchpath.find(sepchar, i+1))
    {
        std::string path=searchpath.substr(j==0?0:j+1, (i==searchpath.npos || j==0)? i : i-j-1);
        logmsg("dll:searching %s\n", path.c_str());
        if (fileexists(path+"/"+name))
            return path+"/"+name;
    }
    throw loadererror("not found");
#else
    return (name[0]=='/' || name[0]=='\\')?name: std::string("\\windows\\")+name;
#endif
}
HMODULE MyLoadLibrary(const char*dllname)
{
    try {
        std::string dllfilename= find_dll(dllname);
        logmsg("dll:loading %s\n", dllfilename.c_str());
        DllModule *dll= new DllModule(dllfilename, true);

//      DLLENTRYPOINT ep= dll->getentrypoint();
//      logmsg("loadlib: entrypoint=%08lx\n", ep);
//      ep(reinterpret_cast<HMODULE>(dll), 0, 0);

        return reinterpret_cast<HMODULE>(dll);
    }
    catch(...)
    {
        MySetLastError(ERROR_MOD_NOT_FOUND);
        return NULL;
    }
}
#ifdef _WIN32_WCE

#define AllocPhysMem (*(LPVOID (*)(DWORD cbSize, DWORD fdwProtect, DWORD dwAlignmentMask, DWORD dwFlags, PULONG pPhysicalAddress))0xf000fd60)
HMODULE MyLoadKernelLibrary(const char*dllname)
{
    try {
        std::string dllfilename= find_dll(dllname);
        logmsg("dll:loading %s\n", dllfilename.c_str());
        DllModule *dll= new DllModule(dllfilename, false);

        DWORD physaddr=0;
        void *vptr= AllocPhysMem(dll->size(), PAGE_EXECUTE_READWRITE, 0, 0, &physaddr);
        if (vptr==NULL) {
            MySetLastError(ERROR_OUTOFMEMORY);
            delete dll;
            return NULL;
        }
        logmsg("klib: relocating to %08lx / phys %08lx\n", vptr, physaddr);
        dll->relocate(PhysToVirt(physaddr));
//        dll->import();

        memcpy(vptr, dll->data(), dll->size());

        DLLENTRYPOINT ep= dll->getentrypoint();
        logmsg("klib: entrypoint=%08lx\n", ep);
        // todo: 3rd param should be kernellibiocontrol
        ep(reinterpret_cast<HMODULE>(dll), 0, 0);

        return reinterpret_cast<HMODULE>(dll);
    }
    catch(...)
    {
        MySetLastError(ERROR_MOD_NOT_FOUND);
        return NULL;
    }
}
#endif

FARPROC MyGetProcAddress(HMODULE hModule, const char*procname)
{
    DllModule *dll= reinterpret_cast<DllModule*>(hModule);
    if (dll==NULL) {
        MySetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    unsigned ord= reinterpret_cast<unsigned>(procname);
    // note: in windows land, pointers are always >=0x11000, not so in the rest of the world.
    // so this method of passing either a string, or a 16bit int does not work properly everywhere.
    if (ord<0x1000)
        return (FARPROC)dll->getprocbyordinal(ord);
    return (FARPROC)dll->getprocbyname(procname);
}

bool MyFreeLibrary(HMODULE hModule)
{
    DllModule *dll= reinterpret_cast<DllModule*>(hModule);
    if (dll==NULL) {
        MySetLastError(ERROR_INVALID_HANDLE);
        return false;
    }
    try {
        delete dll;
        return true;
    }
    catch(...)
    {
        MySetLastError(ERROR_GEN_FAILURE);
        return false;
    }
}
