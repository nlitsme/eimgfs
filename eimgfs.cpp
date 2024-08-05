#include <stdint.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <algorithm>  // max_element
#include <numeric>    // accumulate
#include <sys/stat.h>
#include <ctime>

#include "err/posix.h"
#include "stringutils.h"
#include "FileFunctions.h"
#include <memory>

#ifndef _NO_COMPRESS
#include "lzxxpr_convert.h"
#include "win32compress_link.h"
#include "rom34_convert.h"
#endif
#ifdef _WIN32
#include <io.h>
#endif
#ifndef _WIN32
#define _strtoi64 strtoll
#endif
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "util/ReadWriter.h"
#include "util/endianutil.h"
#include "util/rw/FileReader.h"
#include "util/rw/MmapReader.h"
#include "util/rw/OffsetReader.h"
#include "util/rw/CheckedOffsetReader.h"
#include "util/rw/RangeReader.h"
#include "util/rw/ByteVectorWriter.h"
#include "util/rw/ByteVectorReader.h"
#include "allocmap.h"
#include "args.h"


template<typename BYTEITER> inline std::string getstr(BYTEITER p, size_t maxbytes)
{
    // note: not handling utf conversions
    std::string str;
    unsigned i= 0;

    while (i++<maxbytes) {
        typename std::iterator_traits<BYTEITER>::value_type c= *p++;
        if (!c)
            break;
        str.push_back(c);
    }

    return str;
}

#ifndef _WIN32
typedef uint16_t WCHAR;
#endif
// todo: D000FF ( unsigned nbh ) support
// todo: add FLPART support ( wp7 file format )

// todo: add option to find key for .nbh, given directory with .pvk, .cer, .pem etc files
// todo: add option to patch offsets in a specific reader
// done: add support to extract only xip1, xip2, or imgfs
// done: add support for broken imgfs files - search for dirents by pattern, and try to read despite missing chunks
// todo:  add CAB reader, which can read a nbh directly from a CAB  embedded in an .exe file
// todo: add option to edit/dump a (compressed) indexed data stream
// todo: FFFBFFFDReader: the 0x80 offset should be obtained from the file
// todo: NbhReadWriter : keep track of changed blocks, only recalc sig of those blocks
// done: XipFile : create allocation map
// done: XipFile : implement addfile, renamefile, delfile
// done: rethink action list -> now perform takes rdlist + fslist
//
// todo: need to sort B000FF blocks by blockofs at fileclose
// done: need to write FFFBFFFD sectornrs when writing beyond end
// todo: bug in FFFBFFFDReader, where first allocated block does not get a blocknr
// todo: fix problem reading unallocated fffbfffd secions - now reading the full partition results in truncated reads
//
// todo: add verbose dumping of xip e32, o32 info
// todo: add option to extract relocatable dll ( by rebasing the data + code segments to 0x01000000 )
//
//
// item naming:
//  * files
//  * containers [ imgfs, xip20, xip23 ]
//  * readers [ nbh, htcimg, OS,GSMV2,HTCCONF, fffb, imgfs, xip20, xip23 ]
//
// NOT DONE LIKE THIS: fully qualified readerpath:  nbh:htcimg:OS:fffb:xip23
// NOT DONE LIKE THIS: fully qualified filepath:  nbh:htcimg:OS:fffb:xip23:boot.hv
// usually it is sufficient to just specify the last part of a path
//
// todo: create new imgfs filesystem
//
// notation:  "htcimage:{ devname='PB92', OS:{ bs=0x800, fffb:{ptab:{ updxip=<xip>, bootxip=<xip>, imgfs:{ comp='XPR', files=@filelist, mods=@modlist } } } } }"
//
// add option to convert between wrappers.
//
// -create  "nbh{ key=somefile.pvk, htcimage=srcfile }"
//
// todo: add executable as 'module'
// note: to be able to add modules, i'd have to reconstruct the data and code allocation maps, so i can find a spot to load the module in.
//
// todo: add feature to allow section to grow more, by working in a temporary buffer, and later rewriting the file
//
// done: add -chexdump  - which hexdumps (de)compressed data

int g_verbose= 0;


uint32_t roundsize(uint32_t x, uint32_t round)
{
    if (x==0)
        return 0;
    return ((x-1)|(round-1))+1;
}

// char magic[7] "B000FF\n"
// uint32_t fileoffset;
// uint32_t filesize;
//
// uint32_t blockoffset;
// uint32_t blocksize;
// uint32_t blockcheck;   // byte sum
// uint8_t  data[blocksize];
//
// -- last blockheader:
// uint32_t zerooffset;
// uint32_t entrypoint;
// uint32_t zerocheck;
//


struct caseinsensitive {
    bool operator() (const std::string& lhs, const std::string& rhs) const
    {
        return stringicompare(lhs, rhs)<0;
    }
};

class B000FFReadWriter : public ReadWriter {
    ReadWriter_ptr _r;
    uint32_t _bpos;

    uint32_t _binstart;
    uint32_t _binsize;
    uint32_t _entrypoint;

    struct blockinfo {
        uint64_t fileofs;    // offset into container object ( _r )
        uint32_t blockofs;   // offset into this
        uint32_t size;
        bool modified;

        blockinfo(uint64_t fileofs, uint32_t blockofs, uint32_t size)
            : fileofs(fileofs), blockofs(blockofs), size(size), modified(false)
        {
        }

        uint32_t file2block(uint64_t fo) const
        {
            return uint32_t(fo-fileofs)+blockofs;
        }
        uint64_t block2file(uint32_t bo) const
        {
            return (bo-blockofs)+fileofs;
        }
        uint64_t endfileofs() const
        {
            return fileofs+size;
        }
        uint32_t endblkofs() const
        {
            return blockofs+size;
        }


        bool containsblockoffset(uint32_t bo) const
        {
            return blockofs <= bo && bo < blockofs+size;
        }

    };

    // maps blockofs -> blockinfo
    typedef std::map<uint32_t, blockinfo> blockmap_t;
    blockmap_t _blockmap;

    blockmap_t::iterator _curblk;

    uint32_t _blocksize;
    uint64_t _allocpos;
    bool _extended;
    void allocblock(uint32_t bofs, uint32_t size)
    {
        _blockmap.insert(blockmap_t::value_type(bofs, blockinfo(_allocpos+12, bofs, size)));

        if (g_verbose>1)
            printf("updating b00 blk header at %08llx: %08x %08x %08x\n", _allocpos, bofs, size, 0);
        _r->setpos(_allocpos);

        _r->write32le(bofs);
        _r->write32le(size);
        _r->write32le(0);

        _allocpos += 12+size;
        _extended= true;

        if (g_verbose>1)
            dumpblocks();
    }
public:
    static bool isB000FF(const ByteVector& hdr)
    {
        std::string magic((const char*)&hdr[0], 7);
        return magic=="B000FF\n";
    }
    B000FFReadWriter(ReadWriter_ptr r)
        : _r(r), _bpos(0), _curblk(_blockmap.end()), _blocksize(0), _allocpos(0), _extended(false)
    {
        if (_r->isreadonly()) setreadonly();

        _r->setpos(7);
        _binstart= _r->read32le();
        _binsize= _r->read32le();

        while (!_r->eof())
        {
            uint32_t blockoffset= _r->read32le();
            uint32_t blocksize= _r->read32le();
            uint32_t blockcheck= _r->read32le(); 

            if (_r->eof() || (blockoffset==0 && blockcheck==0 && !_blockmap.empty())) {
                _allocpos= _r->getpos()-12;
                _entrypoint= blocksize;
                if (g_verbose)
                    printf("b000ff: initial allocpos= %08llx\n", _allocpos);
                break;
            }
            uint64_t ofs= _r->getpos();

            _blockmap.insert(blockmap_t::value_type(blockoffset, blockinfo(ofs, blockoffset, blocksize)));

            _r->setpos(ofs+blocksize);
        }

        setpos(_binstart);

        std::map<uint32_t, int> bsstats;
        std::for_each(_blockmap.begin(), _blockmap.end(), [&bsstats](const blockmap_t::value_type& vt) {
            bsstats[vt.second.size]++;
        });

        auto imax= std::max_element(bsstats.begin(), bsstats.end(), [](const std::pair<uint32_t, int>& lhs, const std::pair<uint32_t, int>& rhs) {
                return lhs.second<rhs.second;
        });

        _blocksize= imax->first;
        if (g_verbose) {
            printf("B000FF wrapper: %08x-%08x, entry=%08x, commonblocksize=%08x (%d times), total %d blocks\n",
                  _binstart, _binstart+_binsize, _entrypoint, _blocksize, imax->second, (int)_blockmap.size());

            dumpblocks();

            bool checkok= true;
            std::for_each(_blockmap.begin(), _blockmap.end(), [this, &checkok](const blockmap_t::value_type& vt) {
                const blockinfo& bi= vt.second;
                _r->setpos(bi.fileofs-4);
                uint32_t storedsum= _r->read32le(); 
                uint32_t bytesum= calcbytesum(bi.size);

                if (storedsum!=bytesum) {
                    printf("checksum error for B:%08x  F:[%08llx], size=%08x -> file:%08x calc:%08x\n", bi.blockofs, bi.fileofs, bi.size, storedsum, bytesum);
                    checkok= false;
                }
            });

            if (checkok)
                printf("block checksums ok\n");
        }
    }
    void dumpblocks() const
    {
        uint32_t curofs=_binstart;
        uint32_t startofs=0xFFFFFFFF;
        std::for_each(_blockmap.begin(), _blockmap.end(), [&curofs, &startofs](const blockmap_t::value_type& vt) {
            const blockinfo& bi= vt.second;
            if (bi.blockofs>curofs) {
                if (startofs==0xFFFFFFFF) {
                    printf("                            gap: %08x-%08x\n", curofs, bi.blockofs);
                }
                else {
                    printf("  blk  %08x-%08x", startofs, curofs);
                    printf("    gap: %08x-%08x\n", curofs, bi.blockofs);
                }
                startofs= bi.blockofs;
            }
            else if (startofs==0xFFFFFFFF) {
                startofs= bi.blockofs;
            }
            curofs= bi.endblkofs();
        });
        printf("  blk  %08x-%08x", startofs, curofs);
        if (curofs<_binstart+_binsize)
            printf("    gap: %08x-%08x\n", curofs, _binstart+_binsize);
        else
            printf("\n");
    }
    virtual ~B000FFReadWriter()
    {
    // update checksum of modified blocks
        std::for_each(_blockmap.begin(), _blockmap.end(), [this](const blockmap_t::value_type& vt) {
            const blockinfo& bi= vt.second;
            if (bi.modified) {
                _r->setpos(bi.fileofs);
                uint32_t bytesum= calcbytesum(bi.size);

                _r->setpos(bi.fileofs-4);
                _r->write32le(bytesum);
                if (g_verbose>1)
                    printf("checksum for B:%08x  F:[%08llx], size=%08x -> %08x\n", bi.blockofs, bi.fileofs, bi.size, bytesum);
            }
        });

        if (_extended) {
            printf("adding closing record @ %08llx\n", _allocpos);
            _r->setpos(_allocpos);
            _r->write32le(0);
            _r->write32le(_entrypoint);
            _r->write32le(0);
            _r->truncate(_r->getpos());
        }
    }

    // calculate the byte sum of <size> bytes, starting
    // at the current position
    uint32_t calcbytesum(size_t size)
    {
        uint32_t sum= 0;
        ByteVector buf(_blocksize);
        while (size)
        {
            uint32_t want= std::min(buf.size(), size);
            size_t nr= _r->read(&buf[0], want);
            if (nr==0)
                break;
            
            sum += calcbuffersum(&buf[0], nr);
            size -= nr;
        }

        return sum;
    }
    uint32_t calcbuffersum(const uint8_t *buf, size_t size)
    {
        //uint32_t sum= 0;
        //std::for_each(buf, buf+size, [&sum](uint8_t b) { sum+=b; });
        //return sum;
        return std::accumulate(buf, buf+size, 0);
    }

    virtual size_t read(uint8_t *p, size_t n)
    {
#define b00printf(...)
        b00printf("rd[%08x], %zx\n", _bpos, n);
        if (_curblk==_blockmap.end()) {
            b00printf("  -> EOF\n");
            return 0;
        }

        b00printf("cur: %08llx-%08llx > %08x-%08x\n", _curblk->second.fileofs, _curblk->second.endfileofs(), _curblk->second.blockofs, _curblk->second.endblkofs());
        // cur pos is after cur block -> move to next
        if (_bpos >= _curblk->second.endblkofs()) {
            setpos(_bpos);

            if (_curblk==_blockmap.end()) {
                b00printf("-> nextblk=EOF\n");
                return 0;
            }
            b00printf("newcur: %08llx-%08llx > %08x-%08x\n", _curblk->second.fileofs, _curblk->second.endfileofs(), _curblk->second.blockofs, _curblk->second.endblkofs());
        }

        // cur pos is before current block ( and after prev block )
        if (_bpos < _curblk->second.blockofs) {
            size_t want= std::min(n, size_t(_curblk->second.blockofs-_bpos));
            std::fill(p, p+want, 0);
            b00printf("in gap: size=%zx\n", want);
            _bpos += want;
            return want;
        }

        size_t want= std::min(n, _curblk->second.size-size_t(_bpos-_curblk->second.blockofs));

        _r->setpos(_curblk->second.block2file(_bpos));
        _r->read(p, want);

        b00printf("got data: size=%zx\n", want);

        _bpos += want;
        return want;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        while (n) {
            if (_curblk==_blockmap.end())
                throw "b000ff: out of space";

            // cur pos is after cur block -> move to next
            if (_bpos >= _curblk->second.endblkofs()) {
                setpos(_bpos);

                if (_curblk==_blockmap.end())
                    throw "b000ff: out of space";
            }

            // cur pos is before current block ( and after prev block )
            if (_bpos < _curblk->second.blockofs) {
                uint32_t nextstart= _curblk->second.blockofs;

                if (g_verbose>1)
                    printf("attempted write in b00 gap: %08x [ nextbk=%08x-%08x]\n", _bpos, nextstart, _curblk->second.endblkofs());

                if (_curblk==_blockmap.begin())
                    throw "b000ff: can't write before first block";

                _curblk--;
                uint32_t prevend= _curblk->second.endblkofs();
                int n= (_bpos-prevend)/_blocksize;
    
//              printf("alloccing b00 block: prev=%08x, next=%08x -> n=%d: ofs=%08x, size=%08x\n", 
//                      prevend, nextstart, n, prevend+n*_blocksize, std::min(_blocksize, nextstart-prevend+n*_blocksize));
                allocblock(prevend+n*_blocksize, std::min(_blocksize, nextstart-prevend+n*_blocksize));
                setpos(_bpos);
            }

            _curblk->second.modified= true;

            size_t want= std::min(n, _curblk->second.size-size_t(_bpos-_curblk->second.blockofs));

            _r->setpos(_curblk->second.block2file(_bpos));
            _r->write(p, want);

            _bpos += want;
            n -= want;
        }
    }
    virtual void setpos(uint64_t off)
    {
        _bpos= off;
        
        auto i= _blockmap.upper_bound(off);
        if (i==_blockmap.begin()) i= _blockmap.end(); else i--;

        if (i==_blockmap.end()) {
            printf("map=%d, off=%08llx\n", (int)_blockmap.size(), off);
            throw "b000ff before start of map";
        }

        if (off >= i->second.endblkofs()) {
            i++;

            if (i==_blockmap.end()) {
                printf("map=%d, off=%08llx\n", (int)_blockmap.size(), off);
                throw "beyond end of map";
            }
        }
        _curblk= i;
    }
    virtual void truncate(uint64_t off)
    {
        throw "b000ff truncate not implemented";
    }
    virtual uint64_t size()
    {
        return _binsize;
    }
    virtual uint64_t getpos() const
    {
        return _bpos;
    }
    virtual bool eof()
    {
        return _curblk==_blockmap.end();
    }
};

class HimaReader : public ReadWriter {
    ReadWriter_ptr  _r;
    uint64_t _pos;
public:
    HimaReader(ReadWriter_ptr r)
        : _r(r), _pos(0)
    {
        if (_r->isreadonly()) setreadonly();
    }
    virtual ~HimaReader() { }
    virtual size_t read(uint8_t *p, size_t n)
    {
        size_t total= 0;
        while (n)
        {
            size_t want= (size_t)std::min(uint64_t(n), 0x40000-realpos(_pos)%0x40000);
            _r->setpos(realpos(_pos));

            size_t rn= _r->read(p, want);

            _pos += rn;
            p += rn;
            n -= rn;
            total += rn;

            if (rn<want)
                break;
        }
        return total;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        size_t total= 0;
        while (n)
        {
            size_t want= (size_t)std::min(uint64_t(n), 0x40000-realpos(_pos)%0x40000);
            _r->setpos(realpos(_pos));

            _r->write(p, want);

            _pos += want;
            p += want;
            n -= want;
            total += want;
        }
    }
    virtual void setpos(uint64_t off)
    {
        _r->setpos(realpos(off));
    }
    virtual void truncate(uint64_t off)
    {
        _r->truncate(realpos(off));
    }
    virtual uint64_t size()
    {
        return himapos(_r->size());
    }
    virtual uint64_t getpos() const
    {
        return himapos(_r->getpos());
    }
    virtual bool eof()
    {
        return getpos()>=size();
    }

private:
    static uint64_t realpos(uint64_t pos)
    {
        return (pos/0x3f000)*0x40000+(pos%0x3f000);
    }
    static uint64_t himapos(uint64_t realpos)
    {
        return (realpos/0x40000)*0x3f000+(realpos%0x40000);
    }
};


class PartitionTable {
public:
    struct Entry {
        struct CHS {
            uint8_t side;
            uint16_t cyl;
            uint8_t sect;
            void parse(const uint8_t*p)
            {
                side= p[0];
                sect= p[1]&0x3f;
                cyl= p[2]|((p[1]&0xc0)<<2);
            }
        };
        uint64_t _sectorsize;

        uint8_t _bootable;
        CHS _startchs;
        uint8_t _type;
        CHS _endchs;
        uint32_t _startsector;
        uint32_t _nrsectors;

        void parse(const uint8_t*p, uint64_t ssize)
        {
            _sectorsize= ssize;

            _bootable= p[0];
            _startchs.parse(p+1);
            _type= p[4];
            _endchs.parse(p+5);
            _startsector= get32le(p+8);
            _nrsectors= get32le(p+12);
        }
        uint64_t start() const
        {
            return _sectorsize*_startsector;
        }
        uint64_t size() const
        {
            return _sectorsize*_nrsectors;
        }

        int type() const
        {
            return _type;
        }
        void printentry() const
        {
            printf("%c %02x %06x-%06x/%08x : %10llx-%10llx/%8llx\n", _bootable?'B':' ',
                    _type, _startsector, _startsector+_nrsectors, _nrsectors,
                    start(), start()+size(), size());
        }
    };
    PartitionTable(const ByteVector& sector, uint64_t ssize)
    {
        //note:strange compiler error:
        //   0x1be+16*i  -> suffix +16 on integer constant error
        for (int i=0 ; i<4 ; i++)
            _table[i].parse(&sector[(0x1be)+16*i], ssize);
    }
    static bool isvalidptable(const ByteVector& sector)
    {
        return sector.size()>=512 && sector[510]==0x55 && sector[511]==0xaa;
    }
    Entry* firstoftype(int type)
    {
        for (int i=0 ; i<4 ; i++)
            if (_table[i].type()==type)
                return &_table[i];
        return 0;
    }
    size_t count() const { return 4; }
    const Entry& entry(size_t i) const { return _table[i]; }

    void printtable() const
    {
        printf("partitiontable\n");
        for (int i=0 ; i<4 ; i++)
            _table[i].printentry();
    }
    void partition_enumerator(std::function<void(uint8_t,uint64_t,uint64_t)> fn)
    {
        for (int i=0 ; i<4 ; i++)
            if (_table[i].type() || _table[i].size())
                fn(_table[i].type(), _table[i].start(), _table[i].size());
    }
private:
    Entry _table[4];
};
/*

 =fileoffset=        =fileblocknr=        =blocknr=       =tag=        fileofs/808-blocknr
00000800-00607008: 00000000-00000c01  00000000-00000c01  fffbfffd         0
00607810-006261f8: 00000c02-00000c3f  - 0x003E empty blocks
00626a00-00a31a70: 00000c40-0000144e  00000c40-0000144e  fffbfffd         0
00a32278-00acabf8: 0000144f-0000157f  - 0x0131 empty blocks
00acb400-0c2d6940: 00001580-00018428  00001500-000183a8  fffbffff      0x80     <<< todo: dont hardcode this offset
0c2d7148-0dbdaff8: 00018429-0001b5ff  - 0x31D7 empty blocks
0dbdb800:          EOF

note: partitiontable offsets refer to fffbfffd offsets

*/
class FFFBFFFDReader : public ReadWriter {
    ReadWriter_ptr  _r;
    uint32_t _blocksize;
    uint64_t _pos;

    // for calculating fileoffset from fffbfffd blocknr
    struct areainfo {
        uint32_t blocksize;
        uint64_t fileoffset;
        uint32_t firstblock;
        uint32_t tag;
        size_t usedblocks;
        size_t nblocks;         // max nr of blocks due to partition limit

        areainfo() :
            blocksize(0), fileoffset(0), firstblock(0), tag(0), usedblocks(0), nblocks(0)
        {
        }
        uint32_t ofs2block(uint64_t ofs) const
        {
            return uint32_t((ofs-fileoffset)/(blocksize+8)+firstblock);
        }
        uint64_t block2ofs(uint32_t block) const
        {
            //printf("fofs=%llx, 1st=%05x, bs=%08x\n", fileoffset, firstblock, blocksize);
            return fileoffset+(block-firstblock)*(blocksize+8);
        }
    };

    // maps logical blocknr -> areainfo,  where blocknr is firstblock of area
    typedef std::map<uint32_t, areainfo> areamap_t;
    typedef std::map<uint64_t, areainfo> filemap_t;

    areamap_t _areamap;
    filemap_t _filemap;

    void dumpareas()
    {
        printf("by fileofs\n");
        std::for_each(_filemap.begin(), _filemap.end(), [](const filemap_t::value_type& vt) {
            const areainfo& bi= vt.second;
            printf("%08llx: ", vt.first);
            if (hasblocknr(bi.firstblock, bi.tag)) {
                if (bi.nblocks)  {
                    printf("area %08llx-%08llx/%8x: %08llx-%08llx/%3x: %05x-%05x[..%05x]/%3x..%3x  %08x\n",
                            bi.fileoffset, bi.fileoffset+bi.usedblocks*(bi.blocksize+8),                               uint32_t(bi.usedblocks*(bi.blocksize+8)),
                            uint64_t(bi.firstblock)*bi.blocksize, uint64_t(bi.firstblock+bi.usedblocks)*bi.blocksize,  uint32_t(bi.usedblocks*bi.blocksize),
                            bi.firstblock, uint32_t(bi.firstblock+bi.usedblocks),
                            uint32_t(bi.firstblock+bi.nblocks),                                      uint32_t(bi.usedblocks), uint32_t(bi.nblocks),
                            bi.tag);
                }
                else {
                    printf("area %08llx-%08llx/%8x: %08llx-%08llx/%8x: %05x-%05x/%3x           %08x\n",
                            bi.fileoffset, bi.fileoffset+bi.usedblocks*(bi.blocksize+8),                               uint32_t(bi.usedblocks*(bi.blocksize+8)),
                            uint64_t(bi.firstblock)*bi.blocksize, uint64_t(bi.firstblock+bi.usedblocks)*bi.blocksize,  uint32_t(bi.usedblocks*bi.blocksize),
                            bi.firstblock, uint32_t(bi.firstblock+bi.usedblocks),                    uint32_t(bi.usedblocks),
                            bi.tag);
                }
            }
            else {
                printf("area %08llx-%08llx/%8x:                  %08x   %08x\n",
                        bi.fileoffset, bi.fileoffset+bi.usedblocks*(bi.blocksize+8),  uint32_t(bi.usedblocks*(bi.blocksize+8)),
                        bi.firstblock, bi.tag);
            }
        });
    }

public:
    static uint32_t findblocksize(ReadWriter_ptr rd)
    {
        DwordVector blocks;
        DwordVector magic;
        for (unsigned i= 0 ; i<=0x1000 ; i+=0x200)
        {
            rd->setpos(i);
            blocks.push_back(rd->read32le());
            magic.push_back(rd->read32le());
            blocks.push_back(rd->read32le());
            magic.push_back(rd->read32le());
        }
        if (blocks[2]==0 && magic[2]==0xfffbfffd)
        {
            if (blocks[5]==1 && magic[5]==0xfffbfffd)
                return 0x200;
        }
        else if (blocks[4]==0 && magic[4]==0xfffbfffd)
        {
            if (blocks[9]==1 && magic[9]==0xfffbfffd)
                return 0x400;
        }
        else if (blocks[8]==0 && magic[8]==0xfffbfffd)
        {
            if (blocks[17]==1 && magic[17]==0xfffbfffd)
                return 0x800;
        }
        // for motorola phones where the blk nums start at 0x323200
        else if (blocks[8]==0xFFFFFFFF && magic[8]==0xFFFFFFFF)
        {
            if (blocks[17]==0xFFFFFFFF && magic[17]==0xFFFFFFFF)
                return 0x800;
        }

        if (g_verbose) {
            printf("no fffb: blk: %s\n          mg: %s\n", vhexdump(blocks).c_str(), vhexdump(magic).c_str());
            if (g_verbose>2) {
                rd->setpos(0);
                ByteVector data(4096);
                rd->read(&data[0], data.size());
                printf("0000-1000: %s\n", vhexdump(data).c_str());
            }
        }
        return 0;
    }

    void registerarea(const areainfo& bi)
    {
        _filemap[bi.fileoffset]= bi;
        if (hasblocknr(bi.firstblock, bi.tag))
            _areamap[bi.firstblock]= bi;
    }
    static bool hasblocknr(uint32_t snr, uint32_t tag)
    {
        if (snr==0xFFFFFFFF)
            return false;
        if (snr!=0)
            return true;
        return tag!=0xFFFFFFFF && tag!=0;
    }

    void scan_fffbd_blocks()
    {
        areainfo bi;

        for (uint64_t ofs= 0 ; ofs+_blocksize+8 <= _r->size() ; ofs+=_blocksize+8)
        {
            _r->setpos(ofs+_blocksize);
            uint32_t snr= _r->read32le();
            uint32_t tag= _r->read32le();
//          printf("read[%08x|%08x],  curarea: %08llx-?  %08x-%08x[l=%04x] hs=%d  |%08x : %s\n",
//                  snr, tag, bi.fileoffset, bi.firstblock, uint32_t(bi.firstblock+bi.usedblocks), 
//                  (int)bi.usedblocks, hasblocknr(snr, tag), bi.tag, vhexdump(data).c_str());

            if (ofs==0) {
                bi.fileoffset= ofs;
                bi.blocksize= _blocksize;
                bi.firstblock= snr;
                bi.tag= tag;
                bi.usedblocks=1;
            }
            else if ((!hasblocknr(snr,tag) && bi.firstblock==snr && bi.tag==tag)
                  || (hasblocknr(snr,tag) && bi.firstblock+bi.usedblocks==snr && bi.tag==tag))
            {
                bi.usedblocks++;
            }
            else
            {
                registerarea(bi);

                bi.fileoffset= ofs;
                bi.blocksize= _blocksize;
                bi.firstblock= snr;
                bi.tag= tag;
                bi.usedblocks=1;
            }
        }
        registerarea(bi);
    }
    void process_partitions()
    {
        auto a0= _areamap.find(0);
        if (a0==_areamap.end()) {
            printf("ptablescan could not find block0\n");
            return;
        }
        ByteVector sec0(512);
        _r->setpos(a0->second.fileoffset);
        _r->read(&sec0[0], sec0.size());

        PartitionTable ptab(sec0, _blocksize);

        if (g_verbose)
            ptab.printtable();

        for (size_t i= 0 ; i<ptab.count()-1 ; i++)
        {
            const PartitionTable::Entry& ent= ptab.entry(i);
            uint32_t blocknr= i==0 ? 0 : size_t(ent.start()/_blocksize);
            auto pi= _areamap.upper_bound(blocknr);
            if (pi==_areamap.begin()) {
                printf("ptablescan: no areas [%05x]\n", blocknr);
                continue;
            }
            pi--;
            areainfo &bi= pi->second;
            if (blocknr < bi.firstblock) {
                printf("ptablescan - UNEXPECTED: ub(%05x) = %05x\n", blocknr, bi.firstblock);
                continue;
            }
            if (blocknr >= bi.firstblock+bi.usedblocks) {
                printf("ptablescan - block%05x not in an area\n", blocknr);
                continue;
            }

            _filemap[bi.fileoffset].nblocks = 
              bi.nblocks= size_t(ent.size()/_blocksize + (i==0 ? 2 : 0))+blocknr-bi.firstblock;
        }
    }
    FFFBFFFDReader(ReadWriter_ptr rw, uint32_t blocksize)
        : _r(rw), _blocksize(blocksize), _pos(0)
    {
        if (_r->isreadonly()) setreadonly();

        if (g_verbose)
            printf("FFFBFFFD wrapper with blocksize %08x\n", _blocksize);
        scan_fffbd_blocks();
        process_partitions();
        if (g_verbose)
            dumpareas();
    }
    virtual ~FFFBFFFDReader()
    {
    }

    // returns basereader psize needed to read fffbfffd vsize bytes

    virtual size_t read(uint8_t *p, size_t vsize)
    {
        size_t total= 0;
        _r->setpos(realpos(_pos));
        if (size_t c0= (_pos%_blocksize)) {
            // first read upto block boundary
            size_t want= std::min(vsize, _blocksize-c0);

            size_t rn= _r->read(p, want);
            total += rn;
            p += rn;
            _pos += rn;
            vsize -= rn;
            if (rn<want)
                return total;
        }
        size_t nblocks= vsize/_blocksize;
        while (nblocks--)
        {
            // read whole blocks
            _r->setpos(realpos(_pos));

            size_t rn= _r->read(p, _blocksize);

            total += rn;
            p += rn;
            _pos += rn;
            vsize -= rn;

            if (rn<_blocksize)
                return total;
        }
        if (vsize) 
        {
            // read last partial block
            _r->setpos(realpos(_pos));

            size_t rn= _r->read(p, vsize);

            total += rn;
            p += rn;
            _pos += rn;
            vsize -= rn;

            if (rn<vsize)
                return total;
        } 
        return total;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        size_t total= 0;
        while (n)
        {
            size_t want= (size_t)std::min(uint64_t(n), 0x800-_pos%0x800);

            _r->setpos(realpos(_pos));
//          printf("fffbfffd: vpos=%08x(%x*0800+%x), rpos=%08x(%x*0808+%x), writing %x\n", 
//                  int(_pos), int(_pos/0x800), int(_pos%0x800),
//                  int(realpos(_pos)), int(realpos(_pos)/0x808), int(realpos(_pos)%0x808), int(want));

            _r->write(p, want);

            _pos += want;
            p += want;
            n -= want;
            total += want;

            //if ((_pos%0x800)==0)
            //   todo: optionally i can write the footer here, so writing will happen more in file position order
            //         in that case, i would have to write the final footer in the destructor, since we may not yet have reached it.
        }
    }
    virtual void setpos(uint64_t off)
    {
        _pos= off;
    }
    virtual void truncate(uint64_t off)
    {
        _r->truncate(realpos(off));
    }
    virtual uint64_t size()
    {
        if (_areamap.empty()) {
            printf("note: fffbfffd filesize not yet accurately known\n");
            return (_r->size()/(_blocksize+8))*_blocksize;
        }
        auto lastblock= _areamap.rbegin()->second;
        return ((_r->size()-lastblock.fileoffset)/(_blocksize+8)+lastblock.firstblock)*_blocksize;
    }
    virtual uint64_t getpos() const
    {
        return _pos;
    }
    virtual bool eof()
    {
        return _pos>=size();
    }

    size_t blocksize() const { return _blocksize; }
private:
    uint64_t realpos(uint64_t pos)
    {
        size_t blocknr= size_t(pos/_blocksize);

        auto i= _areamap.upper_bound(blocknr);
        if (i==_areamap.begin()) i= _areamap.end(); else i--;

        if (i==_areamap.end()) {
            printf("ERROR: searched block %05x in %d areas\n", int(blocknr), int(_areamap.size()));
            throw "fffbfffd areamap empty";
        }
        areainfo& bi= i->second;
        if ( blocknr>=bi.firstblock+bi.usedblocks) {
            if (bi.usedblocks>=bi.nblocks)
                throw "ffb area full";
//          printf("alloccing ffb block %05x -> area: %05x-%05x, used-%05x,  tag=%08x  -- new: %05x-%05x\n", int(blocknr), 
//                  int(bi.firstblock),
//                  int(bi.firstblock+bi.nblocks),
//                  int(bi.firstblock+bi.usedblocks), bi.tag,
//                  int(bi.firstblock+bi.usedblocks), int(blocknr) );

            for (unsigned b= bi.firstblock+bi.usedblocks ; b<=blocknr ; b++) {
                if (_r->isreadonly())
                    throw "out of area";
                _r->setpos(bi.block2ofs(b)+_blocksize);
                _r->write32le(b);
                _r->write32le(bi.tag);
            }

            bi.usedblocks= blocknr-bi.firstblock;
        }

        return bi.block2ofs(blocknr)+(pos%_blocksize);
    }
};
class MsFlash50 {
    // see ~/sources/wm500aku/PUBLIC/COMMON/OAK/INC/fls.h
    struct extra {
        std::string name;
        uint32_t start;
        uint32_t size;

        extra(const uint8_t *p)
        {
            name= getstr(p, 8);

            start= get32le(p+8);
            size= get32le(p+12);
        }
        void print() const
        {
            printf("%08x %08x %s\n", start, size, name.c_str());
        }
    };
    struct region {
        int type;        // 0=XIP, 1=READONLY_FILESYS, 2=FILESYS
        uint32_t pstart;
        uint32_t psize;
        uint32_t lsize;
        uint32_t blksectors;
        uint32_t blkbytes;
        int compact;

        region(const uint8_t *p)
        {
            type= get32le(p+0x0);
            pstart= get32le(p+0x4);
            psize= get32le(p+0x8);
            lsize= get32le(p+0xc);
            blksectors= get32le(p+0x10);
            blkbytes= get32le(p+0x14);
            compact= get32le(p+0x18);
        }
        void print() const
        {
            printf("%d %08x %08x %08x  blk:%d sec, 0x%x bytes, compact=%d\n", 
                type, pstart, psize, lsize, blksectors, blkbytes, compact);
        }
    };
    std::vector<extra> _extralist;
    std::vector<region> _regionlist;
    public:
    MsFlash50(const ByteVector& data)
    {
        int extracount= get32le(&data[8])/0x10;
        int regioncount= get32le(&data[12])/0x1C;

        for (int i=0 ; i<extracount ; i++)
            _extralist.push_back(extra(&data[16+16*i]));
        for (int i=0 ; i<regioncount ; i++)
            _regionlist.push_back(region(&data[16+16*extracount+0x1c*i]));

        if (g_verbose) {
            printf("MSFLSH50\n");
            std::for_each(_extralist.begin(), _extralist.end(), [](const extra& e) { e.print(); });
            std::for_each(_regionlist.begin(), _regionlist.end(), [](const region& r) { r.print(); });
        }
    }
    static bool isMSFLASH50(const ByteVector& data)
    {
        return data.size()>256 && memcmp(&data[0], "MSFLSH50", 8)==0
            && (get32le(&data[8])%16)==0
            && (get32le(&data[12])%28)==0;
    }
};


template<typename PTR>
size_t vectorread32le(PTR rd, DwordVector& v, size_t n)
{
    v.resize(n);

    size_t nr= rd->read((uint8_t*)&v[0], n*sizeof(uint32_t));
    if (nr%sizeof(uint32_t))
        throw "read partial uint32_t";
    v.resize(nr/sizeof(uint32_t));
#if __BYTE_ORDER == __BIG_ENDIAN
#ifdef __GXX_EXPERIMENTAL_CXX0X__
    std::for_each(v.begin(), v.end(), [](uint32_t& x) { x= swab32(x);});
#else
    throw "need c++0x";
#endif
#endif
    return v.size();
}
template<typename PTR>
size_t readstr(PTR rd, std::string& v, size_t n)
{
    v.resize(n);
    size_t nr= rd->read((uint8_t*)&v[0], n);
    v.resize(nr);
    v.resize(stringlength(&v[0]));
    return v.size();
}
template<typename PTR>
std::string readstr(PTR rd)
{
    std::string str;
    while(true)
    {
        str.resize(str.size()+16);
        size_t n= rd->read((uint8_t*)&str[str.size()-16], 16);
        str.resize(str.size()-16+n);
        if (n==0)
            return str;
        size_t i0= str.find(char(0), str.size()-n);
        if (i0!=str.npos)
        {
            str.resize(i0);
            return str;
        }
    }
}
template<typename PTR>
size_t readutf16le(PTR rd, std::Wstring& v, size_t n)
{
    v.resize(n);
    size_t nr= rd->read((uint8_t*)&v[0], n*sizeof(uint16_t));
    if (nr%sizeof(uint16_t))
        throw "read partial uint16_t";
    v.resize(nr/sizeof(uint16_t));
    v.resize(stringlength(&v[0]));
#if __BYTE_ORDER == __BIG_ENDIAN
#ifdef __GXX_EXPERIMENTAL_CXX0X__
    std::for_each(v.begin(), v.end(), [](uint16_t& x) { x= swab16(x);});
#else
    throw "need c++0x";
#endif
#endif

    return v.size();
}
class HtcImageFile {
    ReadWriter_ptr _r;

    std::string _devname;
    std::string _cid;
    std::string _version;
    std::string _language;

    DwordVector _typelist;
    DwordVector _ofslist;
    DwordVector _sizelist;
public:
    static std::string nbhtypename(uint32_t type)
    {
        switch(type) {
    case 0x100: return "IPL";
    case 0x101: return "G3IPL";
    case 0x102: return "G4IPL";
    case 0x103: return "H3IPL";
    case 0x200: return "SPL";
    case 0x201: return "G3SPL";
    case 0x202: return "G4SPL";
    case 0x300: return "GSM";
    case 0x301: return "GSMV2";
    case 0x380: return "QCCONF";
    case 0x400: return "OS";
    case 0x500: return "diag";
    case 0x600: return "MainSplash";
    case 0x610: return "splash1";
    case 0x611: return "splash2";
    case 0x700: return "Extrom";
    case 0x800: return "cpldcode";
    case 0x900: return "Extrom2";
    case 0x920: return "HTCCONF";
    default: return "";
        }
    }
    HtcImageFile(ReadWriter_ptr r)
        : _r(r)
    {
        _r->setpos(0);

        DwordVector magic(8);
        vectorread32le(_r, magic, 8);
        std::string magicstr;
        magicstr.resize(8);
        std::copy(magic.begin(), magic.end(), magicstr.begin());
        if (magicstr!="HTCIMAGE")
            throw "missing HTCIMAGE signature";

        readstr(_r, _devname, 32);

        vectorread32le(_r, _typelist, 32);
        vectorread32le(_r, _ofslist, 32);
        vectorread32le(_r, _sizelist, 32);

        readstr(_r, _cid, 32);
        readstr(_r, _version, 16);
        readstr(_r, _language, 16);
        
        if (g_verbose) {
            printf("HTCIMAGE file\n");
            printf("devname: %s\n", _devname.c_str());
            printf("cid    : %s\n", _cid.c_str());
            printf("version: %s\n", _version.c_str());
            printf("language:%s\n", _language.c_str());
            for (unsigned i= 0 ; i<32 ; i++) {
                if (_typelist[i]==0 && _ofslist[i]==0 && _sizelist[i]==0)
                    continue;
                printf("%2x: %08x %08x %08x %s\n", i, _typelist[i], _ofslist[i], _sizelist[i], nbhtypename(_typelist[i]).c_str());
            }
        }
    }
    ReadWriter_ptr getsection(uint32_t type)
    {
        auto i= std::find(_typelist.begin(), _typelist.end(), type);
        if (i==_typelist.end())
            throw "htcimage section not found";

        int ix= i-_typelist.begin();

        //printf("HTCIMAGE section %d: %08x/%08x\n", ix, _ofslist[ix], _sizelist[ix]);
        return ReadWriter_ptr(new CheckedOffsetReader(_r, _ofslist[ix], _sizelist[ix]));
    }
    ReadWriter_ptr getsectionbyidx(int n)
    {
        unsigned ix;
        for (ix= 0 ; n && ix<32 ; ix++) {
            if (_typelist[ix]==0 && _ofslist[ix]==0 && _sizelist[ix]==0)
                continue;
            n--;
        }
        if (ix==32)
            return ReadWriter_ptr();

        //printf("HTCIMAGE section %d: %08x/%08x  %04x %s\n", ix, _ofslist[ix], _sizelist[ix], _typelist[ix], nbhtypename(_typelist[ix]).c_str());
        return ReadWriter_ptr(new CheckedOffsetReader(_r, _ofslist[ix], _sizelist[ix]));
    }
    uint32_t gettypebyidx(int n)
    {
        unsigned ix;
        for (ix= 0 ; n && ix<32 ; ix++) {
            if (_typelist[ix]==0 && _ofslist[ix]==0 && _sizelist[ix]==0)
                continue;
            n--;
        }

        return _typelist[ix];
    }

    size_t count()
    {
        int n=0;
        for (unsigned i= 0 ; i<32 ; i++) {
            if (_typelist[i]==0 && _ofslist[i]==0 && _sizelist[i]==0)
                continue;
            n++;
        }
        return n;
    }

    static bool isHtcImage(const ByteVector& hdr)
    {
        std::string magic;
        for (int i=0 ; i<8 ; i++)
            magic += (char)get32le(&hdr[4*i]);
        return magic=="HTCIMAGE";
    }
};
class rsasigner {
    RSA *_rsa;
public:
    struct sslerror {
        const char*_msg;
        sslerror(const char *msg) : _msg(msg) {
            printf("SSLERROR in %s\n", _msg);
            ERR_print_errors_fp(stdout);
        }
    };
    rsasigner(const std::string& filename)
    {
        FILE *f= fopen(filename.c_str(), "r");
        _rsa= PEM_read_RSAPrivateKey(f, NULL, 0, 0);
        fclose(f);
        if (_rsa==NULL)
            throw sslerror("d2i_RSAPrivateKey");
    }
    ~rsasigner()
    {
        if (_rsa)
            RSA_free(_rsa);
    }
    size_t signaturesize()
    {
        return RSA_size(_rsa);
    }
    void sign(const uint8_t *p, size_t n, uint8_t*signature)
    {
        if (!RSA_private_encrypt(n, p, signature, _rsa, RSA_PKCS1_PADDING))
            throw sslerror("RSA_sign");
    }
};
// todo: decode, with or without rsa sig checking
// todo: encode: keep track of changed blocks, when closing
// recalc only those the block signatures
class NbhReadWriter : public ReadWriter {
    ReadWriter_ptr _r;
    struct blockinfo {
        blockinfo() : ix(0), fileoffset(0), datasize(0), sigsize(0), flag(0), modified(false) { }
        uint32_t ix;
        uint64_t fileoffset;
        uint64_t logicaloffset;
        uint32_t datasize;
        uint32_t sigsize;
        uint8_t flag;

        bool modified;

        uint64_t logical2file(uint64_t logpos) const
        {
            return logpos+fileoffset+headersize()-logicaloffset;
        }
        uint64_t file2logical(uint64_t filepos) const
        {
            return filepos-fileoffset-headersize()+logicaloffset;
        }
        size_t remaining(uint64_t logpos) const
        {
            return size_t(datasize-(logpos-logicaloffset));
        }
        size_t headersize() const { return 9; }
        size_t physicalsize() const { return headersize() + datasize + sigsize; }
    };
    typedef std::map<uint64_t,blockinfo> blockmap_t;
    blockmap_t _blocks;

    uint64_t _logicalpos;
    std::string _keyfile;
    ByteVector _guid;

    bool _modified;
    bool _resign;
public:
    NbhReadWriter(ReadWriter_ptr r, const std::string& keyfile, bool resign)
        : _r(r), _logicalpos(0), _keyfile(keyfile), _guid(16), _resign(resign)
    {
        if (_r->isreadonly()) setreadonly();

        _r->setpos(0);
        std::string magic;
        readstr(_r, magic, 7);

        _r->read(&_guid[0], _guid.size());

        printf("nbh: %s %s\n", magic.c_str(), vhexdump(_guid).c_str());

        scanfile();
        if (g_verbose)
            printf("Nbh with %d blocks, filesize=0x%llx\n", int(_blocks.size()), size());
    }
    virtual ~NbhReadWriter()
    {
        if (_keyfile.empty()) {
            if (_modified)
                printf("WARNING: can't update signatures: no keyfile specified\n");
            return;
        }
        rsasigner rsa(_keyfile);
        std::for_each(_blocks.begin(), _blocks.end(), [this,&rsa](blockmap_t::value_type& item)
            {
                blockinfo& bi= item.second;
                if (!_resign && !bi.modified)
                    return;
                if (rsa.signaturesize()!=bi.sigsize)
                    throw "keyfile has different keysize than nbh";

                SHA_CTX sha1;
                SHA1_Init(&sha1);
                if (bi.datasize) {
                    ByteVector datablock(bi.datasize);
                    _r->setpos(bi.fileoffset+9);
                    _r->read(&datablock[0], datablock.size());
                    SHA1_Update(&sha1, &datablock[0], datablock.size());
                }

                ByteVector zeros(12);
                SHA1_Update(&sha1, &zeros[0], zeros.size());
                SHA1_Update(&sha1, &bi.flag, 1);
                SHA1_Update(&sha1, &_guid[0], _guid.size());
                ByteVector seqnr(4);
                set32le(&seqnr[0], bi.ix);
                SHA1_Update(&sha1, &seqnr[0], seqnr.size());

                ByteVector hash(SHA_DIGEST_LENGTH);
                SHA1_Final(&hash[0], &sha1);

                ByteVector signature(bi.sigsize);
                rsa.sign(&hash[0], hash.size(), &signature[0]);

                _r->setpos(bi.fileoffset+9+bi.datasize);
                _r->write(&signature[0], signature.size());

                bi.modified= false;
            }
        );
    }
    void scanfile()
    {
        typedef std::map<uint32_t,int> i32map_t;
        i32map_t ds_stats;
        i32map_t ss_stats;
        uint64_t filepos= 0x17;
        uint64_t logicalpos= 0;
        uint32_t ix= 0;
        while (true)
        {
            _r->setpos(filepos);

            blockinfo blk;
            blk.ix= ix;
            blk.fileoffset= filepos;
            blk.logicaloffset= logicalpos;
            blk.datasize= _r->read32le();
            blk.sigsize= _r->read32le();
            blk.flag= _r->read8();

            if (g_verbose) {
                ds_stats[blk.datasize]++;
                ss_stats[blk.sigsize]++;
            }

            _blocks[logicalpos]= blk;

            filepos+= blk.physicalsize();
            logicalpos+= blk.datasize;
            ix++;

            if (blk.flag==2)
                break;
        }
        if (g_verbose) {
            printf("ds: ");
            for (auto i= ds_stats.begin() ; i!=ds_stats.end() ; ++i)
                printf(" %08x:%d", i->first, i->second);
            printf("\n");
            printf("ss: ");
            for (auto i= ss_stats.begin() ; i!=ss_stats.end() ; ++i)
                printf(" %08x:%d", i->first, i->second);
            printf("\n");
        }
    }
    static bool isNbh(const ByteVector& hdr)
    {
        std::string magic((const char*)&hdr[0], 7);
        return magic=="R000FF\n";
    }
    blockinfo& findblock(uint64_t logpos)
    {
        auto i= _blocks.upper_bound(logpos);
        if (i==_blocks.begin()) i= _blocks.end(); else i--;

        if (i==_blocks.end()) {
            throw "nbh blockmap empty";
        }
        blockinfo& bi= i->second;
        if (bi.datasize && (logpos < bi.logicaloffset || logpos >= bi.logicaloffset+bi.datasize))
        {
            printf("ERROR: in L[%08llx-%08llx] F[%08llx-%08llx] :  found %08llx\n",
                    bi.logicaloffset, bi.logicaloffset+bi.datasize,
                    bi.fileoffset, bi.fileoffset+bi.datasize,
                    logpos);
            throw "nbh wrong block found";
        }
        return bi;
    }
    virtual size_t read(uint8_t *p, size_t n)
    {
        size_t total= 0;

        //printf("@L:%llx nbh.read(%zx)\n", _logicalpos, n);
        while (total < n) {
            //printf("@l:%llx\n", _logicalpos);
            blockinfo& bi= findblock(_logicalpos);
            _r->setpos(bi.logical2file(_logicalpos));

            size_t want= std::min(n-total, bi.remaining(_logicalpos));
            if (want==0)
                break;

            size_t rn= _r->read(p, want);

            //printf("@F:%llx  want=%zx  read=%zx\n", bi.logical2file(_logicalpos), want, rn);

            total += rn;
            p += rn;
            _logicalpos += rn;

            if (rn<want)
                break;
        }
        return total;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        if (n)
            _modified= true;

        size_t total= 0;

        while (total < n) {
            blockinfo& bi= findblock(_logicalpos);
            _r->setpos(bi.logical2file(_logicalpos));

            size_t want= std::min(n-total, bi.remaining(_logicalpos));
            _r->write(p, want);

            total += want;
            p += want;
            _logicalpos += want;

            bi.modified= true;
        }
    }
    virtual void setpos(uint64_t off)
    {
        _logicalpos= off;
    }
    virtual void truncate(uint64_t off)
    {
        // ignored
    }
    virtual uint64_t size()
    {
        if (_blocks.empty()) 
            return 0;

        return _blocks.rbegin()->second.logicaloffset;
    }
    virtual uint64_t getpos() const
    {
        return _logicalpos;
    }
    virtual bool eof()
    {
        return _logicalpos>=size();
    }

};




std::string unixtime2string(uint64_t t)
{
    std::string buf; buf.resize(64);
    // note: on osx time_t is 32 bit, on windows 64bit
    // on osx this hides a conversion error leaving a 0x300000000 offset
    // in the time.
    time_t tt= t&0xFFFFFFFF;
    struct tm *ptm= localtime(&tt);
    if (ptm==NULL)
        return "----/--/-- --:--:--";
    struct tm tm= *ptm;
    size_t n= strftime(&buf[0], buf.size(), "%Y-%m-%d %H:%M:%S", &tm);
    buf.resize(n);
    return buf;
}
uint64_t filetimetounix(uint64_t filetime)
{
    return filetime/10000000-11644473600;
}
uint64_t unixtofiletime(uint64_t unixtime)
{
    return (unixtime+11644473600)*10000000;
}

// used for exporting modules as .exe/.dll
class exe_reconstructor {

    struct sectioninfo {
        std::string name;
        uint64_t size;
        ReadWriter_ptr r;

        sectioninfo(const std::string &name, uint64_t size, ReadWriter_ptr r)
            : name(name), size(size), r(r)
        {
        }

        void copydata(ReadWriter_ptr w)
        {
            uint64_t pos= 0;
            r->setpos(0);
            while (pos < r->size()) {
                ByteVector buf(65536);
                size_t n= r->read(&buf[0], buf.size());
                w->write(&buf[0], n);
                pos += n;
            }
        }
    };
    typedef std::shared_ptr<sectioninfo> sectioninfo_ptr;
public:
    enum infotype_t { EXP, IMP, RES, EXC, SEC, FIX, DEB, IMD, MSP, TLS, CFG, BND, IAT, DMP, COM, RS5 };
                      
#ifndef _WIN32
#define IMAGE_FILE_RELOCS_STRIPPED 1
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000
#define STD_EXTRA 16
#define IMAGE_FILE_MACHINE_ARM 0x01c0
#endif
#define IMAGE_SCN_COMPRESSED 0x00002000
#define IMAGE_SCN_TYPE_NOLOAD 0x00000002

    struct infoitem {
        uint32_t rva;
        uint32_t size;
        infoitem() : rva(0), size(0) { }
        infoitem(uint32_t rva, uint32_t size) : rva(rva), size(size) { }
        bool equals(uint32_t r, uint32_t s)
        {
            return r==rva && s==size;
        }
    };
    struct e32rom {
        uint16_t objcnt;
        uint16_t imageflags;
        uint32_t entryrva;
        uint32_t vbase;
        uint16_t subsysmajor;
        uint16_t subsysminor;
        uint32_t stackmax;
        uint32_t vsize;
        uint32_t sect14rva;
        uint32_t sect14size;
        uint32_t timestamp;
        infoitem info[9];
        uint16_t subsys;

        static bool g_wm2003;

        e32rom(const uint8_t *p)
        {
            objcnt     = get16le(p);     p += 2; // 0x00
            imageflags = get16le(p);     p += 2; // 0x02
            entryrva   = get32le(p);     p += 4; // 0x04
            vbase      = get32le(p);     p += 4; // 0x08
            subsysmajor= get16le(p);     p += 2; // 0x0C
            subsysminor= get16le(p);     p += 2; // 0x0E
            stackmax   = get32le(p);     p += 4; // 0x10
            vsize      = get32le(p);     p += 4; // 0x14
            sect14rva  = get32le(p);     p += 4; // 0x18
            sect14size = get32le(p);     p += 4; // 0x1C
            if (!g_wm2003) {                             
                timestamp = get32le(p);  p += 4; // 0x20
            }
            else { timestamp = 0; }

            for (int i=0 ; i<9 ; i++) {
                info[i].rva = get32le(p+8*i+0);
                info[i].size= get32le(p+8*i+4);
            }
            p+=8*9;
            subsys = get16le(p);         p += 4; // 0x6C
        }
        void printe32() const
        {
            printf("flags=%08x, entry=%08x, vbase/size=%08x/%08x, subsys=%d/v%d.%d, stack=%08x ts=%08x\n",
                    imageflags, entryrva, vbase, vsize, subsys, subsysmajor, subsysminor, stackmax, timestamp);
            const char*infoname= "EXP IMP RES EXC SEC FIX DEB IMD MSP TLS CFG BND IAT DMP COM RS5 ";
            for (int i=0 ; i<9 ; i++) {
                if (info[i].rva || info[i].size) 
                    printf("   %c%c%c : %08x %08x\n", infoname[4*i], infoname[4*i+1], infoname[4*i+2], info[i].rva, info[i].size);
            }
        }
        static size_t size() { return g_wm2003 ? 0x6C : 0x70; }

        void getdata(uint8_t *p)
        {
            set16le(p, objcnt);      p += 2; // 0x00
            set16le(p, imageflags);  p += 2; // 0x02
            set32le(p, entryrva);    p += 4; // 0x04
            set32le(p, vbase);       p += 4; // 0x08
            set16le(p, subsysmajor); p += 2; // 0x0C
            set16le(p, subsysminor); p += 2; // 0x0E
            set32le(p, stackmax);    p += 4; // 0x10
            set32le(p, vsize);       p += 4; // 0x14
            set32le(p, sect14rva);   p += 4; // 0x18
            set32le(p, sect14size);  p += 4; // 0x1C
            if (!g_wm2003) {
                set32le(p, timestamp); p+=4; // 0x20
            }
            for (int i=0 ; i<9 ; i++) {
                set32le(p+8*i+0, info[i].rva);
                set32le(p+8*i+4, info[i].size);
            }
            p+=8*9;
            set16le(p, subsys);              // 0x6C
        }
    };
    typedef std::shared_ptr<e32rom> e32rom_ptr;
    struct o32rom {
        uint32_t vsize;
        uint32_t rva;
        uint32_t psize;
        uint32_t dataptr;   // todo - this is something else!!, byte,byte,int16
        uint32_t realaddr;
        uint32_t flags;
        o32rom(const uint8_t *p)
        {
            vsize=    get32le(p+0x00);
            rva=      get32le(p+0x04);
            psize=    get32le(p+0x08);
            dataptr=  get32le(p+0x0c);
            realaddr= get32le(p+0x10);
            flags=    get32le(p+0x14);
            //printf("o32rom: vsize=%08x psize=%08x r%08x ptr=%08x real=%08x flags=%08x\n", vsize, psize, rva, dataptr, realaddr, flags);
        }
        void printo32(sectioninfo_ptr s)
        {
            printf("rva=%08x v:%08x,p:%08x, real=%08x, flag=%08x, ?=%08x",
                    rva, vsize, psize, realaddr, flags, dataptr);
            if (s) {
                printf(" | %s : %08x\n", s->name.c_str(), (unsigned)s->size);
            }
            else {
                printf("\n");
            }
        }
        static size_t size() { return 0x18; }

        void getdata(uint8_t *p)
        {
            set32le(p+0x00, vsize);
            set32le(p+0x04, rva);
            set32le(p+0x08, psize);
            set32le(p+0x0c, dataptr);
            set32le(p+0x10, realaddr);
            set32le(p+0x14, flags);
        }
    };
    typedef std::shared_ptr<o32rom> o32rom_ptr;
private:
    struct e32exe {
        uint32_t magic;        // 0000  Magic number E32_MAGIC
        uint16_t cpu;          // 0004  The CPU type
        uint16_t objcnt;       // 0006  Number of memory objects
        uint32_t timestamp;    // 0008  Time EXE file was created/modified
        uint32_t symtaboff;    // 000c  Offset to the symbol table

        uint32_t symcount;     // 0010  Number of symbols
        uint16_t opthdrsize;   // 0014  Optional header size   - usually 0xe0
        uint16_t imageflags;   // 0016  Image flags

        // optheader:
        uint16_t coffmagic;    // 0018  Coff magic number (usually 0x10b)
        uint8_t linkmajor;     // 001a  The linker major version number
        uint8_t linkminor;     // 001b  The linker minor version number
        uint32_t codesize;     // 001c  Sum of sizes of all code sections

        uint32_t initdsize;    // 0020  Sum of all initialized data size
        uint32_t uninitdsize;  // 0024  Sum of all uninitialized data size
        uint32_t entryrva;     // 0028  rva Relative virt. addr. of entry point
        uint32_t codebase;     // 002c  rva Address of beginning of code section

        uint32_t database;     // 0030  rva Address of beginning of data section
        uint32_t vbase;        // 0034  Virtual base address of module
        uint32_t objalign;     // 0038  Object Virtual Address align. factor
        uint32_t filealign;    // 003c  Image page alignment/truncate factor

        uint16_t osmajor;      // 0040  The operating system major ver. no.
        uint16_t osminor;      // 0042  The operating system minor ver. no.
        uint16_t usermajor;    // 0044  The user major version number
        uint16_t userminor;    // 0046  The user minor version number
        uint16_t subsysmajor;  // 0048  The subsystem major version number
        uint16_t subsysminor;  // 004a  The subsystem minor version number
        uint32_t res1;         // 004c  Reserved bytes - must be 0

        uint32_t vsize;        // 0050  Virtual size of the entire image
        uint32_t hdrsize;      // 0054  Header information size    - 0x400
        uint32_t filechksum;   // 0058  Checksum for entire file
        uint16_t subsys;       // 005c  The subsystem type
        uint16_t dllflags;     // 005e  DLL flags

        uint32_t stackmax;     // 0060  Maximum stack size
        uint32_t stackinit;    // 0064  Initial committed stack size
        uint32_t heapmax;      // 0068  Maximum heap size
        uint32_t heapinit;     // 006c  Initial committed heap size

        uint32_t res2;         // 0070  Reserved bytes - must be 0
        uint32_t hdrextra;     // 0074  Number of extra info units in header
        infoitem info[16];     // 0078
        // 00f8  - o32 list

        enum { DEFAULT_FILEALIGN=0x200, DEFAULT_OBJECTALIGN=0x1000 };

        uint32_t FindFirstSegment(uint32_t flag, std::vector<o32rom_ptr> &o32rom)
        {
            auto i= std::find_if(o32rom.begin(), o32rom.end(), [flag](o32rom_ptr o32) {
                return o32->flags & flag;
            });
            if (i!=o32rom.end())
                return (*i)->rva;
            //printf("WARNING: no section with flag %08x found\n", flag);
            return 0;
        }
        uint32_t CalcSegmentSizeSum(uint32_t flag, std::vector<o32rom_ptr> &o32rom)
        {
            // note: vc10 requires explicit mentioning of the exe_reconstructor::e32exe class for the constabts
            uint32_t sum= 0;
            std::for_each(o32rom.begin(), o32rom.end(), [&sum, flag](o32rom_ptr o32) {
                if (o32->flags & flag)
                    sum += roundsize(o32->vsize, exe_reconstructor::e32exe::DEFAULT_FILEALIGN);
            });
            return sum;
        }
        uint32_t FindMaxRva(std::vector<o32rom_ptr> &o32rom)
        {
            // note: vc10 requires explicit mentioning of the exe_reconstructor::e32exe class for the constabts
            uint32_t maxrva= 0;
            std::for_each(o32rom.begin(), o32rom.end(), [&maxrva](o32rom_ptr o32) {
                if (roundsize(o32->rva + o32->vsize, exe_reconstructor::e32exe::DEFAULT_OBJECTALIGN) > maxrva )
                    maxrva= roundsize(o32->rva + o32->vsize, exe_reconstructor::e32exe::DEFAULT_OBJECTALIGN);
            });
            return maxrva;
        }
        e32exe(uint16_t cputype, e32rom_ptr rom, std::vector<o32rom_ptr> &o32rom)
        {
            magic= 0x00004550;
            cpu= cputype;
            objcnt= rom->objcnt;
            timestamp= rom->timestamp;
            symtaboff= 0;

            symcount= 0;
            opthdrsize= 0xe0;
            imageflags= rom->imageflags;      // no longer adding IMAGE_FILE_RELOCS_STRIPPED

            // optheader:
            coffmagic= 0x010b;
            linkmajor= 6;
            linkminor= 1;
            codesize= CalcSegmentSizeSum(IMAGE_SCN_CNT_CODE, o32rom);

            initdsize=  CalcSegmentSizeSum(IMAGE_SCN_CNT_INITIALIZED_DATA, o32rom);
            uninitdsize=CalcSegmentSizeSum(IMAGE_SCN_CNT_UNINITIALIZED_DATA, o32rom);
            entryrva= rom->entryrva;
            codebase= FindFirstSegment(IMAGE_SCN_CNT_CODE, o32rom);
                                                                                 
            database= FindFirstSegment(IMAGE_SCN_CNT_INITIALIZED_DATA, o32rom);
            vbase= rom->vbase;
            objalign= DEFAULT_OBJECTALIGN;
            filealign= DEFAULT_FILEALIGN;

            osmajor= 4;
            osminor= 0;
            usermajor= 0;
            userminor= 0;
            subsysmajor= rom->subsysmajor;
            subsysminor= rom->subsysminor;
            res1= 0;

            vsize= FindMaxRva(o32rom);
            hdrsize= 0; // set later
            filechksum= 0;
            subsys= rom->subsys;
            dllflags= 0;

            stackmax= rom->stackmax;
            stackinit= 0x1000;
            heapmax= 0x100000;
            heapinit= 0x1000;

            res2= 0;
            hdrextra= 16;

            for (int i=0 ; i<9 ; i++)
            {
                info[i].rva= rom->info[i].rva;
                info[i].size= rom->info[i].size;
            }
            info[COM].rva= rom->sect14rva;
            info[COM].size= rom->sect14size;
        }
        void appendexedata(ByteVector& hdr)
        {
            hdr.resize(hdr.size()+0x78+0x80);
            uint8_t *p= &hdr[hdr.size()-0x78-0x80];

            set32le(p+0x0000, magic);
            set16le(p+0x0004, cpu);
            set16le(p+0x0006, objcnt);
            set32le(p+0x0008, timestamp);
            set32le(p+0x000c, symtaboff);

            set32le(p+0x0010, symcount);
            set16le(p+0x0014, opthdrsize);
            set16le(p+0x0016, imageflags);

        // optheader:
            set16le(p+0x0018, coffmagic);
            set8  (p+0x001a, linkmajor);
            set8  (p+0x001b, linkminor);
            set32le(p+0x001c, codesize);

            set32le(p+0x0020, initdsize);
            set32le(p+0x0024, uninitdsize);
            set32le(p+0x0028, entryrva);
            set32le(p+0x002c, codebase);

            set32le(p+0x0030, database);
            set32le(p+0x0034, vbase);
            set32le(p+0x0038, objalign);
            set32le(p+0x003c, filealign);

            set16le(p+0x0040, osmajor);
            set16le(p+0x0042, osminor);
            set16le(p+0x0044, usermajor);
            set16le(p+0x0046, userminor);
            set16le(p+0x0048, subsysmajor);
            set16le(p+0x004a, subsysminor);
            set32le(p+0x004c, res1);

            set32le(p+0x0050, vsize);
            set32le(p+0x0054, hdrsize);
            set32le(p+0x0058, filechksum);
            set16le(p+0x005c, subsys);
            set16le(p+0x005e, dllflags);

            set32le(p+0x0060, stackmax);
            set32le(p+0x0064, stackinit);
            set32le(p+0x0068, heapmax);
            set32le(p+0x006c, heapinit);

            set32le(p+0x0070, res2);
            set32le(p+0x0074, hdrextra);
            for (int i=0 ; i<16 ; i++) {
                set32le(p+0x78+8*i, info[i].rva);
                set32le(p+0x7c+8*i, info[i].size);
            }
        }
    };
    typedef std::shared_ptr<e32exe> e32exe_ptr;
    struct o32exe {
        std::string name;    // 0000 Object name
        uint32_t vsize;      // 0008  Virtual memory size
        uint32_t rva;        // 000c  Object relative virtual address
        uint32_t psize;      // 0010  Physical file size of init. data
        uint32_t dataptr;    // 0014  Image pages offset
        uint32_t realaddr;   // 0018  pointer to actual
        uint32_t access;     // 001c  assigned access
        uint32_t temp3;      // 0020  #relocs,  #linenrs
        uint32_t flags;      // 0024  Attribute flags for the object

        bool isfixup;

        o32exe(o32rom_ptr rom, e32exe_ptr e32)
        {
            isfixup= false;

            if (e32->info[RES].equals(rom->rva, rom->vsize))
                name= ".rsrc";
            else if (e32->info[EXC].equals(rom->rva, rom->vsize))
                name= ".pdata";
            else if (e32->info[FIX].equals(rom->rva, rom->vsize)) {
                name= ".reloc";
                isfixup= true;
            }
            else if (rom->flags&IMAGE_SCN_CNT_CODE)
                name= ".text";
            else if (rom->flags&IMAGE_SCN_CNT_INITIALIZED_DATA)
                name= ".data";
            else if (rom->flags&IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                name= ".pdata";
            else
                name= ".other";

            vsize= rom->vsize;
            if ((rom->flags&IMAGE_SCN_TYPE_NOLOAD) && rom->realaddr==0) {
                // most likely reloc section
                rva= rom->rva;
                //printf("reloc: rom: rva=%08x, real=%08x, dataptr=%08x e.vbase=%08x\n", rom->rva, rom->realaddr, rom->dataptr, e32->vbase);
            }
            else {
                rva= rom->realaddr - e32->vbase;
            }
            psize= roundsize(rom->vsize, e32->filealign);       // note: ignoring rom psize, this is the compressed size.
            dataptr= 0;         // set later
            realaddr= 0;
            access= 0;
            temp3= 0;
            flags= rom->flags & ~IMAGE_SCN_COMPRESSED;
        }
        void appendexedata(ByteVector& hdr)
        {
            if (name.size()>=8)
                throw "section name > 8 chars";

            hdr.resize(hdr.size()+o32exe::size());
            uint8_t *p= &hdr[hdr.size()-o32exe::size()];
            std::copy(name.begin(), name.end(), p);
            if (name.size()<8)
                std::fill_n(p+name.size(), 8-name.size(), uint8_t(0));

            set32le(p+0x0008, vsize);
            set32le(p+0x000c, rva);
            set32le(p+0x0010, psize);
            set32le(p+0x0014, dataptr);
            set32le(p+0x0018, realaddr);
            set32le(p+0x001c, access);
            set32le(p+0x0020, temp3);
            set32le(p+0x0024, flags);
        }

        static size_t size() { return 0x28; }
    };
    typedef std::shared_ptr<o32exe> o32exe_ptr;

    // decompress fixup data as found in wince roms
    struct fixupdecompressor {
        template<typename ITER>
        static size_t getrelocvalue(uint32_t& value, int shift, ITER first, ITER last)
        {
            size_t n= 0;
            ITER p= first;
            while (p<last) {
                bool bit7= *p&0x80;
                value |= ((*p)&0x7f)<<shift;
                n++;

                if (!bit7)
                    return n;
                shift += 7;
                p++;
            }
            throw "getrelocvalue: buffer too short";
        }
        template<typename ITER>
        static void decompressrelocstring(ITER first, ITER last, DwordVector& relocs)
        {
            //printf("decompressrelocstring(%04x)\n", int(last-first));
            uint32_t base=0;
            ITER p= first;
            while (p<last) {
                //printf("%04x:<%02x>", int(p-first), *p);
                bool bit7= *p&0x80;
                if (bit7) {
                    uint32_t increment= 4*(((*p>>5)&3)+1);
                    uint32_t count= (*p&0x1f)+1;
                    p++;
                    uint32_t value= 0;
                    p+=getrelocvalue(value, 0, p, last);

                    base += value;
                    relocs.push_back(base);
                    while (count--) {
                        base += increment;
                        relocs.push_back(base);
                    }
                }
                else {
                    bool bit6= *p&0x40;
                    bool bit5= *p&0x20;

                    uint32_t value= *p&0x1f;
                    p++;
                    if (bit5)
                        p+=getrelocvalue(value, 5, p, last);

                    if (bit6)
                        base += value;
                    else {
                        printf("NOTE: unexpected compressed reloc with bit6=0 [%04x] b7:b6:b5=%d%d%d base=%08x val=%08x\n", int(p-first), bit7, bit6, bit5, base, value);
                        base = value;
                    }
                    relocs.push_back(base);
                }
            }
            //printf("reloc end base->%08x\n", base);
        }

        template<typename ITER>
        static void decompressrelocs(ITER first, ITER last, DwordVector& relocs)
        {
            //printf("decompressrelocs(%04x)\n", int(last-first));
            ITER p= first;
            while (p<last) {
                uint16_t unknown= (p+2<=last) ? get16le(p) : -1;
                p+=2;
                uint16_t size= (p+2<=last) ? get16le(p) : -1;
                p+=2;
                //printf("%04x={%04x %04x} ", int(p-4-first), unknown, size);

                if (p<last) {
                    if (unknown!=0xfd00 && unknown!=0xfe00)
                        decompressrelocstring(p, p+size, relocs);
                    else
                        printf("unhandled relocdata: [%04x] %s\n", unknown, hexdump(&*p, size).c_str());
                    p+=size;
                }
            }
        }
    };

    // pack a list of reloc ptrs as needed for win32 binaries
    struct fixupreconstructor {
        static void addfixupdata(ByteVector& fixupdata, uint32_t curpage, const WordVector& pagerelocs)
        {
            //printf("%08x:%08x %s\n", curpage, 8+2*pagerelocs.size(), vhexdump(pagerelocs).c_str());
            size_t fsize= 8+2*pagerelocs.size();
            fixupdata.resize(fixupdata.size()+fsize);
            uint8_t *p= &fixupdata[fixupdata.size()-fsize];
            set32le(p, curpage);
            set32le(p+4, fsize);
            // note: nonportable endian cast
            std::copy(pagerelocs.begin(), pagerelocs.end(), (uint16_t*)(p+8));
        }
        static void packrelocs(const DwordVector& relocs, ByteVector& fixupdata)
        {
            // IMAGE_REL_BASED_HIGHLOW == 3
            //  {pagerva, bytesizeofentirerecord, shorts},  
            //  short = (type<<12)|(reloc-pagerva)
            WordVector pagerelocs;
            uint32_t curpage= 0;
#ifndef _WIN32
            const int IMAGE_REL_BASED_HIGHLOW= 3;
#endif
            std::for_each(relocs.begin(), relocs.end(), [&curpage, &pagerelocs, &fixupdata](uint32_t reloc){
                if (curpage==0) {
                    curpage= reloc&~0xfff;
                }
                else if (curpage!=(reloc&~0xfff))
                {
                    if (pagerelocs.size()&1)
                        pagerelocs.push_back(0);
                    addfixupdata(fixupdata, curpage, pagerelocs);
                    curpage= reloc&~0xfff;
                    pagerelocs.clear();
                }
                pagerelocs.push_back((IMAGE_REL_BASED_HIGHLOW<<12)|(reloc&0xfff));
            });
            if (!pagerelocs.empty()) {
                if (pagerelocs.size()&1)
                    pagerelocs.push_back(0);
                addfixupdata(fixupdata, curpage, pagerelocs);
            }
        }
    };


    e32rom_ptr _e32rom;
    std::vector<o32rom_ptr> _o32rom;

    e32exe_ptr _e32exe;
    std::vector<o32exe_ptr> _o32exe;



    std::vector<sectioninfo_ptr> _sections;

    typedef std::map<uint32_t,infoitem> rvamap_t;
    rvamap_t _rvamap;

    uint16_t _cputype;

public:
    exe_reconstructor(uint16_t cputype)
        : _cputype(cputype)
    {
    }
    // todo: split in add e32 and o32
    void add_pe_data(const ByteVector &rompe)
    {
        if (rompe.size()<e32rom::size())
            throw "module: PE data block too small";
        _e32rom= e32rom_ptr(new e32rom(&rompe[0]));

        if (rompe.size() < e32rom::size() + _e32rom->objcnt*o32rom::size())
            throw "module: PE data block too small";
        if (rompe.size() > e32rom::size() + _e32rom->objcnt*o32rom::size())
            throw "module: PE data block too large";
        for (unsigned i=0 ; i<_e32rom->objcnt ; i++)
            _o32rom.push_back(o32rom_ptr(new o32rom(&rompe[e32rom::size()+o32rom::size()*i])));
    }
    void get_pe_data(ByteVector &rompe)
    {
        rompe.resize(e32rom::size()+_e32rom->objcnt*o32rom::size());
        _e32rom->getdata(&rompe[0]);
        for (unsigned i=0 ; i<_e32rom->objcnt ; i++)
            _o32rom[i]->getdata(&rompe[e32rom::size()+i*o32rom::size()]);
    }
    void printexe() const
    {
        _e32rom->printe32();
        if (_sections.size() != _o32rom.size())
            printf("WARNING: #sections=%d, #o32=%d\n", (int)_sections.size(), (int)_o32rom.size());
        for (unsigned i= 0 ; i<_o32rom.size() ; i++) 
            _o32rom[i]->printo32(i<_sections.size() ? _sections[i] : sectioninfo_ptr());
    }
    void add_sectioninfo(const std::string& name, uint64_t size, ReadWriter_ptr r)
    {
        _sections.push_back(sectioninfo_ptr(new sectioninfo(name, size, r)));
    }
    void append_mz_header(ByteVector &hdr)
    {
        uint8_t mzheader[]= {
            0x4d,0x5a,0x90,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0xff,0xff,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x80,0x00,0x00,0x00,        // peofs
            0x0e,0x1f,0xba,0x0e,0x00,0xb4,0x09,0xcd,0x21,0xb8,0x01,0x4c,0xcd,0x21,0x54,0x68,0x69,0x73,0x20,0x70,0x72,0x6f,0x67,0x72,0x61,0x6d,0x20,0x63,0x61,0x6e,0x6e,0x6f,0x74,0x20,0x62,0x65,0x20,0x72,0x75,0x6e,0x20,0x69,0x6e,0x20,0x44,0x4f,0x53,0x20,0x6d,0x6f,0x64,0x65,0x2e,0x0d,0x0d,0x0a,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };

        hdr.insert(hdr.end(), mzheader, mzheader+sizeof(mzheader));
    }
    void expandfixupdata(const ByteVector& comp, ByteVector& fixup)
    {
        //printf("comp: %s\n", vhexdump(comp).c_str());
        DwordVector relocs;
        fixupdecompressor::decompressrelocs(comp.begin(), comp.end(), relocs);

        // translate rva ( to match "rva= rom->realaddr - e32->vbase;"
        for (unsigned i=0 ; i<relocs.size() ; i++)
        {
            if (relocs[i] != find_rva_patch(relocs[i])) {
                relocs[i]= find_rva_patch(relocs[i]);
            }
        }
        //printf("reloc: %s\n", vhexdump(relocs).c_str());
        fixupreconstructor::packrelocs(relocs, fixup);
        //printf("fixup: %s\n", vhexdump(fixup).c_str());
    }
    void save(ReadWriter_ptr w)
    {
        if (_sections.size()!=_o32rom.size())
            throw "PE hdr and sectioncount don't match";
        _e32exe= e32exe_ptr(new e32exe(_cputype, _e32rom, _o32rom));

        const int mzsize= 0x80;
        const int pehdrsize= 0x18;

        uint32_t fileofs= _e32exe->hdrsize 
            = roundsize( mzsize + pehdrsize + _e32exe->opthdrsize
                    + o32exe::size()*_e32exe->objcnt, _e32exe->filealign);

        unsigned fixupix=-1;
        ByteVector fixupdata;
        for (unsigned i= 0 ; i<_o32rom.size() ; i++) {
            _o32exe.push_back(o32exe_ptr(new o32exe(_o32rom[i], _e32exe)));

            if (_o32exe[i]->isfixup)
            {
                fixupix= i;
                ByteVector compressedfixup;
                _sections[i]->copydata(ReadWriter_ptr(new ByteVectorWriter(compressedfixup)));

                try {
                expandfixupdata(compressedfixup, fixupdata);
                }
                catch(const char*msg) {
                    printf("ERROR: %s\n", msg);
                }
                catch(std::exception& e)
                {
                    printf("E: %s\n", e.what());
                }
                catch(...)
                {
                    printf("ERROR in expandfixupdata\n");
                }

                _o32exe[i]->vsize = fixupdata.size();
                _o32exe[i]->psize = roundsize(fixupdata.size(), _e32exe->filealign);
                _e32exe->info[FIX].size= fixupdata.size();
            }

            _o32exe[i]->dataptr= fileofs;

            if (_o32exe[i]->vsize && _o32exe[i]->name!=".pdata") {
                auto ins= _rvamap.insert(rvamap_t::value_type(_o32rom[i]->rva, infoitem(_o32exe[i]->rva, _o32exe[i]->vsize)));
                if (!ins.second) {
                    // note: this happens sometimes with .pdata and .data sections
                    printf("NOTE: duplicate rva %08x -> [%08x/%08x] and [%08x/%08x]\n",
                            _o32rom[i]->rva, _o32exe[i]->rva, _o32exe[i]->vsize,
                            (*ins.first).second.rva, (*ins.first).second.size);
                }
            }

            fileofs += roundsize(_o32exe.back()->psize, _e32exe->filealign);
        }

        ByteVector exehdr;

        append_mz_header(exehdr);
        _e32exe->appendexedata(exehdr);
        for (unsigned i=0 ; i<_o32exe.size() ; i++)
            _o32exe[i]->appendexedata(exehdr);

        w->write(&exehdr[0], exehdr.size());

        for (unsigned i= 0 ; i<_e32exe->objcnt ; i++)
        {
            w->setpos(_o32exe[i]->dataptr);
            if (fixupix==i) {
                w->write(&fixupdata[0], fixupdata.size());
            }
            else {
                _sections[i]->copydata(w);
            }
        }

        if (_e32exe->info[IMP].rva) {
            repair_import_table(w);
        }
        if (_e32exe->info[EXP].rva) {
            repair_export_table(w);
        }


        // mark end
        w->truncate(fileofs);
    }

    void repair_import_table(ReadWriter_ptr w)
    {
        uint32_t impofs;
        try {
        impofs= RvaToFileOfs(_e32exe->info[IMP].rva);
        }
        catch(const char*msg)
        {
            printf("rva2ofs(IMP:%08x) -> %s\n", _e32exe->info[IMP].rva, msg);
            return;
        }

        while (1) {
            w->setpos(impofs+0x10);
            uint32_t impaddr= w->read32le();
            if (impaddr==0)
                break;
            uint32_t newimpaddr= find_rva_patch(impaddr);
            if (newimpaddr!=impaddr) {
                w->setpos(impofs+0x10);
                w->write32le(newimpaddr);
            }

            impofs += 0x14;
        }
    }
    void repair_export_table(ReadWriter_ptr w)
    {
        uint32_t expofs;
        try {
        expofs= RvaToFileOfs(_e32exe->info[EXP].rva);
        }
        catch(const char*msg)
        {
            printf("rva2ofs(EXP:%08x) -> %s\n", _e32exe->info[EXP].rva, msg);
            return;
        }


        uint32_t eatrva= w->read32le(expofs+0x1c);
        uint32_t cnt= w->read32le(expofs+0x14);
        uint32_t eatofs= RvaToFileOfs(eatrva);

        for (unsigned i=0 ; i<cnt ; i++) {
            w->setpos(eatofs);
            uint32_t expaddr= w->read32le();
            uint32_t newexpaddr= find_rva_patch(expaddr);
            if (newexpaddr!=expaddr) {
                w->setpos(eatofs);
                w->write32le(newexpaddr);
            }

            eatofs += 4;
        }
    }


    uint32_t find_rva_patch(uint32_t romrva)
    {
        for (auto i= _rvamap.begin() ; i!=_rvamap.end() ; i++)
        {
            if ((*i).first <= romrva && romrva < (*i).first+(*i).second.size)
                return romrva-(*i).first+(*i).second.rva;
        }
        return romrva;
    }

    uint32_t RvaToFileOfs(uint32_t rva)
    {
        for (auto i= _o32exe.begin() ; i!=_o32exe.end() ; i++)
        {
            if ((*i)->rva<=rva && rva<(*i)->rva+(*i)->psize)
                return rva-(*i)->rva+(*i)->dataptr;
        }
        throw "rva not found";
    }

    uint32_t o32datarva(size_t ix)    { return _o32rom[ix]->dataptr; }
    uint32_t o32compressed(size_t ix) { return _o32rom[ix]->flags&IMAGE_SCN_COMPRESSED; }
    uint32_t o32datasize(size_t ix)   { return std::min(_o32rom[ix]->vsize, _o32rom[ix]->psize); }
    uint32_t o32compsize(size_t ix)   { return o32datasize(ix); }
    uint32_t o32fullsize(size_t ix)   { return _o32rom[ix]->vsize; }
    uint32_t nr_o32_sections() const { return _e32rom->objcnt; }
};

bool exe_reconstructor::e32rom::g_wm2003;


// used for importing .exe/.dll as a module
class exereader {
struct mzheader {
    uint16_t magic;
    uint32_t lfanew;
    mzheader(const uint8_t *p)
    {
        magic= get16le(p);
        //
        lfanew= get32le(p+0x3c);
    }
    bool isvalid() const
    {
        return magic==0x5a4d;
    }
    static uint32_t size() { return 0x40; }
};

struct peheader {
    uint32_t magic;        // Magic number E32_MAGIC
    uint16_t cpu;          // The CPU type
    uint16_t objcnt;       // Number of memory objects
    uint32_t timestamp;    // Time EXE file was created/modified
    uint32_t symtaboff;    // Offset to the symbol table
    uint32_t symcount;     // Number of symbols
    uint16_t opthdrsize;   // Optional header size
    uint16_t imageflags;   // Image flags

    static uint32_t size() { return 0x18; }
    peheader(const uint8_t *p)
    {
        magic        = get32le(p);    // 0x00004550
        cpu          = get16le(p+4);  // 0x01c0 for armv4, 0x01c2 for armv4t
        objcnt       = get16le(p+6);  // small number ( usually < 0x10 )
        timestamp    = get32le(p+8);  // ??
        symtaboff    = get32le(p+12);
        symcount     = get32le(p+16);
        opthdrsize   = get16le(p+20); // usually 0xe0
        imageflags   = get16le(p+22);
    }
    bool isvalid()
    {
        return magic==0x4550;
    }
};
struct optheader {
    uint32_t _size;
    
    uint16_t coffmagic;          // Coff magic number (usually 0x10b)
    uint8_t linkmajor;           // The linker major version number
    uint8_t linkminor;           // The linker minor version number
    uint32_t codesize;           // Sum of sizes of all code sections
    uint32_t initdsize;          // Sum of all initialized data size
    uint32_t uninitdsize;        // Sum of all uninitialized data size
    uint32_t entryrva;           // rva Relative virt. addr. of entry point
    uint32_t codebase;           // rva Address of beginning of code section
    uint32_t database;           // rva Address of beginning of data section
    uint32_t vbase;              // Virtual base address of module
    uint32_t objalign;           // Object Virtual Address align. factor
    uint32_t filealign;          // Image page alignment/truncate factor
    uint16_t osmajor;            // The operating system major ver. no.
    uint16_t osminor;            // The operating system minor ver. no.
    uint16_t usermajor;          // The user major version number
    uint16_t userminor;          // The user minor version number
    uint16_t subsysmajor;        // The subsystem major version number
    uint16_t subsysminor;        // The subsystem minor version number
    uint32_t res1;               // Reserved bytes - must be 0
    uint32_t vsize;              // Virtual size of the entire image
    uint32_t hdrsize;            // Header information size
    uint32_t filechksum;         // Checksum for entire file
    uint16_t subsys;             // The subsystem type
    uint16_t dllflags;           // DLL flags
    uint32_t stackmax;           // Maximum stack size
    uint32_t stackinit;          // Initial committed stack size
    uint32_t heapmax;            // Maximum heap size
    uint32_t heapinit;           // Initial committed heap size
    uint32_t res2;               // Reserved bytes - must be 0
    uint32_t hdrextra;           // Number of extra info units in header

    struct info {
        uint32_t rva;
        uint32_t size;
    };
    std::vector<info> inf;

    optheader(const uint8_t *p, uint32_t size)
        : _size(size)
    {
        coffmagic    = size<0x2 ? 0 : get16le(p+0x0);  // 0x010b
        linkmajor    = size<0x3 ? 0 : get8(p+0x2);
        linkminor    = size<0x4 ? 0 : get8(p+0x3);
        codesize     = size<0x8 ? 0 : get32le(p+0x4);
        initdsize    = size<0xc ? 0 : get32le(p+0x8);
        uninitdsize  = size<0x10 ? 0 : get32le(p+0xc);
        entryrva     = size<0x14 ? 0 : get32le(p+0x10);
        codebase     = size<0x18 ? 0 : get32le(p+0x14);
        database     = size<0x1c ? 0 : get32le(p+0x18);
        vbase        = size<0x20 ? 0 : get32le(p+0x1c);
        objalign     = size<0x24 ? 0 : get32le(p+0x20);  // 0x1000
        filealign    = size<0x28 ? 0 : get32le(p+0x24);  // 0x0200
        osmajor      = size<0x2a ? 0 : get16le(p+0x28);
        osminor      = size<0x2c ? 0 : get16le(p+0x2a);
        usermajor    = size<0x2e ? 0 : get16le(p+0x2c);
        userminor    = size<0x30 ? 0 : get16le(p+0x2e);
        subsysmajor  = size<0x32 ? 0 : get16le(p+0x30);
        subsysminor  = size<0x34 ? 0 : get16le(p+0x32);
        res1         = size<0x38 ? 0 : get32le(p+0x34);
        vsize        = size<0x3c ? 0 : get32le(p+0x38);
        hdrsize      = size<0x40 ? 0 : get32le(p+0x3c);  // usually 0x400
        filechksum   = size<0x44 ? 0 : get32le(p+0x40);
        subsys       = size<0x46 ? 0 : get16le(p+0x44);
        dllflags     = size<0x48 ? 0 : get16le(p+0x46);
        stackmax     = size<0x4c ? 0 : get32le(p+0x48);
        stackinit    = size<0x50 ? 0 : get32le(p+0x4c);
        heapmax      = size<0x54 ? 0 : get32le(p+0x50);
        heapinit     = size<0x58 ? 0 : get32le(p+0x54);
        res2         = size<0x5c ? 0 : get32le(p+0x58);
        hdrextra     = size<0x60 ? 0 : get32le(p+0x5c); // 0x10

        if (hdrextra*8+0x60>size)
            throw "invalid opthdr.extra";
        if (hdrextra) {
            inf.resize(hdrextra);
            for (unsigned i=0 ; i<hdrextra ; i++)
            {
                inf[i].rva= get32le(p+0x60+8*i);
                inf[i].size= get32le(p+0x60+8*i+4);
            }
        }
    }
    bool isvalid()
    {
        return coffmagic==0x010b;
    }
};
struct o32header {
    std::string name;     // Object name
    uint32_t vsize;       // Virtual memory size
    uint32_t rva;         // Object relative virtual address
    uint32_t psize;       // Physical file size of init. data
    uint32_t dataptr;     // Image pages offset
    uint32_t realaddr;    // pointer to actual
    uint32_t access;      // assigned access
    uint32_t temp3; 
    uint32_t flags;       // Attribute flags for the object

    static uint32_t size() { return 0x28; }
    o32header(const uint8_t *p)
    {
        name=       getstr(p, 8);

        vsize=      get32le(p+0x08);
        rva=        get32le(p+0x0c);
        psize=      get32le(p+0x10);
        dataptr=    get32le(p+0x14);
        realaddr=   get32le(p+0x18);
        access=     get32le(p+0x1c);
        temp3=      get32le(p+0x20);
        flags=      get32le(p+0x24);
    }
    bool isvalid()
    {
        return true;
    }
};

    std::shared_ptr<mzheader> mz;
    std::shared_ptr<peheader> pe;
    std::shared_ptr<optheader> opt;
    std::vector<std::shared_ptr<o32header> > o32;
    
    void load(ReadWriter_ptr r)
    {
        ByteVector mzhdr(mzheader::size());
        r->read(&mzhdr[0], mzhdr.size());

        mz.reset(new mzheader(&mzhdr[0]));
        if (!mz->isvalid() || mz->lfanew+0xf8 > r->size())
            throw "invalid mz header";

        r->setpos(mz->lfanew);

        ByteVector pehdr(peheader::size());
        r->read(&pehdr[0], pehdr.size());

        pe.reset(new peheader(&pehdr[0]));
        if (!pe->isvalid())
            throw "invalid pe header";

        ByteVector opthdr(pe->opthdrsize);
        r->read(&opthdr[0], opthdr.size());
        opt.reset(new optheader(&opthdr[0], opthdr.size()));
        if (!opt->isvalid())
            throw "invalid opt header";

        r->setpos(mz->lfanew+peheader::size()+pe->opthdrsize);
        ByteVector o32hdr(o32header::size()*pe->objcnt);

        for (unsigned i=0 ; i<pe->objcnt ; i++)
            o32.push_back(std::shared_ptr<o32header>(new o32header(&o32hdr[i*o32header::size()])));
    }

};

class filetypefilter {
public:
    virtual ~filetypefilter() { }
    virtual bool match(ReadWriter_ptr file)= 0;
};
typedef std::shared_ptr<filetypefilter> filetypefilter_ptr;

class FileContainer {
public:
    virtual ~FileContainer() { }

    virtual void addfile(const std::string&romname, ReadWriter_ptr r)= 0;
    virtual void renamefile(const std::string&romname, const std::string&newname)= 0;
    virtual void deletefile(const std::string&romname)= 0;
    virtual std::string infostring() const= 0;
    virtual void printfileinfo(const std::string&romname)= 0;
    virtual bool extractfile(const std::string&romname, const std::string& dstpath, filetypefilter_ptr filter)= 0;
    virtual void listfiles()= 0;
    virtual void dirhexdump()= 0;

    typedef std::function<void(const std::string& romname)> namefn;
    virtual void filename_enumerator(namefn fn)= 0;
};
typedef std::shared_ptr<FileContainer> FileContainer_ptr;

class ImgfsFile : public FileContainer {
    ReadWriter_ptr _rd;

public:
    std::string name() { return "imgfs"; }
    static bool isimgfsheader(ReadWriter_ptr rd, uint64_t ofs)
    {
        const uint8_t imgfsuuid[16]= {
            0xf8, 0xac, 0x2c, 0x9d, 0xe3, 0xd4, 0x2b, 0x4d, 0xbd, 0x30, 0x91, 0x6e, 0xd8, 0x4f, 0x31, 0xdc
        };
        rd->setpos(ofs);
        ByteVector sig(16);
        rd->read(&sig[0], sig.size());

        return std::equal(imgfsuuid, imgfsuuid+sizeof(imgfsuuid), &sig[0]);
    }

    // FlashLayoutSector ( see Fal/fls.h )
    //    "MSFLSH50"        
    //       00000020    - size of reserved
    //       00000054    - size of flashregions
    //    --- reserved entries
    //    "LOGO"                 00000000    00000009
    //    "MODEM"                00000009    00000010
    //    --- FlashRegion entries
    //      type     pstart   psize    lsize    sec/blk  byt/blk  compact
    //      00000000 00000000 00000000 00000054 00000040 00020000 00000000  xip
    //      00000001 00000000 00000000 00000684 00000040 00020000 00000002  readonly
    //      00000002 00000000 00000000 ffffffff 00000040 00020000 00000002  filesys
    static uint64_t find_header(ReadWriter_ptr rd)
    {
        if (isimgfsheader(rd, 0))
            return 0;

        const uint8_t msflshsig[8]= { 'M', 'S', 'F', 'L', 'S', 'H', '5', '0' }; 
        ByteVector sec0(512);
        rd->setpos(0);
        rd->read(&sec0[0], sec0.size());
        if (!PartitionTable::isvalidptable(sec0))
            throw "partition table not found";
        ByteVector sec1(512);
        unsigned ssize;
        for (ssize= 512 ; ssize<=65536 ; ssize*=2)
        {
            rd->setpos(ssize);
            rd->read(&sec1[0], sec0.size());
            if (std::equal(msflshsig, msflshsig+sizeof(msflshsig), &sec1[0]))
                break;
            //printf("nohdr: %08x : %s\n", ssize, hexdump(&sec1[0], 16).c_str());
        }
        if (ssize>65536)
            throw "MSFLSH50 header not found";

        PartitionTable ptab(sec0, ssize);

        PartitionTable::Entry *ent25= ptab.firstoftype(0x25);
        if (!ent25)
            throw "partition table has no imgfs";
        printf("found ent25 : %08llx-%08llx\n", ent25->start(), ent25->size());

        if (isimgfsheader(rd, ent25->start()))
            return ent25->start();

        throw "could not find imgfs header";
    }

    enum entrytype_t : char {
        FILEENTRY= 'f',
        NAMEENTRY='n',
        FREEENTRY=' ',
        SECTIONENTRY='s',
    };

    class DirEntry {
        uint64_t _ofs;

        class DirEntryReader : public ReadWriter {
            struct area_t {
                uint32_t ix;
                uint32_t fileofs;
                uint32_t dataofs;
                uint32_t compsize;
                uint32_t fullsize;
            };
            typedef std::map<uint32_t,area_t> areamap_t;
            areamap_t _areas;
            ImgfsFile& _imgfs;
            uint32_t _pos;
        public:
            DirEntryReader(DirEntry& dir, ImgfsFile& imgfs)
                : _imgfs(imgfs), _pos(0)
            {
                uint32_t fileofs= 0;
                uint32_t ix=0;
                //printf("ixtab: ");
                dir.datatable_enumerator(_imgfs, [this, &fileofs, &ix](uint64_t ofs, size_t compsize, size_t fullsize)
                    {
                        area_t& a= _areas[fileofs];
                        a.ix= ix;
                        a.fileofs= fileofs;
                        a.fullsize= fullsize;
                        a.dataofs= ofs;
                        a.compsize= compsize;

                        fileofs += fullsize;
                        ix++;

                        //printf(" %08x:%04x/%04x", uint32_t(ofs), compsize, fullsize);
                    }
                );
                //printf("\n");
            }
            virtual ~DirEntryReader() { }
            virtual size_t read(uint8_t*p, size_t n)
            {
                size_t total= 0;

                while (_pos<size() && total < n) {
                    area_t &a= findarea(_pos);

                    //printf("ofs %08x -> area file:%08x/%04x data:%08x/%04x\n", uint32_t(_pos), a.fileofs, a.fullsize, a.dataofs, a.compsize);

                    size_t blockpos= _pos-a.fileofs;
                    size_t want= std::min(a.fullsize-blockpos, n-total);

                    ByteVector compdata(a.compsize);
                    _imgfs.rd()->setpos(a.dataofs);
                    _imgfs.rd()->read(&compdata[0], compdata.size());
                    ByteVector fulldata(a.fullsize);

                    if (a.compsize<a.fullsize) {
                        _imgfs.decompress(&compdata[0], a.compsize, &fulldata[0], a.fullsize);
                    }
                    else if (a.compsize==a.fullsize) {
                        std::copy(&compdata[0], &compdata[a.compsize], &fulldata[0]);
                    }
                    else {
                        printf("ERROR: @%08x, comp=%08x, full=%08x\n", a.dataofs, int(a.compsize), int(a.fullsize));
                        throw "index error: fullsize < compsize";
                    }

                    std::copy(&fulldata[blockpos], &fulldata[blockpos+want], p);

                    total += want;
                    p += want;
                    _pos += want;
                }

                return total;
            }

            virtual void write(const uint8_t *p, size_t n)
            {
                throw "writing dirent through reader not implemented";
            }
            virtual void setpos(uint64_t off)
            {
                _pos= off;
            }
            virtual void truncate(uint64_t off)
            {
                throw "truncate dirent not implemented";
            }

            area_t& findarea(uint32_t ofs)
            {
                auto i= _areas.upper_bound(ofs);
                if (i==_areas.begin()) i= _areas.end(); else i--;

                if (i==_areas.end())
                    throw "dirent-filereader: no areas";

                return i->second;
            }
            virtual uint64_t size()
            {
                if (_areas.empty())
                    return 0;
                return _areas.rbegin()->second.fileofs + _areas.rbegin()->second.fullsize;
            }
            virtual uint64_t getpos() const
            {
                return _pos;
            }
            virtual bool eof()
            {
                return _pos>=size();
            }
        };
    protected:
        uint32_t _magic;
        // for file/section entry
        uint32_t _indexptr;
        uint32_t _indexsize;
        uint32_t _size;
    public:
        explicit DirEntry(uint64_t ofs)
            : _ofs(ofs), _magic(0), _indexptr(0), _indexsize(0), _size(0)
        {
        }
        DirEntry()
            : _ofs(0), _magic(0), _indexptr(0), _indexsize(0), _size(0)
        {
        }
        virtual ~DirEntry() { }
        uint32_t offset() const {
            if (_ofs>>32)
                throw "offset too large";
            return (uint32_t)_ofs;
        }

        void save(ImgfsFile& imgfs)
        {
            if (_ofs==0)
                _ofs= imgfs.allocent(tag());
            ByteVector data(imgfs.direntsize());
            getdata(&data[0], imgfs);
            //printf("DirEntry[%08x]. save\n", _ofs);
            imgfs.rd()->setpos(_ofs);
            imgfs.rd()->write(&data[0], data.size());
        }
        // subclasses have 2 constructors:
        //    1 for decoding a (const uint8_t*pentry)
        //    1 for constructing from values
        //
        //
        // method to serialize entry to data
        virtual void getdata(uint8_t*pdata, ImgfsFile& imgfs)= 0;
        virtual entrytype_t tag() const= 0;



        template<typename datablockfn>
        void datatable_enumerator(ImgfsFile& imgfs, datablockfn fn)
        {
            if (_indexptr==0 || _indexsize==0)
                return;
            ByteVector ixblock(_indexsize);
            imgfs.rd()->setpos(_indexptr);
            imgfs.rd()->read(&ixblock[0], ixblock.size());

            uint32_t total= 0;
            for (ByteVector::iterator i= ixblock.begin() ; i+8<=ixblock.end() ; )
            {
                uint16_t compsize=get16le(i); i+=2;
                uint16_t fullsize=get16le(i); i+=2;
                uint32_t ptr=get32le(i); i+=4;

                if (compsize && fullsize && ptr)
                    fn(ptr, compsize, fullsize);
                total += fullsize;
            }
            if (total!=_size)
                printf("WARNING: %08llx[%08x] : indextotal= %08x, ent.size=%08x\n", _ofs, _magic, total, _size);
        }

        void deletedirent(ImgfsFile& imgfs)
        {
            datatable_enumerator(imgfs, [&imgfs](uint64_t ofs, size_t compsize, size_t /*fullsize*/) {
                    imgfs.freechunk(ofs, compsize);
                }
            );
            if (_indexptr)
                imgfs.freechunk(_indexptr, _indexsize);

            imgfs.freeent(offset());
        }
        void savedirent(ImgfsFile& imgfs, ReadWriter_ptr w)
        {
            datatable_enumerator(imgfs, [&imgfs, w](uint64_t ofs, size_t compsize, size_t fullsize) {
                    ByteVector compdata(compsize);
                    imgfs.rd()->setpos(ofs);
                    imgfs.rd()->read(&compdata[0], compsize);

                    if (fullsize>compsize) {
                        ByteVector fulldata(fullsize);
                        imgfs.decompress(&compdata[0], compsize, &fulldata[0], fullsize);
                        w->write(&fulldata[0], fullsize);
                    }
                    else if (fullsize==compsize) {
                        // compsize == fullsize -> not compressed
                        w->write(&compdata[0], compsize);
                    }
                    else {
                        printf("ERROR: @%08llx, comp=%08x, full=%08x\n", ofs, int(compsize), int(fullsize));
                        throw "index error: fullsize < compsize";
                    }
                }
            );
        }
        size_t calc_compressed_size(ImgfsFile& imgfs)
        {
            size_t comptotal= 0;
            size_t fulltotal= 0;
            datatable_enumerator(imgfs, [&comptotal, &fulltotal](uint64_t ofs, size_t compsize, size_t fullsize) {
                    comptotal+=compsize;
                    fulltotal+=fullsize;
                }
            );
            if (fulltotal!=_size)
                printf("WARNING: stored size=%d, calculated size: %d\n", _size, int(fulltotal));

            return comptotal;

        }

        // extract data via index block
        ByteVector getdatablock(ImgfsFile& imgfs)
        {
            ByteVector filedata;
            savedirent(imgfs, ReadWriter_ptr(new ByteVectorWriter(filedata)));
            return filedata;
        }

        std::string entstring() const
        {
            return stringformat("i->%08x:%08x", _indexptr, _indexsize);
        }

        uint32_t size() const { return _size; }
        uint32_t indexblock() const { return _indexptr; }
        uint32_t indexsize() const { return _indexsize; }

        ReadWriter_ptr getdatareader(ImgfsFile& imgfs)
        {
            return ReadWriter_ptr(new DirEntryReader(*this, imgfs));
        }

    };
    class NameEntry : public DirEntry {
        std::string _name;
    public:
        enum { MAGIC= 0xFFFFFEFBu };
        virtual entrytype_t tag() const { return NAMEENTRY; }
        NameEntry(uint64_t ofs, const uint8_t *p, size_t len)
            : DirEntry(ofs)
        {
            _magic= get32le(p);
            if (_magic!=MAGIC)
                throw stringformat("NameEntry@%08x: invalid magic: %08x", offset(), _magic);

            _name= ToString(std::Wstring((const WCHAR*)(p+4), len));
        }
        explicit NameEntry(const std::string& name)
            : _name(name)
        {
            _magic= MAGIC;
        }
        virtual ~NameEntry() { }

        virtual void getdata(uint8_t* p, ImgfsFile& /*imgfs*/)
        {
            set32le(p, _magic);
            std::Wstring wstr= ToWString(_name);
            wstr.resize(24);
            // note: nonportable endian cast
            std::copy(wstr.begin(), wstr.end(), (WCHAR*)(p+4));
        }
        std::string name() const
        {
            return _name;
        }
    };
    class nameinfo {
        uint16_t _length;
        uint16_t _flags;
        uint32_t _hash;
        uint32_t _ptr;
        std::string _name;
    public:
        // note: pass ptr to name in file or section entry
        nameinfo(const uint8_t *p)
        {
            _length= get16le(p);
            _flags= get16le(p+2);
            if (_length<=4) {
                _name= ToString(std::Wstring((const WCHAR*)(p+4), 4));
                _hash= 0;
                _ptr= 0;
            }
            else {
                _hash= get32le(p+4);
                _ptr= get32le(p+8);
            }
        }
        nameinfo(const std::string& name)
            : _name(name)
        {
            _length= 0;
            _flags= 0;
            _hash= 0;
            _ptr= 0;
        }
        void setname(const std::string& name)
        {
            _name= name;
        }

        enum { IN_DIR_ENTRY, IN_NAME_ENTRY, IN_NAME_CHUNK };
        static int nametype(size_t len)
        {
            if (len<=4)
                return IN_DIR_ENTRY;
            else if (len<=24)
                return IN_NAME_ENTRY;
            else
                return IN_NAME_CHUNK;
        }
        void getdata(uint8_t *p, ImgfsFile& imgfs)
        {
            int oldtype= nametype(_length);
            int newtype= nametype(_name.size());

            // first free resources
            if (oldtype!=newtype) {
                if (oldtype==IN_NAME_ENTRY)
                    imgfs.freeent(_ptr);
                else if (oldtype==IN_NAME_CHUNK)
                    imgfs.freechunk(_ptr, imgfs.roundtochunk(_length*sizeof(WCHAR)));
                _ptr= 0;
            }
            if (_name.size()>=0x10000)
                throw "filename too long";
            _length= (uint16_t)_name.size();
            set16le(p, _length);
            if (newtype==IN_DIR_ENTRY) {
                set16le(p+2, _flags);
                std::Wstring wstr= ToWString(_name);
                std::fill_n((WCHAR*)(p+4), 4, WCHAR(0));
                // note: nonportable endian cast
                std::copy(wstr.begin(), wstr.end(), (WCHAR*)(p+4));
            }
            else {
                if (_ptr==0) {
                    std::Wstring wstr= ToWString(_name);
                    if (newtype==IN_NAME_ENTRY)
                    {
                        _flags|= 2;
                        NameEntry ent(_name);
                        ent.save(imgfs);
                        _ptr= ent.offset();
                    }
                    else {
                        size_t rounded= imgfs.roundtochunk(wstr.size()*sizeof(WCHAR));
                        // alloc chunk
                        _ptr= imgfs.allocchunk(rounded, NAMECHUNK);

                        wstr.resize(rounded/sizeof(WCHAR));
                        imgfs.rd()->setpos(_ptr);
                        //printf("nameinfo: getdata(%08x)\n", _ptr);
                        imgfs.rd()->write((const uint8_t*)wstr.c_str(), rounded);
                    }
                }
                _hash= calc_name_hash(_name);
                set16le(p+2, _flags);
                set32le(p+4, _hash);
                set32le(p+8, _ptr);
            }
        }
        // note: passing name by value!
        static uint32_t calc_name_hash(std::string name)
        {
            if (name.size()<=4)
                return 0;
            unsigned i= name.find_last_of('.');
            if (i==name.size()-4 && i>=4)
                name.resize(i);

            return (name[0]<<24)|(name[1]<<16)|(name[name.size()-2]<<8)|(name[name.size()-1]);
        }

        std::string name(ImgfsFile& imgfs)
        {
            if (_name.empty()) {
                if (_flags&2) {
                    ByteVector entdata(imgfs.direntsize());
                    imgfs.rd()->setpos(_ptr);
                    imgfs.rd()->read(&entdata[0], entdata.size());
                    NameEntry ent(_ptr, &entdata[0], _length);
                    _name= ent.name();
                }
                else {
                    imgfs.rd()->setpos(_ptr);

                    std::Wstring wstr;
                    readutf16le(imgfs.rd(), wstr, _length);

                    _name= ToString(wstr);
                }
            }
            return _name;
        }
        std::string shortname()
        {
            return _name;
        }

        template<typename entryfn, typename chunkfn>
        void name_enumerator(entryfn efn, chunkfn cfn)
        {
            if (_length<=4) {
                // nop
            }
            else if (_flags&2) {
                efn(_ptr);
            }
            else {
                cfn(_ptr, _length*sizeof(WCHAR));
            }
        }

        void deletename(ImgfsFile& imgfs)
        {
            name_enumerator(
                [&imgfs](uint64_t dirofs) { imgfs.freeent(dirofs); },
                [&imgfs](uint64_t ofs, size_t size) { imgfs.freechunk(ofs, size); }
            );
        }
    };
    class SectionEntry : public DirEntry {
        nameinfo _name;
        uint32_t _datatable;
        uint32_t _nextsection;

    public:
        enum { MAGIC= 0xFFFFF6FDu };
        virtual entrytype_t tag() const { return SECTIONENTRY; }
        SectionEntry(uint64_t ofs, const uint8_t *pdata)
            : DirEntry(ofs), _name(pdata+12)
        {
            _magic= get32le(pdata);
            if (_magic!=MAGIC)
                throw stringformat("SectionEntry@%08x: invalid magic: %08x", offset(), _magic);
            _datatable= get32le(pdata+4);
            _nextsection= get32le(pdata+8);
            //name : pdata+12
            _size= get32le(pdata+24);
            _indexptr= get32le(pdata+28);
            _indexsize= get32le(pdata+32);

            if (std::find_if(pdata+36, pdata+36+16, [](uint8_t t) { return t!=0; })!=pdata+36+16)
                printf("WARNING: %08x :sectionent+24 not nul: %s\n", offset(), hexdump(pdata+36, 16).c_str());
            if (_datatable)
                printf("WARNING: %08x : sectionent datatable=%08x\n", offset(), _datatable);

        }
        explicit SectionEntry(const std::string& name)
            : _name(name)
        {
            _magic= MAGIC;
            _datatable=0;
            _nextsection=0;
            _size=0;
            _indexptr=0;
            _indexsize=0;
        }
        virtual ~SectionEntry() { }
        virtual void getdata(uint8_t *pdata, ImgfsFile& imgfs)
        {
            set32le(pdata, _magic);
            set32le(pdata+4, _datatable);
            set32le(pdata+8, _nextsection);
            _name.getdata(pdata+12, imgfs);
            set32le(pdata+24, _size);
            set32le(pdata+28, _indexptr);
            set32le(pdata+32, _indexsize);
            std::fill_n(pdata+36, 16, uint8_t(0));
        }
        void deletesection(ImgfsFile& imgfs)
        {
            _name.deletename(imgfs);
            deletedirent(imgfs);
        }
        void listsection(ImgfsFile& imgfs)
        {
            if (g_verbose>1) {
                size_t compsize= calc_compressed_size(imgfs);
                printf("         %08x: n->%08x %9d %9d                       %s %s\n",
                        offset(), _nextsection, _size, int(compsize), entstring().c_str(), _name.name(imgfs).c_str());
            }
            else {
                printf("         %08x: n->%08x %9d                        %s %s\n",
                        offset(), _nextsection, _size, entstring().c_str(), _name.name(imgfs).c_str());
            }
        }
        uint32_t nextsection() const { return _nextsection; }
        nameinfo &ni() { return _name; }
    };
    typedef std::shared_ptr<SectionEntry> SectionEntry_ptr;



    class FileEntry : public DirEntry {
        uint32_t _datatable;
        uint32_t _sectionlist;
        nameinfo _name;
        uint32_t _attr;
        uint64_t _filetime;
        uint32_t _reserved;

    public:
        // note: 0xFFFFFEFEu    for module entry
        enum { MAGIC= 0xFFFFF6FEu };
        virtual entrytype_t tag() const { return FILEENTRY; }
        FileEntry(uint64_t ofs, const uint8_t *pdata)
            : DirEntry(ofs), _name(pdata+12)
        {
            _magic= get32le(pdata);
            if ((_magic&~0x800)!=MAGIC)
                throw stringformat("FileEntry@%08x: invalid magic: %08x", offset(), _magic);

            _datatable= get32le(pdata+4);
            _sectionlist= get32le(pdata+8);
            //name : pdata+12
            _size= get32le(pdata+24);
            _attr= get32le(pdata+28);
            _filetime= get64le(pdata+32);
            _reserved= get32le(pdata+40);
            _indexptr= get32le(pdata+44);
            _indexsize= get32le(pdata+48);

            if (_datatable)
                printf("warning: file datatable= %08x\n", _datatable);
        }
        explicit FileEntry(const std::string& name)
            : _name(name)
        {
            _magic= MAGIC;
            _datatable=0;
            _sectionlist=0;
            _size=0;
            _attr= 0x41;
            _filetime= 0;
            _reserved= 0;
            _indexptr=0;
            _indexsize=0;
        }
        virtual ~FileEntry() { }
        uint64_t getunixtime() const {
            return filetimetounix(_filetime);
        }
        void setunixtime(uint64_t t)
        {
            _filetime= unixtofiletime(t);
        }
        virtual void getdata(uint8_t *pdata, ImgfsFile& imgfs)
        {
            set32le(pdata, _magic);
            set32le(pdata+4, _datatable);
            set32le(pdata+8, _sectionlist);
            _name.getdata(pdata+12, imgfs);
            set32le(pdata+24, _size);
            set32le(pdata+28, _attr);
            set64le(pdata+32, _filetime);
            set32le(pdata+40, _reserved);
            set32le(pdata+44, _indexptr);
            set32le(pdata+48, _indexsize);
        }
        template<typename sectionfn>
        void section_enumerator(ImgfsFile& imgfs, sectionfn fn)
        {
            uint64_t ofs= _sectionlist;
            while (ofs)
            {
                ByteVector entdat(imgfs.direntsize());
                imgfs.rd()->setpos(ofs);
                imgfs.rd()->read(&entdat[0], entdat.size());
                SectionEntry_ptr ent(new SectionEntry(ofs, &entdat[0]));

                fn(ent);
                ofs= ent->nextsection();
            }
        }
        void fromstream(ImgfsFile& imgfs, ReadWriter_ptr r)
        {
            //printf("fromstream\n");
            ByteVector indexdata;
            ByteVector buf(4096);
            uint64_t ofs=0;
            while (true)
            {
                size_t fullsize= r->read(&buf[0], buf.size());
                if (fullsize>=0x10000)
                    throw "uncompressed data way too large (>=64k)";

                ByteVector compdata(4096);
                size_t compsize= imgfs.compress(&buf[0], fullsize, &compdata[0]);
                if (compsize==size_t(-1)) {
                    compsize= fullsize;
                    std::copy(&buf[0], &buf[fullsize], &compdata[0]);
                }
                else if (compsize>=0x10000) {
                    throw "compressed data way too large (>=64k)";
                }

                size_t allocsize= imgfs.roundtochunk(compsize);
                uint32_t chunkofs= imgfs.allocchunk(allocsize, FILEDATACHUNK);

                imgfs.rd()->setpos(chunkofs);

                // note: allocsize can be > compsize, but will be <= compdata.size()
                // taking advantage of the empty space left in compdata to auto pad
                // with nul
                imgfs.rd()->write(&compdata[0], allocsize);

                indexdata.resize(indexdata.size()+8);
                uint8_t *pidx= &indexdata.back()-7;
                set16le(pidx+0, uint16_t(compsize));
                set16le(pidx+2, uint16_t(fullsize));
                set32le(pidx+4, chunkofs);

                ofs += fullsize;
                if (fullsize<buf.size())
                    break;
            }
            if (ofs>>32)
                throw "fileentry data > 4G";
            _size= uint32_t(ofs);
            _indexsize= imgfs.roundtochunk(indexdata.size());
            _indexptr= imgfs.allocchunk(_indexsize, FILEINDEXCHUNK);
            imgfs.rd()->setpos(_indexptr);

            indexdata.resize(_indexsize);
            imgfs.rd()->write(&indexdata[0], _indexsize);
        }
        void tostream(ImgfsFile& imgfs, ReadWriter_ptr w)
        {
            if (_sectionlist)
                reconstructmodule(imgfs, w);
            else
                savedirent(imgfs, w);
        }
        void deletefile(ImgfsFile& imgfs)
        {
            section_enumerator(imgfs,
                // todo: why is a [imgfs] capture -> const, and [&imgfs] not const ?
                [&imgfs](SectionEntry_ptr section) {
                    section->deletesection(imgfs);
                }
            );
            _name.deletename(imgfs);
            deletedirent(imgfs);
        }

        void listentry(ImgfsFile& imgfs)
        {
            if (g_verbose>1) {
                size_t compsize= calc_compressed_size(imgfs);
                printf("%08x: %c:s->%08x %9d %9d [%08x] %s  %s %s\n",
                        offset(), _magic==MAGIC?'F':'M', _sectionlist, _size, int(compsize), _attr,
                        unixtime2string(getunixtime()).c_str(), entstring().c_str(), _name.name(imgfs).c_str());
            }
            else {
                printf("%08x: %c:s->%08x %9d [%08x] %s  %s %s\n",
                        offset(), _magic==MAGIC?'F':'M', _sectionlist, _size, _attr,
                        unixtime2string(getunixtime()).c_str(), entstring().c_str(), _name.name(imgfs).c_str());
            }

            section_enumerator(imgfs,
                [&imgfs](SectionEntry_ptr section) {
                    section->listsection(imgfs);
                }
            );
            if (g_verbose && _sectionlist) {

                exe_reconstructor exe(imgfs.cputype());
                exe.add_pe_data(getdatablock(imgfs));
                section_enumerator(imgfs,
                    [&imgfs,&exe](SectionEntry_ptr section) {
                        exe.add_sectioninfo(section->ni().shortname(), section->size(), section->getdatareader(imgfs));
                    }
                );

                exe.printexe();
            }
        }

        void reconstructmodule(ImgfsFile& imgfs, ReadWriter_ptr w)
        {
            exe_reconstructor exe(imgfs.cputype());
            exe.add_pe_data(getdatablock(imgfs));
            section_enumerator(imgfs,
                [&imgfs,&exe](SectionEntry_ptr section) {
                    exe.add_sectioninfo(section->ni().shortname(), section->size(), section->getdatareader(imgfs));
                }
            );

            exe.save(w);
        }
        nameinfo &ni() { return _name; }
    };
    typedef std::shared_ptr<FileEntry> FileEntry_ptr;

    struct imgfsheader {
        imgfsheader(ReadWriter_ptr rd)
        {
            // 00: f8 ac 2c 9d e3 d4 2b 4d bd 30 91 6e d8 4f 31 dc

            // 0x10 : 1
            // 0x14 : 1
            // 0x18 : 1
            rd->setpos(0x1c);
            direntsize= rd->read32le(); // 0x1c : 0x34
            chunksperblock= rd->read32le(); // 0x20 : 0x20
            bytesperblock= rd->read32le(); // 0x24 : 0x800
            rd->read32le(); // 0x28 : 0x1000
            compressiontype= rd->read32le(); // 0x2c
            freesectorcount= rd->read32le(); // 0x30
            hiddensectorcount= rd->read32le(); // 0x34 : 0x40

            bytesperchunk= bytesperblock/chunksperblock;
            entriesperblock= (bytesperblock-8)/direntsize;
            if (direntsize!=0x34)
                throw "unsupported direntsize";

            if (g_verbose) { 
                printf("imgfshdr: dirent=%d, cpb=%d, bpb=%d bpc=%d, epb= %d, comp=%s free=%d, hidden=%d\n", 
                    direntsize, chunksperblock, bytesperblock, bytesperchunk, entriesperblock, getstr((const uint8_t*)&compressiontype, 4).c_str(), freesectorcount, hiddensectorcount);
            }
        }

        // todo: add method to update freesector count

        uint32_t direntsize;
        uint32_t chunksperblock;
        uint32_t firstheaderblockoffset;
        uint32_t compressiontype;
        uint32_t freesectorcount;
        uint32_t hiddensectorcount;
        uint32_t bytesperblock;
        uint32_t bytesperchunk;
        uint32_t entriesperblock;
    };
    imgfsheader _hdr;


    // what is the chunk used for
    enum chunktype_t : char {
        IMGFSHEADER='h',
        DIRCHUNK='d',
        SECTIONINDEXCHUNK='i',
        SECTIONDATACHUNK='a',
        NAMECHUNK='n',
        FILEINDEXCHUNK='I',
        FILEDATACHUNK='A',
        FREECHUNK=' ',
    };

    // keeps track of what chunks are used for.
    // indexed by chunkid ( = offset / chunksize )
    typedef std::vector<chunktype_t> chunkmap_t;
    chunkmap_t _chunkmap;

    // keeps track of what direntries are used for.
    // indexed by direntryid ( = offset/entsize )
    typedef std::vector<entrytype_t> entrymap_t;
    entrymap_t _entrymap;

    // fileblocknr = offset_of_dir_entry / blocksize
    // dirblocknr = direntrynr / entriesperblock
    //
    // file2dir  : maps fileblocknr => dirblocknr
    typedef std::map<unsigned, unsigned> file2dirmap_t;
    file2dirmap_t _file2dir;

    // dir2file : maps dirblocknr => fileblocknr
    typedef std::vector<unsigned> dir2filemap_t;
    dir2filemap_t _dir2file;

    typedef std::map<std::string,FileEntry_ptr, caseinsensitive> filemap_t;
    filemap_t _files;
    typedef std::pair<filemap_t::iterator,bool> filemap_insert;

    bool _broken;
    int _cputype;

    enum {
        IMGFSCOMPRESS_XPR= 0x525058,
        IMGFSCOMPRESS_LZX= 0x585a4c,
        IMGFSCOMPRESS_XPH= 0x485058,
    };
#ifndef _NO_COMPRESS
    int compresstype() const {
        switch(_hdr.compressiontype) {
        case IMGFSCOMPRESS_XPR: return ITSCOMP_XPR_ENCODE;
        case IMGFSCOMPRESS_LZX: return ITSCOMP_LZX_ENCODE;
        case IMGFSCOMPRESS_XPH: return ITSCOMP_XPH_ENCODE;
        default: throw "unknown compression type";
        }
    }
    int decompresstype() const {
        switch(_hdr.compressiontype) {
        case IMGFSCOMPRESS_XPR: return ITSCOMP_XPR_DECODE;
        case IMGFSCOMPRESS_LZX: return ITSCOMP_LZX_DECODE;
        case IMGFSCOMPRESS_XPH: return ITSCOMP_XPH_DECODE;
        default: throw "unknown decompression type";
        }
    }
#endif

    ImgfsFile(ReadWriter_ptr rd)
        : _rd(rd), _hdr(rd), _broken(false), _cputype(IMAGE_FILE_MACHINE_ARM)
    {
        if (_hdr.compressiontype!=IMGFSCOMPRESS_XPR && _hdr.compressiontype!=IMGFSCOMPRESS_LZX && _hdr.compressiontype!=IMGFSCOMPRESS_XPH)
            throw stringformat("unsupported compression: %08x", _hdr.compressiontype);

        markchunk(0, _hdr.bytesperblock, IMGFSHEADER);
        if (!dirblock_enumerator(
            [&](uint64_t ofs) {
                this->markchunk(ofs, _hdr.bytesperblock, DIRCHUNK);
                this->registerdirblock(ofs);
            }
            ))
            _broken= true;

        if (_broken)
            return;

        // initialize entry map
        _entrymap.resize(_dir2file.size()*_hdr.entriesperblock, FREEENTRY);

        direntry_enumerator(
            [&](FileEntry_ptr file) {
            // note: msvc10 does not allow passing a captured 'this' to a nested lambda function
            // see http://connectppe.microsoft.com/VisualStudio/feedback/details/560907/capturing-variables-in-nested-lambdas
                ImgfsFile *t1= this;
                this->markent(file->offset(), FILEENTRY);
                filemap_insert ins= _files.insert(ImgfsFile::filemap_t::value_type(file->ni().name(*this), file));
                if (!ins.second) {
                    printf("duplicate name: %s\n", file->ni().name(*this).c_str());
                }
                file->section_enumerator(*this,
                    [&, t1](SectionEntry_ptr section) {
                    ImgfsFile *t2= t1;
                    // note: msvc10 requires explicit mention of ImgfsFile for SECTIONENTRY
                        t2->markent(section->offset(), ImgfsFile::SECTIONENTRY);

                        // note: msvc10 does not allow t1 to be captured by default-ref [&]
                        section->ni().name_enumerator(
                            [t2](uint64_t dirofs) { t2->markent(dirofs, ImgfsFile::NAMEENTRY); },
                            [t2](uint64_t ofs, size_t size) { t2->markchunk(ofs, size, ImgfsFile::NAMECHUNK); }
                        );
                        section->datatable_enumerator( *t2,
                            [t2](uint64_t ofs, size_t compsize, size_t /*fullsize*/) { t2->markchunk(ofs, compsize, ImgfsFile::SECTIONDATACHUNK); }
                        );
                        if (section->indexblock()) {
                            t2->markchunk(section->indexblock(), section->indexsize(), ImgfsFile::SECTIONINDEXCHUNK);
                        }
                    }
                );
                file->ni().name_enumerator(
                    [t1](uint64_t dirofs) { t1->markent(dirofs, ImgfsFile::NAMEENTRY); },
                    [t1](uint64_t ofs, size_t size) { t1->markchunk(ofs, size, ImgfsFile::NAMECHUNK); }
                );
                file->datatable_enumerator( *this,
                    [t1](uint64_t ofs, size_t compsize, size_t /*fullsize*/) { t1->markchunk(ofs, compsize, ImgfsFile::FILEDATACHUNK); }
                );
                if (file->indexblock()) {
                    t1->markchunk(file->indexblock(), file->indexsize(), ImgfsFile::FILEINDEXCHUNK);
                }
            }
        );
    }

    virtual void addfile(const std::string&romname, ReadWriter_ptr r)
    {
        if (_broken)
            throw "can't modify broken imgfs";

        filemap_t::iterator fi= _files.find(romname);
        if (fi!=_files.end())
        {
            if (g_verbose) {
                printf("replacing ");
                (*fi).second->listentry(*this);
            }

            (*fi).second->deletefile(*this);

            _files.erase(fi);
        }
        FileEntry_ptr dstfile(new FileEntry(romname));

        std::shared_ptr<FileReader> srcfile= std::dynamic_pointer_cast<FileReader>(r);
        if (srcfile) {
            try {
            dstfile->setunixtime(srcfile->getunixtime());
            }
            catch(...)
            {
                printf("imgfs.add: error setting filetime\n");
            }
        }
        dstfile->fromstream(*this, r);
        dstfile->save(*this);
    }
    virtual void renamefile(const std::string&romname, const std::string&newname)
    {
        if (_broken)
            throw "can't modify broken imgfs";

        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end())
            throw "rename: not found";

        if (g_verbose)
            (*fi).second->listentry(*this);

        FileEntry_ptr file= (*fi).second;
        _files.erase(fi);

        file->ni().setname(newname);
        file->save(*this);

        filemap_insert ins= _files.insert(filemap_t::value_type(file->ni().name(*this), file));
        if (!ins.second) {
            printf("duplicate name: %s\n", file->ni().name(*this).c_str());
        }
    }
    virtual void deletefile(const std::string&romname)
    {
        if (_broken)
            throw "can't modify broken imgfs";
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end()) {
            printf("WARNING: delete: %s not found\n", romname.c_str());
            return;
        }

        if (g_verbose)
            (*fi).second->listentry(*this);

        (*fi).second->deletefile(*this);

        _files.erase(fi);
    }
    virtual std::string infostring() const
    {
        return stringformat("%d files, %d dirblocks, %d chunks, %d direntries",
                (int)_files.size(), (int)_dir2file.size(), (int)_chunkmap.size(), (int)_entrymap.size());
    }
    void dumpstatistics()
    {
        printf("chunk statistics\n");

        struct refmax {
            int ref;
            int max;
            refmax() : ref(0), max(0) { }
            void add(int i)
            {
                ref++;
                if (i>max) max=i;
            }
        };
        std::map<chunktype_t,refmax> chunkref;
        for (unsigned i=0 ; i<_chunkmap.size() ; i++)
            chunkref[_chunkmap[i]].add(i);
        std::for_each(chunkref.begin(), chunkref.end(), [this](const std::pair<chunktype_t,refmax>& i) { printf("%9d '%c'  %08llx\n", i.second.ref, i.first, i.second.max*uint64_t(_hdr.bytesperchunk)); });

        printf("entry statistics\n");
        std::map<entrytype_t,refmax> entryref;
        for (unsigned i=0 ; i<_entrymap.size() ; i++)
            entryref[_entrymap[i]].add(i);
        std::for_each(entryref.begin(), entryref.end(), [this](const std::pair<entrytype_t,refmax>& i) { printf("%9d '%c'   %08llx\n", i.second.ref, i.first, index2entryofs(i.second.max)); });
    }
    virtual void printfileinfo(const std::string&romname)
    {
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end())
            throw "dump: not found";

        (*fi).second->listentry(*this);
    }
    virtual bool extractfile(const std::string&romname, const std::string& dstpath, filetypefilter_ptr filter)
    {
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end())
            return false;

        if (g_verbose)
            (*fi).second->listentry(*this);

        FileEntry_ptr srcfile= (*fi).second;
        if (filter && !filter->match(srcfile->getdatareader(*this))) {
            if (g_verbose > 1)
                printf("filtered %s\n", romname.c_str());
            return false;
        }

        ReadWriter_ptr w(new FileReader(dstpath, FileReader::createnew));

        srcfile->tostream(*this, w);

        std::shared_ptr<FileReader> dstfile= std::dynamic_pointer_cast<FileReader>(w);
        if (dstfile) {
            try {
            dstfile->setunixtime(srcfile->getunixtime());
            }
            catch(...)
            {
                printf("imgfs.get: error setting filetime\n");
            }
        }
        return true;
    }
    virtual void listfiles()
    {
        for (auto i=_files.begin() ; i!=_files.end() ; i++)
            (*i).second->listentry(*this);
    }
    virtual void dirhexdump()
    {
        printf("offset     magic    datatab  sections n: f   l namehash nameptr  size     attr     ftlo     fthi     res      indexptr indexsiz\n");
        dirblock_enumerator(
            [&](uint64_t ofs) {
                 ByteVector dirblock(bytesperblock());
                 rd()->setpos(ofs);
                 rd()->read(&dirblock[0], dirblock.size());
                 for (unsigned i= 8 ; i+direntsize() <=bytesperblock() ; i+=direntsize())
                 {
                     printf("%08llx: %s\n", i+ofs, hexdump(&dirblock[i], direntsize()/4, 4).c_str());
                 }
            }
        );
    }


    virtual void filename_enumerator(namefn fn)
    {
        for (auto i=_files.begin() ; i!=_files.end() ; i++)
        {
            fn((*i).first);
        }
    }

    // dirblocks for a chained list through the entire imgfs image
    template<typename blockfn>
    bool dirblock_enumerator(blockfn fn)
    {
        uint64_t ofs= _hdr.bytesperblock;
        while (ofs)
        {
            _rd->setpos(ofs);
            uint32_t magic= _rd->read32le();
            uint32_t next= _rd->read32le();
            if (magic!=0x2f5314ce) {
                printf("\nWARNING: invalid dirblock magic(%08x) at %08llx\n", magic, ofs);
                return false;
            }

            fn(ofs);

            ofs= next;
        }
        return true;
    }
    template<typename filefn>
    void direntry_enumerator(filefn fn)
    {
        // iterate over all dir blocks
        for (file2dirmap_t::iterator i= _file2dir.begin() ; i!=_file2dir.end() ; i++)
        {
            ByteVector dirblock(_hdr.bytesperblock-8);
            uint64_t dirblockoffset= uint64_t((*i).first)*_hdr.bytesperblock+8;
            _rd->setpos(dirblockoffset);
            _rd->read(&dirblock[0], dirblock.size());

            // iterate over entries within block
            for (unsigned entofs= 0 ; entofs<dirblock.size() ; entofs+=_hdr.direntsize)
            {
                uint32_t magic= get32le(&dirblock[entofs]);
                if (magic==0xfffffefe || magic==0xfffff6fe)
                    fn(FileEntry_ptr(new FileEntry(dirblockoffset+entofs, &dirblock[entofs])));
            }
        }
    }

private:
    void registerdirblock(uint64_t ofs)
    {
        if ((ofs/_hdr.bytesperblock)>>32)
            throw "registerdirblock: offset too large";
        unsigned fileblocknr= unsigned(ofs/_hdr.bytesperblock);

        _file2dir[fileblocknr]= _dir2file.size();
        _dir2file.push_back(fileblocknr);
    }
    void markent(uint64_t ofs, entrytype_t tag)
    {
        unsigned ix= entryofs2index(ofs);
        if (tag!=FREEENTRY && _entrymap[ix]!=FREEENTRY) {
            printf("entry %08llx (%d) is already %c, marking %c\n", ofs, ix, _entrymap[ix], tag);
        }
        _entrymap[ix]= tag;
    }
    void freeent(uint64_t ofs)
    {
        markent(ofs, FREEENTRY);
        _rd->setpos(ofs);
        ByteVector ent(_hdr.direntsize, 0xff);
        _rd->write(&ent[0], ent.size());

        //printf("freed direntry @%08llx\n", ofs);
    }
    uint64_t allocent(entrytype_t tag)
    {
        // NOTE: performance warning - linear search
        entrymap_t::iterator i= std::find(_entrymap.begin(), _entrymap.end(), FREEENTRY);
        if (i==_entrymap.end()) {
            unsigned prevblockofs= _dir2file.empty() ? 0 : _dir2file.back()*_hdr.bytesperblock;
            uint32_t newdirblockofs= allocdirblock();

            if (g_verbose)
                printf("added new dir block [%08x -> %08x]\n", prevblockofs, newdirblockofs);
            registerdirblock(newdirblockofs);
            _entrymap.resize(_dir2file.size()*_hdr.entriesperblock, FREEENTRY);
            // link to previous block
            _rd->setpos(prevblockofs);
            _rd->write32le(0x2f5314ce);
            _rd->write32le(newdirblockofs);

            _rd->setpos(newdirblockofs);
            ByteVector block(_hdr.bytesperblock, 0xff);
            set32le(&block[0], 0x2f5314ce);
            set32le(&block[4], 0);
            _rd->write(&block[0], block.size());
            //printf("write empty dirblock at %08x\n", newdirblockofs);

            i= _entrymap.end()-_hdr.entriesperblock;

            uint64_t ofs= newdirblockofs+8;
            markent(ofs, tag);
            return ofs;
        }
        uint64_t ofs= index2entryofs(i-_entrymap.begin());
//        printf("allocent(%c) -> %d : %d : %08llx\n", tag, int(i-_entrymap.begin()), *i, ofs);
        markent(ofs, tag);

        return ofs;
    }
    unsigned entryofs2index(uint64_t ofs)
    {
        if (ofs<_hdr.bytesperblock || ofs>=_rd->size())
            throw stringformat("invalid entry offset: %08llx", ofs);
        if ((ofs/_hdr.bytesperblock)>>32)
            throw stringformat("entryofs2index: offset too large: %08llx", ofs);
        unsigned fileblocknr= unsigned(ofs/_hdr.bytesperblock);
        unsigned blockofs= ofs%_hdr.bytesperblock;
        if ((blockofs-8)%_hdr.direntsize)
            throw stringformat("unaligned entry offset: %08llx", ofs);
        unsigned blockix= (blockofs-8)/_hdr.direntsize;
        file2dirmap_t::iterator i= _file2dir.find(fileblocknr);
        if (i==_file2dir.end())
            throw stringformat("entry ofs not found: %08llx [blocknr=%08x]", ofs, fileblocknr);
        return (*i).second*_hdr.entriesperblock + blockix;
    }
    uint64_t index2entryofs(unsigned ix)
    {
        unsigned dirblocknr= ix/_hdr.entriesperblock;
        unsigned dirblockix= ix%_hdr.entriesperblock;
        if (dirblocknr>=_dir2file.size())
            throw "unknown dirblock";

        //printf("i2entofs [ix=%d], blocknr=%d, blockix=%d -> fileblock=%d -> ofs=%08llx\n", ix, dirblocknr, dirblockix, _dir2file[dirblocknr], uint64_t(_dir2file[dirblocknr])*_hdr.bytesperblock+8+dirblockix*_hdr.direntsize);
        return _dir2file[dirblocknr]*_hdr.bytesperblock+8+dirblockix*_hdr.direntsize;
    }

    void markchunk(uint64_t ofs, unsigned size, chunktype_t type)
    {
        if (size==0)
            throw stringformat("can't mark empty chunk @%08llx, '%c'", ofs, type);
        if (ofs>=_rd->size() || ofs+size > _rd->size())
            throw stringformat("chunk @%08llx+%08x outside of file [filesize=%llx]", ofs, size, _rd->size());
        if (ofs%_hdr.bytesperchunk)
            throw stringformat("unaligned chunk @%08llx", ofs);

        size= roundtochunk(size);

        if ((ofs/_hdr.bytesperchunk)>>32)
            throw "markchunk: offset too large";
        unsigned ix= unsigned(ofs/_hdr.bytesperchunk);
        unsigned n= size/_hdr.bytesperchunk;
        if (_chunkmap.size()<ix+n)
            _chunkmap.resize(ix+n, FREECHUNK);

        chunkmap_t::iterator begin= _chunkmap.begin()+ix;
        chunkmap_t::iterator end= _chunkmap.begin()+ix+n;

        // note: msvc10 requires the explicit class scope ImgfsFile  for FREECHUNK
        if (type!=FREECHUNK && std::find_if(begin, end, [](chunktype_t t) { return t!=ImgfsFile::FREECHUNK; })!=end) {
            printf("markchunk, n=%d, type=%c\n", n, type);
            std::string str;
            std::for_each(begin, end, [&str](chunktype_t t){ str += (char)t; });
            printf("chunk %08llx+%08x is already: '%s'\n", ofs, size, str.c_str());

            // is 'str' correct, while the string below is not,
            //    -> because i did not declare the enum as ':char'
            //printf("chunk %08llx+%08x is already: '%s'\n", ofs, size, std::string((const char*)&(*begin), n).c_str());
        }
        std::fill_n(begin, n, type);
    }
    // finds block aligned block sized sequence of free chunks
    uint32_t allocdirblock()
    {
        // BUG: sometimes this leads to an infinite loop
        //     probably when a FREECHUNK is found at a non-block boundary -> ix%cpb!=0
        //     -> i=search(i)  -> i again

        chunkmap_t::iterator i= _chunkmap.begin();
        while (i!=_chunkmap.end()) {
            i= std::search_n(i, _chunkmap.end(), _hdr.chunksperblock, FREECHUNK);
            if (i==_chunkmap.end()) {
                // alloc more space from outer layer ( fffbfffd reader )
                _chunkmap.resize(_chunkmap.size()+_hdr.chunksperblock, FREECHUNK);

//                printf("added %d chunks for dirblock\n", _hdr.chunksperblock);
                i= _chunkmap.begin()+_chunkmap.size()-_hdr.chunksperblock;
            }
            unsigned ix= i-_chunkmap.begin();
            if ((ix%_hdr.chunksperblock)==0) {
                uint64_t ofs= ix*_hdr.bytesperchunk;
                markchunk(ofs, _hdr.bytesperchunk*_hdr.chunksperblock, DIRCHUNK);
                if (ofs>>32)
                    throw "allocdirblock: offset too large";
                return uint32_t(ofs);
            }
            ++i;
        }
        throw "could not alloc dirblock";
    }
    void freechunk(uint64_t ofs, unsigned size)
    {
        markchunk(ofs, size, FREECHUNK);
        _rd->setpos(ofs);
        ByteVector data(size, 0xff);
        _rd->write(&data[0], data.size());
        //printf("freed chunk @ %08llx, size=%08x\n", ofs, size);
    }

    // alloc for index or data block - does not need to be block aligned
    uint32_t allocchunk(unsigned size, chunktype_t tag)
    {
        if (size==0) return 0;
        if (size%_hdr.bytesperchunk)
            throw "allocchunk: unaligned size";

        unsigned n= size/_hdr.bytesperchunk;
        chunkmap_t::iterator i= std::search_n(_chunkmap.begin(), _chunkmap.end(), n, FREECHUNK);
        if (i==_chunkmap.end()) {
            // alloc more space from outer layer ( fffbfffd reader )
            auto last= std::find_if(_chunkmap.rbegin(), _chunkmap.rend(), [](chunktype_t t){ return t!=ImgfsFile::FREECHUNK; });
            size_t nfreeatend= last-_chunkmap.rbegin();
            size_t oldsize= _chunkmap.size();

            _chunkmap.resize(roundsize(_chunkmap.size()+n-nfreeatend, _hdr.chunksperblock), FREECHUNK);

//            printf("added %d chunks\n", (int)(_chunkmap.size()-oldsize));

            i= _chunkmap.begin()+oldsize-nfreeatend;
        }

        chunkmap_t::iterator end= i+n;
        std::string str;
        std::for_each(i, end, [&str](chunktype_t t){ str += (char)t; });

        unsigned ix= i-_chunkmap.begin();
        uint64_t ofs= ix*_hdr.bytesperchunk;
        //printf("allocchunk(%08x) ->: %06x:%06x:%08llx '%s'\n", size, int(i-_chunkmap.begin()), ix, ofs, str.c_str());
        markchunk(ofs, size, tag);
        if (ofs>>32)
            throw "allocchunk: offset too large";
        return (uint32_t)ofs;
    }

public:
    uint32_t roundtochunk(uint32_t x)
    {
        return roundsize(x, _hdr.bytesperchunk);
    }

    ReadWriter_ptr rd() const { return _rd; }
    size_t direntsize() const { return _hdr.direntsize; }
    size_t bytesperblock() const { return _hdr.bytesperblock; }

    size_t compress(const uint8_t*data, size_t datasize, uint8_t *compdata)
    {
#ifndef _NO_COMPRESS
        return _xpr.DoCompressConvert(compresstype(), compdata, datasize-1, data, datasize);
#else
        std::copy(data, data+datasize, compdata);
        return datasize;
#endif
    }
    void decompress(const uint8_t*compdata, size_t compsize, uint8_t*data, size_t fullsize)
    {
#ifndef _NO_COMPRESS
        if (compsize<fullsize) {
            uint32_t rc= _xpr.DoCompressConvert(decompresstype(), data, fullsize, compdata, compsize);
            if (g_verbose>1) {
                printf("decompress -> %08x\n", rc);
                if (g_verbose>2) {
                    printf("indata: %s\n", hexdump(compdata, compsize).c_str());
                    printf("outdat: %s\n", hexdump(data, fullsize).c_str());
                }
            }
        }
        else
#endif
        {
            std::copy(compdata, compdata+compsize, data);
            std::fill_n(data+compsize, fullsize-compsize, uint8_t(0));
        }
    }
#ifndef _NO_COMPRESS
    lzxxpr_convert _xpr;
#endif
    uint16_t cputype() const
    {
        return _cputype;
    }
    void setcputype(int type) {
        _cputype= type;
        if (g_verbose)
            printf("imgfs: cputype=%04x\n", type);
    }
};
typedef std::shared_ptr<ImgfsFile> ImgfsFile_ptr;

class XipFile : public FileContainer {

    ReadWriter_ptr _r;
    allocmap _mm;
    bool _filelistmodified;

    struct XipHeader {
        XipHeader(ReadWriter_ptr r, allocmap& m, uint32_t Xrvabase)
        {
            r->setpos(0x40);
            uint32_t ecec= r->read32le();
            if (ecec!=0x43454345) throw "no Xip ECEC signature";
            hdrrva= r->read32le();
            uint32_t hdrofs= r->read32le();
            if (Xrvabase==0 && hdrofs==0) {
                throw "old style xips not supported";
            }
            if (Xrvabase && hdrofs==0) {
                hdrofs= hdrrva-Xrvabase;
            }

            rvabase= hdrrva-hdrofs;

            // note: for cp450 it is required that the firstblock is not used
            if (!exe_reconstructor::e32rom::g_wm2003)
                m.markused(rvabase, 0x1000, "firstblock");
            //m.markused(rvabase, 4, "jump");
            //m.markused(rvabase+0x40, 12, "ecechdr");

            if (hdrofs+84>=r->size()) throw "invalid romhdr offset";
            r->setpos(hdrofs);
            m.markused(hdrrva, XipHeader::size(), "romhdr");

            dllfirst= r->read32le();
            dlllast= r->read32le();
            physfirst= r->read32le();
            physlast= r->read32le();
            nummods= r->read32le();
            ulRAMStart= r->read32le();
            ulRAMFree= r->read32le();
            ulRAMEnd= r->read32le();
            ulCopyEntries= r->read32le();
            ulCopyOffset= r->read32le();
            ulProfileLen= r->read32le();
            ulProfileOffset= r->read32le();
            numfiles= r->read32le();
            ulKernelFlags= r->read32le();
            ulFSRamPercent= r->read32le();
            ulDrivglobStart= r->read32le();
            ulDrivglobLen= r->read32le();
            usCPUType= r->read16le();
            usMiscFlags= r->read16le();
            pExtensions= r->read32le();
            ulTrackingStart= r->read32le();
            ulTrackingLen= r->read32le();


            m.markused(ulCopyOffset, ulCopyEntries*16, "copylist");

            modlistpos= hdrofs+XipHeader::size();
            m.markused(rvabase+modlistpos, nummods*TocEntry::size(), "modlist");

            filelistpos= hdrofs+XipHeader::size()+nummods*TocEntry::size();
            m.markused(rvabase+filelistpos, numfiles*FileEntry::size(), "filelist");

            if (g_verbose)
                printf("%08x: romhdr dll:%08x-%08x, phys:%08x-%08x, ram:%08x-%08x, copy:%d, profile:%08x-%08x, drvglob:%08x-%08x, track:%08x-%08x\n",
                    hdrrva,
                    dllfirst, dlllast,
                    physfirst, physlast,
                    ulRAMStart, ulRAMEnd,
                    ulCopyEntries,
                    ulProfileOffset, ulProfileOffset+ulProfileLen,
                    ulDrivglobStart, ulDrivglobStart+ulDrivglobLen,
                    ulTrackingStart, ulTrackingStart+ulTrackingLen);
        }
        void getdata(uint8_t *p)
        {
            set32le(p+0x00, dllfirst);
            set32le(p+0x04, dlllast);
            set32le(p+0x08, physfirst);
            set32le(p+0x0c, physlast);
            set32le(p+0x10, nummods);
            set32le(p+0x14, ulRAMStart);
            set32le(p+0x18, ulRAMFree);
            set32le(p+0x1c, ulRAMEnd);
            set32le(p+0x20, ulCopyEntries);
            set32le(p+0x24, ulCopyOffset);
            set32le(p+0x28, ulProfileLen);
            set32le(p+0x2c, ulProfileOffset);
            set32le(p+0x30, numfiles);
            set32le(p+0x34, ulKernelFlags);
            set32le(p+0x38, ulFSRamPercent);
            set32le(p+0x3c, ulDrivglobStart);
            set32le(p+0x40, ulDrivglobLen);
            set16le(p+0x44, usCPUType);
            set16le(p+0x46, usMiscFlags);
            set32le(p+0x48, pExtensions);
            set32le(p+0x4c, ulTrackingStart);
            set32le(p+0x50, ulTrackingLen);
        }

        static size_t size() { return 0x54; }

    uint32_t  dllfirst;                // first DLL address
    uint32_t  dlllast;                 // last DLL address
    uint32_t  physfirst;               // first physical address
    uint32_t  physlast;                // highest physical address
    uint32_t  nummods;                 // number of TOCentry's
    uint32_t  ulRAMStart;              // start of RAM
    uint32_t  ulRAMFree;               // start of RAM free space
    uint32_t  ulRAMEnd;                // end of RAM
    uint32_t  ulCopyEntries;           // number of copy section entries
    uint32_t  ulCopyOffset;            // offset to copy section
    uint32_t  ulProfileLen;            // length of PROFentries RAM 
    uint32_t  ulProfileOffset;         // offset to PROFentries
    uint32_t  numfiles;                // number of FILES
    uint32_t  ulKernelFlags;           // optional kernel flags from ROMFLAGS .bib config option
    uint32_t  ulFSRamPercent;          // Percentage of RAM used for filesystem 
    uint32_t  ulDrivglobStart;         // device driver global starting address
    uint32_t  ulDrivglobLen;           // device driver global length
    uint16_t  usCPUType;               // CPU (machine) Type
    uint16_t  usMiscFlags;             // Miscellaneous flags
    uint32_t  pExtensions;             // pointer to ROM Header extensions
    uint32_t  ulTrackingStart;         // tracking memory starting address
    uint32_t  ulTrackingLen;           // tracking memory ending address

    uint32_t   rvabase;
    uint32_t hdrrva;
    uint32_t modlistpos; // todo: these are no longer consistent with nummods+numfiles after adding files
    uint32_t filelistpos;
    };
    XipHeader  _hdr;

    class XipEntry {
    public:
        XipEntry (uint64_t pos) : _pos(pos)
        {
        }
        virtual ~XipEntry() { }
        virtual void getentry(uint8_t *p) const= 0;

        std::string name(XipFile& xip)
        {
            if (_rvaname==0)
                return "";
            ReadWriter_ptr r= xip.getrvareader(_rvaname, 260);
            return readstr(r);
        }
        void listentry(XipFile& xip)
        {
            printf("%08x %s %8d %c:[%08x] %s\n", (unsigned)_pos, unixtime2string(getunixtime()).c_str(), 
                    _size, typechar(), _attr, name(xip).c_str());
        }

        uint64_t getunixtime() const {
            return filetimetounix(_filetime);
        }
        void setunixtime(uint64_t t)
        {
            _filetime= unixtofiletime(t);
        }
        virtual void recordmemusage(XipFile& xip, allocmap& m)= 0;
        virtual void tostream(XipFile& xip, ReadWriter_ptr w)= 0;
        virtual void fromstream(XipFile& xip, allocmap& m, ReadWriter_ptr r)= 0;
        virtual ReadWriter_ptr getdatareader(XipFile& xip)= 0;
        virtual void deletefile(XipFile& xip, allocmap& m)= 0;

        virtual char typechar() const= 0;

        void renamefile(const std::string& newname, XipFile& xip, allocmap& m)
        {
            if (_rvaname) {
                std::string oldname= name(xip);
                m.markfree(_rvaname, roundsize(oldname.size()+1,4));

                // zero old name
                memset(&oldname[0], 0, oldname.size());
                xip.getrvareader(_rvaname, roundsize(oldname.size()+1,4))->write((const uint8_t*)&oldname[0], oldname.size()+1);

                _rvaname= 0;
            }

            if (_rvaname==0)
                _rvaname= m.findfree(roundsize(newname.size()+1, 4));
            if (_rvaname==0)
                throw "xip: could not alloc space for name";

            xip.getrvareader(_rvaname, newname.size()+1)->write((const uint8_t*)&newname[0], newname.size()+1);
        }

    protected:
        uint64_t _pos;
        uint32_t _attr;
        uint64_t _filetime;
        uint32_t _rvaname;
        uint32_t _size;
    };
    typedef std::shared_ptr<XipEntry> XipEntry_ptr;
    class TocEntry : public XipEntry {
        std::shared_ptr<exe_reconstructor> _exe;
    public:
        TocEntry(uint64_t pos, const uint8_t *pdata)
            : XipEntry(pos)
        {
            _attr= get32le(pdata);
            _filetime= get64le(pdata+0x4);
            _size= get32le(pdata+0xC);
            _rvaname= get32le(pdata+0x10);
            _rvae32= get32le(pdata+0x14);
            _rvao32= get32le(pdata+0x18);
            _rvaload= get32le(pdata+0x1C);
        }

        static size_t size() { return 0x20; }
        virtual void getentry(uint8_t *p) const
        {
            set32le(p, _attr);
            set64le(p+0x4, _filetime);
            set32le(p+0xC, _size);
            set32le(p+0x10, _rvaname);
            set32le(p+0x14, _rvae32);
            set32le(p+0x18, _rvao32);
            set32le(p+0x1C, _rvaload);
        }
        void buildexe(XipFile& xip)
        {
            if (_exe)
                return;

            _exe.reset(new exe_reconstructor(xip.cputype()));
            size_t e32size= exe_reconstructor::e32rom::size();
            size_t o32size= exe_reconstructor::o32rom::size();
            ByteVector rompe(e32size);
            xip.getrvareader(_rvae32, e32size)->read(&rompe[0], rompe.size());

            // note: can't take this from _exe yet, only after add_pe_data is called
            int nobj= rompe[0];
            rompe.resize(e32size+nobj*o32size);
            xip.getrvareader(_rvao32, nobj*o32size)->read(&rompe[e32size], nobj*o32size);

            _exe->add_pe_data(rompe);
        }

        virtual void recordmemusage(XipFile& xip, allocmap& m)
        {
            buildexe(xip);

            m.markused(_rvaname, roundsize(name(xip).size()+1, 4), "modname");

            size_t e32size= exe_reconstructor::e32rom::size();
            size_t o32size= exe_reconstructor::o32rom::size();

            m.markused(_rvae32, e32size, "e32hdr");
            m.markused(_rvao32, o32size*_exe->nr_o32_sections(), "o32hdr");
            for (int i=0 ; i<_exe->nr_o32_sections() ; i++) {
                m.markused(_exe->o32datarva(i), roundsize(_exe->o32datasize(i), 4), "objdata");
            }
        }
        virtual void tostream(XipFile& xip, ReadWriter_ptr w)
        {
            buildexe(xip);

            for (int i=0 ; i<_exe->nr_o32_sections() ; i++) {
                if (!_exe->o32compressed(i)) {
                    _exe->add_sectioninfo(stringformat("S%03d", i),
                            _exe->o32datasize(i),
                            xip.getrvareader(_exe->o32datarva(i), _exe->o32datasize(i)));
                }
                else {
                    ByteVector compdata(_exe->o32compsize(i));
                    ByteVector fulldata(_exe->o32fullsize(i));
                    xip.getrvareader(_exe->o32datarva(i), compdata.size())->read(&compdata[0], compdata.size());
                    XipFile::decompress(&compdata[0], compdata.size(), &fulldata[0], fulldata.size());

                    _exe->add_sectioninfo(stringformat("S%03d", i),
                            fulldata.size(),
                            ReadWriter_ptr(new ByteVectorReader(fulldata)));
                }
            }

            _exe->save(w);
        }
        virtual void fromstream(XipFile& xip, allocmap& m, ReadWriter_ptr r)
        {
            throw "xip module import not supported";
#if 0
            // todo - finish module importer
            exereader exerd;
            exerd.load(r);

            size_t e32size= exe_reconstructor::e32rom::size();
            size_t o32size= exe_reconstructor::o32rom::size();

            // alloc space for e32/o32 headers
            _rvae32= m.findfree(e32size);
            _rvao32= m.findfree(o32size*exerd.nr_o32_sections());
            // alloc space for sections
            for (int i=0 ; i<exerd.nr_o32_sections() ; i++) {
                ByteVector data(roundsize(_exe->o32datasize(i), 4));
                r->setpos(_exe->o32dataptr(i));
                r->read(&data[0], data.size());
                ByteVector compressed(data.size());
                uint32_t compsize= XipFile::compress(&data[0], data.size(), &compressed[0]);

                uint32_t attr= 0;
                const uint8_t *pdata= &compressed[0];
                if (compsize>=data.size() || compsize==0) {
                    compsize= data.size();
                    pdata= &data[0];
                }
                else {
                    attr |= 0x800;   // compressed
                }

                _exe->o32datarva(i, m.findfree(roundsize(compsize, 4)));
                xip.getrvareader(_exe->o32datarva(i), data.size())->write(pdata, compsize);
            }
            ByteVector pehdr(e32size+o32size*exerd.nr_o32_sections());
            _exe->get_pe_data(pehdr);

            xip.getrvareader(_rvae32, e32size)->write(&pehdr[0], e32size);
            xip.getrvareader(_rvao32, o32size*exerd.nr_o32_sections())->write(&pehdr[e32size], o32size*exerd.nr_o32_sections());

#endif
        }
        virtual ReadWriter_ptr getdatareader(XipFile& xip)
        {
            // dummy - used to satisfy the filter in extractfile
            return ReadWriter_ptr();
        }
        virtual void deletefile(XipFile& xip, allocmap& m)
        {
            std::string oldname= name(xip);
            m.markfree(_rvaname, roundsize(oldname.size()+1,4));

            // zero old name
            memset(&oldname[0], 0, oldname.size());
            xip.getrvareader(_rvaname, roundsize(oldname.size()+1,4))->write((const uint8_t*)&oldname[0], oldname.size()+1);


            buildexe(xip);

            size_t e32size= exe_reconstructor::e32rom::size();
            size_t o32size= exe_reconstructor::o32rom::size();

            // zero e32
            ByteVector zerorome(e32size);
            xip.getrvareader(_rvae32, e32size)->write(&zerorome[0], zerorome.size());
            m.markfree(_rvae32, e32size);

            int nobj= _exe->nr_o32_sections();

            // zero o32
            ByteVector zeroromo(nobj*o32size);
            xip.getrvareader(_rvao32, o32size*nobj)->write(&zeroromo[0], zeroromo.size());
            m.markfree(_rvao32, o32size*nobj);


            for (int i=0 ; i<nobj ; i++) {
                m.markfree(_exe->o32datarva(i), roundsize(_exe->o32datasize(i), 4));

                // zero section
                ByteVector zero(roundsize(_exe->o32datasize(i), 4));
                xip.getrvareader(_exe->o32datarva(i), zero.size())->write(&zero[0], zero.size());
            }
        }
        virtual char typechar() const { return 'M'; }

    private:
        uint32_t _rvae32;
        uint32_t _rvao32;
        uint32_t _rvaload;
    };
    class FileEntry : public XipEntry {
    public:
        FileEntry(uint64_t pos, const uint8_t *pdata)
            : XipEntry(pos)
        {
            _attr= get32le(pdata);
            _filetime= get64le(pdata+0x4);
            _size= get32le(pdata+0xC);
            _compsize= get32le(pdata+0x10);
            _rvaname= get32le(pdata+0x14);
            _rvaload= get32le(pdata+0x18);
        }
        FileEntry()
            : XipEntry(0)
        {
            _attr= 7;  // readonly+hidden+system
            setunixtime(time(NULL));
            _size= 0;
            _compsize= 0;
            _rvaname= 0;
            _rvaload= 0;
        }

        static size_t size() { return 0x1C; }
        virtual void getentry(uint8_t *p) const
        {
            set32le(p, _attr);
            set64le(p+0x4, _filetime);
            set32le(p+0xC, _size);
            set32le(p+0x10, _compsize);
            set32le(p+0x14, _rvaname);
            set32le(p+0x18, _rvaload);
        }

        virtual void recordmemusage(XipFile& xip, allocmap& m)
        {
            m.markused(_rvaname, roundsize(name(xip).size()+1, 4), "filename");

            m.markused(_rvaload, roundsize(_compsize, 4), "filedata");
        }

        virtual void tostream(XipFile& xip, ReadWriter_ptr w)
        {
            ReadWriter_ptr r= getdatareader(xip);

            r->copyto(w);
        }
        virtual void fromstream(XipFile& xip, allocmap& m, ReadWriter_ptr r)
        {
            ByteVector filedata(r->size());
            r->read(&filedata[0], filedata.size());
            ByteVector compressed(filedata.size());
            _size= filedata.size();
            _compsize= XipFile::compress(&filedata[0], filedata.size(), &compressed[0]);
            const uint8_t *pdata= &compressed[0];
            if (_compsize>=_size || _compsize==0) {
                _compsize= _size;
                pdata= &filedata[0];
            }
            else {
                _attr |= 0x800;   // compressed
            }
            _rvaload= m.findfree(roundsize(_compsize, 4));
            if (_rvaload==0) {
                printf("error writing xip:%s - tried to alloc 0x%x bytes\n", name(xip).c_str(), _compsize);
                throw "xip: could not alloc space for filedata";
            }
            xip.getrvareader(_rvaload, _compsize)->write(pdata, _compsize);
        }
        ReadWriter_ptr getdatareader(XipFile& xip)
        {
            if (_size==_compsize) {
                return xip.getrvareader(_rvaload, _size);
            }
            else {
                ReadWriter_ptr comprd(xip.getrvareader(_rvaload, _compsize));
                ByteVector compdata(_compsize);
                comprd->read(&compdata[0], compdata.size());
                ByteVector fulldata(_size);
                XipFile::decompress(&compdata[0], compdata.size(), &fulldata[0], fulldata.size());

                return ReadWriter_ptr(new ByteVectorReader(fulldata));
            }
        }
        virtual void deletefile(XipFile& xip, allocmap& m)
        {
            std::string oldname= name(xip);
            m.markfree(_rvaname, roundsize(oldname.size()+1,4));
            // zero old name
            memset(&oldname[0], 0, oldname.size());
            xip.getrvareader(_rvaname, roundsize(oldname.size()+1,4))->write((const uint8_t*)&oldname[0], oldname.size()+1);

            m.markfree(_rvaload, _compsize);
            // zero file data
            ByteVector zero(_compsize);
            xip.getrvareader(_rvaload, _compsize)->write((const uint8_t*)&zero[0], zero.size());
        }
        virtual char typechar() const { return 'F'; }

    private:
        uint32_t _compsize;
        uint32_t _rvaload;
    };

    // currently used to calc memusage + build _files map
    template<typename entfn>
    void xipent_enumerator(entfn fn)
    {
        _r->setpos(_hdr.modlistpos);
        ByteVector data(_hdr.nummods*TocEntry::size()+_hdr.numfiles*FileEntry::size());
        _r->read(&data[0], data.size());
        uint8_t *p= &data[0];
        for (unsigned i= 0 ; i<_hdr.nummods ; i++)
        {
            fn(XipEntry_ptr(new TocEntry(_hdr.modlistpos+i*TocEntry::size(), p)));

            p+= TocEntry::size();
        }
        for (unsigned i= 0 ; i<_hdr.numfiles ; i++)
        {
            fn(XipEntry_ptr(new FileEntry(_hdr.filelistpos+i*FileEntry::size(), p)));

            p+= FileEntry::size();
        }
    }

    typedef std::map<std::string,XipEntry_ptr, caseinsensitive> filemap_t;
    typedef std::pair<filemap_t::iterator,bool> filemap_insert;
    filemap_t _files;
public:
    XipFile(ReadWriter_ptr r, uint32_t rvabase)
        : _r(r), _filelistmodified(false), _hdr(r, _mm, rvabase)
    {
        // create name -> file map
        xipent_enumerator([this](XipEntry_ptr ent) {
                // note: repeating typedef here for msvc10
    typedef std::map<std::string,XipEntry_ptr, caseinsensitive> filemap_t;
    typedef std::pair<filemap_t::iterator,bool> filemap_insert;
            filemap_insert ins= _files.insert(filemap_t::value_type(ent->name(*this), ent));
            if (!ins.second) {
                printf("duplicate name: %s\n", ent->name(*this).c_str());
            }

            ent->recordmemusage(*this, _mm);
        });

        if (g_verbose>1) {
            printf("xip memmap\n");
            _mm.printallocmap();
        }
    }
    ~XipFile()
    {
        if (!_filelistmodified)
            return;

        size_t numfiles= 0;
        size_t nummods= 0;
        for (auto i= _files.begin() ; i!=_files.end() ; ++i)
        {
            if (i->second->typechar()=='F')
                numfiles++;
            else
                nummods++;
        }
        _hdr.nummods= nummods;
        _hdr.numfiles= numfiles;

        ByteVector hdr(XipHeader::size()+_hdr.nummods*TocEntry::size()+_hdr.numfiles*FileEntry::size());

        _hdr.getdata(&hdr[0]);
        uint8_t *p= &hdr[XipHeader::size()];
        for (auto i= _files.begin() ; i!=_files.end() ; ++i)
            if (i->second->typechar()=='M') {
                i->second->getentry(p);
                p += TocEntry::size();
            }

        for (auto i= _files.begin() ; i!=_files.end() ; ++i)
            if (i->second->typechar()=='F') {
                i->second->getentry(p);
                p += FileEntry::size();
            }

        uint32_t oldhdrrva= _hdr.hdrrva;

        _hdr.hdrrva= _mm.findfree(hdr.size());
        if (_hdr.hdrrva==0)
            throw "xip: could not alloc space for romhdr";
        getrvareader(_hdr.hdrrva, hdr.size())->write(&hdr[0], hdr.size());

        ReadWriter_ptr wrhdrptr= getrvareader(_hdr.rvabase+0x44, 8);
        wrhdrptr->write32le(_hdr.hdrrva);
        wrhdrptr->write32le(_hdr.hdrrva-_hdr.rvabase);

        update_romhdrptr_in_nk(oldhdrrva, _hdr.hdrrva);
    }
    void update_romhdrptr_in_nk(uint32_t oldromhdr, uint32_t newromhdr)
    {
        // todo
#if 0
        auto i= _files.find("nk.exe");
        if (i==_files.end()) {
            printf("WARNING: missing nk.exe - needed to update romhdr ptr\n");
            return;
        }
        auto nk= std::dynamic_pointer_cast<TocEntry>(i->second);
        uint32_t rvaptr= 0;
        nk->section_enumerator(*this, [oldromhdr, &rvaptr](uint32_t rva, const uint8_t *p, uint32_t size)
                {
                    const uint32_t *first= (const uint32_t*)p;
                    const uint32_t *last= (const uint32_t*)(p+size);
                    auto pp= std::find(first, last, oldromhdr);
                    if (pp != last && rvaptr==0)
                        rvaptr= rva+(pp-first)*sizeof(uint32_t);
                });
        if (rvaptr) {
            printf("WARNING: could not find romhdr ptr in nk.exe\n");
            return;
        }
        getrvareader(rvaptr, sizeof(uint32_t))->write32le(newromhdr);
        if (g_verbose)
            printf("updated romhdrptr at %08x\n", rvaptr);
#endif
    }
    ReadWriter_ptr getrvareader(uint32_t rva, uint32_t size)
    {
        ReadWriter_ptr r(new OffsetReader(_r, rva-_hdr.rvabase, size));
        r.reset(new RangeReader(r, 0, size));
        r->setpos(0);
        return r;
    }

    void clearromhdr()
    {
        if (_filelistmodified)
            return;

        _mm.markfree(_hdr.hdrrva, XipHeader::size()+_hdr.nummods*TocEntry::size()+_hdr.numfiles*FileEntry::size());
        _filelistmodified= true;

        // zero romhdr
        ByteVector zero(XipHeader::size()+_hdr.nummods*TocEntry::size()+_hdr.numfiles*FileEntry::size());
        getrvareader(_hdr.hdrrva, zero.size())->write((const uint8_t*)&zero[0], zero.size());
    }
    virtual void addfile(const std::string&romname, ReadWriter_ptr r)
    {
        clearromhdr(); // need to rewrite romhdr because we optionally delete the old file + the entry gets a new name
        auto i= _files.find(romname);
        if (i!=_files.end())
        {
            if (g_verbose) {
                printf("replacing ");
                i->second->listentry(*this);
            }
            i->second->deletefile(*this, _mm);
            _files.erase(i);
        }
        XipEntry_ptr dstfile= XipEntry_ptr(new FileEntry());

        auto ins= _files.insert(filemap_t::value_type(romname, dstfile));
        if (!ins.second) {
            printf("duplicate name in xip: %s", romname.c_str());
            return;
        }
        std::shared_ptr<FileReader> rfile= std::dynamic_pointer_cast<FileReader>(r);
        if (rfile) {
            try {
            dstfile->setunixtime(rfile->getunixtime());
            }
            catch(...)
            {
                printf("xip.get: error setting filetime\n");
            }
        }
        dstfile->renamefile(romname, *this, _mm);
        dstfile->fromstream(*this, _mm, r);
    }

    virtual void renamefile(const std::string&romname, const std::string&newname)
    {
        clearromhdr(); // need to rewrite romhdr because we alloc new mem for the name
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end()) {
            printf("renamefile: %s not found\n", romname.c_str());
            return;
        }
        fi->second->renamefile(newname, *this, _mm);
    }
    virtual void deletefile(const std::string&romname)
    {
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end()) {
            printf("deletefile: %s not found\n", romname.c_str());
            return;
        }
        fi->second->deletefile(*this, _mm);

        _files.erase(fi);
        clearromhdr();
    }

    virtual std::string infostring() const
    {
        return stringformat("%d files, %d modules", _hdr.numfiles, _hdr.nummods);
    }
    virtual void printfileinfo(const std::string&romname)
    {
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end()) {
            printf("printfileinfo: %s not found\n", romname.c_str());
            return;
        }
        fi->second->listentry(*this);
    }
    virtual bool extractfile(const std::string&romname, const std::string& dstpath, filetypefilter_ptr filter)
    {
        filemap_t::iterator fi= _files.find(romname);
        if (fi==_files.end()) {
            printf("extract: %s not found\n", romname.c_str());
            return false;
        }

        if (g_verbose)
            (*fi).second->listentry(*this);

        XipEntry_ptr srcfile= (*fi).second;
        if (filter && !filter->match(srcfile->getdatareader(*this))) {
            if (g_verbose > 1)
                printf("filtered %s\n", romname.c_str());
            return false;
        }

        ReadWriter_ptr w(new FileReader(dstpath, FileReader::createnew));

        srcfile->tostream(*this, w);

        std::shared_ptr<FileReader> dstfile= std::dynamic_pointer_cast<FileReader>(w);
        if (dstfile) {
            try {
            dstfile->setunixtime(srcfile->getunixtime());
            }
            catch(...)
            {
                printf("xip.get: error setting filetime\n");
            }
        }
        return true;
    }
    virtual void listfiles()
    {
        for (filemap_t::iterator i= _files.begin() ; i!=_files.end() ; i++)
            i->second->listentry(*this);
    }
    virtual void dirhexdump()
    {
        // first dump modules
        ByteVector modentries(_hdr.nummods*TocEntry::size());
        rd()->setpos(_hdr.modlistpos);
        rd()->read(&modentries[0], modentries.size());
        printf("offset     attr     ftlo     fthi     size     nameptr  e32      o32      baseaddr\n");
        for (unsigned i=0  ; i<_hdr.nummods ; i++)
            printf("%08lx: %s\n", _hdr.modlistpos+i*TocEntry::size(), hexdump(&modentries[i*TocEntry::size()], TocEntry::size()/4, 4).c_str());

        ByteVector fileentries(_hdr.numfiles*FileEntry::size());
        rd()->setpos(_hdr.filelistpos);
        rd()->read(&fileentries[0], fileentries.size());
        printf("offset     attr     ftlo     fthi     fullsize compsize nameptr  dataptr\n");
        for (unsigned i=0  ; i<_hdr.numfiles ; i++)
            printf("%08lx: %s\n", _hdr.filelistpos+i*FileEntry::size(), hexdump(&fileentries[i*FileEntry::size()], FileEntry::size()/4, 4).c_str());
    }

    virtual void filename_enumerator(namefn fn)
    {
        for (filemap_t::iterator i= _files.begin() ; i!=_files.end() ; i++)
            fn(i->first);
    }

    static bool isXipFile(ReadWriter_ptr r, uint32_t rvabase)
    {
        r->setpos(0x40);
        uint32_t ecec= r->read32le();
        if (ecec!=0x43454345) {
            if (g_verbose > 1)
                printf("not xip: ecec=0x%x\n", ecec);
            return false;
        }
        uint32_t hdrrva= r->read32le();
        uint32_t hdrofs= r->read32le();
        if (hdrrva==0 && hdrofs==0) {
            if (g_verbose > 1)
                printf("not xip: hdrofs=0x%x\n", hdrofs);
            return false;
        }
        if (rvabase && hdrofs==0)
            hdrofs= hdrrva-rvabase;
        else if (rvabase==0)
            rvabase= hdrrva-hdrofs;

        r->setpos(hdrofs+8);
        uint32_t physfirst= r->read32le();

        if (physfirst != hdrrva-hdrofs) {
            if (g_verbose > 1)
                printf("not xip: p1(0x%x) != hrva(0x%x)-hofs(0x%x) == 0x%x\n", physfirst, hdrrva, hdrofs, hdrrva-hdrofs);
            return false;
        }

        return true;
    }

    static size_t compress(const uint8_t*data, size_t datasize, uint8_t *compdata)
    {
#ifndef _NO_COMPRESS
        return _rom34.DoCompressConvert(ITSCOMP_ROM4_ENCODE, compdata, datasize-1, data, datasize);
#else
        std::copy(data, data+datasize, compdata);
        return datasize;
#endif
    }
    static void decompress(const uint8_t*compdata, size_t compsize, uint8_t*data, size_t fullsize)
    {
#ifndef _NO_COMPRESS
        if (compsize<fullsize) {
            _rom34.DoCompressConvert(ITSCOMP_ROM4_DECODE, data, fullsize, compdata, compsize);
            if (g_verbose>2) {
                printf("indata: %s\n", hexdump(compdata, compsize).c_str());
                printf("outdat: %s\n", hexdump(data, fullsize).c_str());
            }
        }
        else
#endif
        {
            std::copy(compdata, compdata+compsize, data);
            std::fill_n(data+compsize, fullsize-compsize, uint8_t(0));
        }
    }
#ifndef _NO_COMPRESS
    static rom34_convert _rom34;
#endif

    uint16_t cputype() const
    {
        return _hdr.usCPUType;
    }

    ReadWriter_ptr rd() { return _r; }
};
#ifndef _NO_COMPRESS
    rom34_convert XipFile::_rom34;
#endif

typedef std::shared_ptr<XipFile> XipFile_ptr;

class CompressedXipReader : public ReadWriter {
    // +00: 00970178
    // +04: 0097d688
    // +08: ".FSDMgr\x00"
    // +10: 0
    // +14: 0
    // +18: 0
    // +1c: 0048
    // +1e: 0394
    // +20: 0097de90
    // +24: 00970640
    // +28: 5
    // +2c: 0
    // +30: 5
    // +34: 0c44  == ptr to compressed data
    // +38: 0600  == nr blocks
    // +3c: 1000  == full blocksize
    // +40: "SRPX"
    // +44: uint16_t  compressedsize[nrblocks]
    ReadWriter_ptr _r;
    uint32_t _fullblocksize;
    uint32_t _totalsize;

    DwordVector _compptrs;
    DwordVector _compsizes;

    uint32_t _pos;

    ByteVector _cache;
    uint32_t _cachepos; // decompressed offset for contents of _cache

    std::shared_ptr<MemoryReader> _memrd;
public:
    static bool isCompressedXip(ReadWriter_ptr rd, uint64_t ofs)
    {
        rd->setpos(ofs+0x34);
        uint32_t dataofs= rd->read32le();
        uint32_t nblocks= rd->read32le();
        //printf("d=%08x, n=%08x\n", dataofs, nblocks);
        if (nblocks*2+0x44>dataofs) {
            if (g_verbose > 1)
                printf("not cxip: nb(=0x%x)*x+0x44 > do(0x%x)\n", nblocks, dataofs);
            return false;
        }
        uint32_t fullblocksize= rd->read32le();
        //printf("bs=%08x\n", fullblocksize);
        if (fullblocksize & (fullblocksize-1)) {
            if (g_verbose > 1)
                printf("not cxip: fb(0x%x)\n", fullblocksize);
            return false;
        }
        if (uint64_t(fullblocksize)*nblocks > 0x40000000) {
            if (g_verbose > 1)
                printf("not cxip: fb(0x%x)*nb(0x%x) > 0x40000000\n", fullblocksize, nblocks );
            return false;
        }
        uint32_t magic= rd->read32le();
        //printf("mg=%08x\n", magic);
        if (magic!=0x58505253)  {
            if (g_verbose > 1)
                printf("not cxip: mg(0x%x)\n", magic);
            return false;
        }

        return true;
    }
    CompressedXipReader(ReadWriter_ptr r)
        : _r(r), _fullblocksize(0), _totalsize(0), _pos(0), _cachepos(0)
    {
        if (_r->isreadonly()) setreadonly();

        // 0x30:  5  - version ?
        _r->setpos(0x34);
        uint32_t dataofs= _r->read32le();
        uint32_t nblocks= _r->read32le();
        _fullblocksize= _r->read32le();
        uint32_t magic= _r->read32le();
        if (magic!=0x58505253) throw "invalid compressed xip signature";

        // create map of  pos/fullblocksize -> compresseddata ptr
        ByteVector sizedata(nblocks*2);
        _r->read(&sizedata[0], sizedata.size());
        _compptrs.resize(nblocks);
        _compsizes.resize(nblocks);
        uint8_t *p= &sizedata[0];
        uint32_t pos= dataofs;
        for (unsigned i=0 ; i<nblocks ; i++)
        {
            _compptrs[i]= pos;
            _compsizes[i]= get16le(p);
            pos += _compsizes[i];
            p+=2;
        }
        _totalsize= nblocks*_fullblocksize;

        if (g_verbose)
            printf("compressed xip: compsize=%08x, fullsize=%08x\n", (unsigned)(pos-dataofs), _totalsize);
    }
    virtual ~CompressedXipReader()
    {
        if (!_memrd)
            return;

        // create new compressed data
        _memrd->setpos(0);
        ByteVector compdata;

        while (!_memrd->eof()) {
            ByteVector data(_fullblocksize);
            size_t n= _memrd->read(&data[0], data.size());

            compdata.resize(compdata.size()+_fullblocksize);
            size_t c= compress(&data[0], n, &compdata[compdata.size()-_fullblocksize]);
            compdata.resize(compdata.size()-_fullblocksize+c);

            _compsizes.push_back(c);
        }
        printf("updated cxip: %d blocks ( full=%x, comp=%x )\n", (int)_compsizes.size(), (int)_memrd->size(), (int)compdata.size());

        // write new header
        _r->setpos(0x34);
        _r->write32le(0x44+2*_compsizes.size());
        _r->write32le(_compsizes.size());
        _r->write32le(_fullblocksize);
        _r->write32le(0x58505253);
        std::for_each(_compsizes.begin(), _compsizes.end(), [this](uint32_t c) { _r->write16le(c); });
        _r->write(&compdata[0], compdata.size());
    }
    virtual size_t read(uint8_t *p, size_t n)
    {
        if (_memrd) {
            size_t nr= _memrd->read(p, n);
            _pos += nr;
            return nr;
        }

        if (_pos>=_totalsize)
            return 0;
        size_t wanttotal= std::min(n, size_t(_totalsize-_pos));

        size_t nread=0;
        while (nread < wanttotal)
        {
            size_t n= readcomp(p, wanttotal-nread);
            _pos += n;
            p += n;
            nread += n;
        }

        return nread;
    }
    size_t readcomp(uint8_t *p, size_t n)
    {
        if (_cachepos>_pos || _pos >= _cachepos+_cache.size()) {
            _cache.resize(_fullblocksize);

            size_t comppos= _compptrs[_pos/_fullblocksize];

            ByteVector comp(_compsizes[_pos/_fullblocksize]);

            _r->setpos(comppos);
            _r->read(&comp[0], comp.size());

            decompress(&comp[0], comp.size(), &_cache[0], _cache.size());

            _cachepos= (_pos/_fullblocksize)*_fullblocksize;

            //printf("decomp: %08x %08zx: %s\n", _cachepos, comppos, vhexdump(_cache).c_str());
        }
        size_t want= std::min(n, _cachepos+_cache.size()-_pos);
        std::copy(&_cache[_pos-_cachepos], &_cache[_pos-_cachepos]+want, p);

        //printf("reading from cache: pos=%08x, cache=%08x  want=%08x\n", _pos, _cachepos, want);
        return want;
    }
    void loadmemrd()
    {
        std::shared_ptr<MemoryReader> memrd(new ByteVectorReader());
        uint64_t savedpos= _pos;

        setpos(0);
        copyto(memrd);

        // from now on all read/writes are done via memrd
        _memrd= memrd;
        setpos(savedpos);

        // discard ptrs into live image
        _compsizes.clear();
        _compptrs.clear();
        _cache.clear();
        _cachepos= 0;
    }

    virtual void write(const uint8_t *p, size_t n)
    {
        if (!_memrd)
            loadmemrd();

        _memrd->write(p, n);
        _pos += n;
    }
    virtual void setpos(uint64_t off)
    {
        if (_memrd)
            _memrd->setpos(off);
        _pos= off;
    }
    virtual void truncate(uint64_t off)
    {
        throw "compressed xip truncate: not yet implemented";
    }
    virtual uint64_t size()
    {
        return _totalsize;
    }
    virtual uint64_t getpos() const
    {
        if (_memrd)
            return _memrd->getpos();
        return _pos;
    }
    virtual bool eof()
    {
        if (_memrd)
            return _memrd->eof();
        return _pos>=size();
    }
private:
    size_t compress(const uint8_t*data, size_t datasize, uint8_t *compdata)
    {
#ifndef _NO_COMPRESS

        //printf("compress %04zx: %s\n", datasize, hexdump(data, datasize).c_str());

        size_t compsize= _xpr.DoCompressConvert(ITSCOMP_XPR_ENCODE, compdata, datasize-1, data, datasize);
        //printf("    %c %04zx: %s\n", compsize<datasize ? '<' : '=', compsize, hexdump(compdata, compsize).c_str());
        if (compsize<datasize)
            return compsize;
#endif
        std::copy(data, data+datasize, compdata);
        return datasize;
    }
    void decompress(const uint8_t*compdata, size_t compsize, uint8_t*data, size_t fullsize)
    {
#ifndef _NO_COMPRESS
        if (compsize<fullsize) {
            _xpr.DoCompressConvert(ITSCOMP_XPR_DECODE, data, fullsize, compdata, compsize);
            if (g_verbose>2) {
                printf("indata: %s\n", hexdump(compdata, compsize).c_str());
                printf("outdat: %s\n", hexdump(data, fullsize).c_str());
            }
        }
        else
#endif
        {
            std::copy(compdata, compdata+compsize, data);
            std::fill_n(data+compsize, fullsize-compsize, uint8_t(0));
        }
    }

#ifndef _NO_COMPRESS
    lzxxpr_convert _xpr;
#endif

};

//////////////////////////////////////////////////////////////////////////////
class readercollection {
    struct readerinfo {
        std::string name;
        std::string parent;
        ReadWriter_ptr r;

        readerinfo(std::string name, std::string parent, ReadWriter_ptr r)
            : name(name), parent(parent), r(r)
        {
        }
        readerinfo()
        {
        }
    };
    typedef std::map<std::string,readerinfo, caseinsensitive> name2readermap_t;
    typedef std::map<ReadWriter_ptr,readerinfo> ptr2readermap_t;
    name2readermap_t _rdbyname;
    ptr2readermap_t _rdbyptr;
    readerinfo _ri;
public:
    void addreader(ReadWriter_ptr rd, const std::string& name)
    {
        _ri.r= rd;
        _ri.name= name;

        auto ins= _rdbyname.insert(name2readermap_t::value_type(_ri.name, _ri));
        if (!ins.second) {
            printf("WARNING: duplicate reader name %s\n", _ri.name.c_str());
        }

        auto insp= _rdbyptr.insert(ptr2readermap_t::value_type(_ri.r, _ri));
        if (!insp.second) {
            printf("WARNING: duplicate reader ptr %s\n", _ri.name.c_str());
        }

    }
    void setparent(ReadWriter_ptr rd)
    {
        auto pnt= _rdbyptr.find(rd);
        if (pnt==_rdbyptr.end()) {
            printf("WARNING: unknown parent reader %p\n", rd.get());
            _ri.parent= "";
            return;
        }
        _ri.parent= pnt->second.name;
    }
    void printreadertree(const std::string& name, int level)
    {
        int count=0;
        for (auto i= _rdbyname.begin() ; i!=_rdbyname.end() ; i++)
            if (i->second.parent==name) {
                if (count==0)
                    printf("%*s{\n", level*4, "");
                //printf("%*s%p %10lld %s [%s]\n", (level+1)*4, "", i->second.r.get(), i->second.r->size(), i->second.name.c_str(), i->second.parent.c_str());
                printf("%*s%s 0x%llx\n", (level+1)*4, "", i->second.name.c_str(), i->second.r->size());
                printreadertree(i->second.name, level+1);
                count++;
            }
        if (count)
            printf("%*s}\n", level*4, "");
    }
    size_t count() const { return _rdbyname.size(); }

    ReadWriter_ptr getbyname(const std::string& name)
    {
        auto i= _rdbyname.find(name);
        if (i==_rdbyname.end())
            return ReadWriter_ptr();
        return i->second.r;
    }
};
class filesystemcollection {
    typedef std::map<std::string, FileContainer_ptr, caseinsensitive> fsmap_t;

    fsmap_t _byname;
public:
    void addfs(FileContainer_ptr fs, const std::string& name)
    {
        auto ins= _byname.insert(fsmap_t::value_type(name, fs));
        if (!ins.second) {
            printf("WARNING: duplicate filesystem name %s\n", name.c_str());
        }
    }
    size_t count() const { return _byname.size(); }

    FileContainer_ptr getbyname(const std::string& name)
    {
        auto i= _byname.find(name);
        if (i==_byname.end())
            return FileContainer_ptr();
        return i->second;
    }
    template<typename ACTION>
    void enumerate_filesystems(ACTION f)
    {
        for (auto i= _byname.begin() ; i!=_byname.end() ; i++)
            f(i->first, i->second);
    }
};
//////////////////////////////////////////////////////////////////////////////
// scripted actions
//////////////////////////////////////////////////////////////////////////////


struct action {
    virtual ~action() { }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)= 0;
};
typedef std::shared_ptr<action> action_ptr;

struct print_info : action {
    virtual ~print_info() { }
    print_info()
    {
    }

    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        printf("readers: ( total = %d )\n", (int)rdlist.count());
        rdlist.printreadertree("", 0);
        printf("filesystems: ( total = %d )\n", (int)fslist.count());
        fslist.enumerate_filesystems([](const std::string& name, FileContainer_ptr fs) {
            printf("    %-10s  %s\n", name.c_str(), fs->infostring().c_str());
        });
    }
};
struct extract_all : action {
    std::string _fsname;
    std::string _dstpath;
    filetypefilter_ptr _filter;

    virtual ~extract_all() { }
    extract_all(const std::string& fsname, const std::string&dstpath, filetypefilter_ptr filter)
        : _fsname(fsname), _dstpath(dstpath), _filter(filter)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (_fsname.empty())
        {
            fslist.enumerate_filesystems([this](const std::string& name, FileContainer_ptr fs) {
                this->extractfs(name, fs);
            });
        }
        else {
            FileContainer_ptr fs= fslist.getbyname(_fsname);
            if (!fs) throw "extractall: invalid fsname";
            extractfs(_fsname, fs);
        }
    }
    void extractfs(const std::string& name, FileContainer_ptr fs)
    {
        std::string fssavepath= _dstpath+"/"+name;
        CreateDirPath(fssavepath);
        fs->filename_enumerator(
            [this,fs,fssavepath](const std::string& romname) {
                try {
                    fs->extractfile(romname, fssavepath+"/"+romname, _filter);
                }
                catch(const char*msg)
                {
                    printf("extractfile: %s: %s\n", romname.c_str(), msg);
                }
            }
        );

    }
};

struct list_files : action {
    std::string _fsname;

    virtual ~list_files() { }
    list_files(const std::string& fsname)
        : _fsname(fsname)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (_fsname.empty())
        {
            fslist.enumerate_filesystems([](const std::string& name, FileContainer_ptr fs) {
                printf("-------- %s\n", name.c_str());
                fs->listfiles();
            });
        }
        else {
            FileContainer_ptr fs= fslist.getbyname(_fsname);
            if (!fs) throw "list: invalid fsname";
            fs->listfiles();
        }
    }
};
struct add_file : action {
    std::string _srcpath;
    std::string _fsname;
    std::string _romname;

    virtual ~add_file() { }
    add_file(const std::string&srcname, const std::string& filesystemname, const std::string&romname)
        : _srcpath(srcname), _fsname(filesystemname), _romname(romname)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose > 1)
            printf("adding %s:%s from %s\n", _fsname.c_str(), _romname.c_str(), _srcpath.c_str());
        FileContainer_ptr fs= fslist.getbyname(_fsname);
        if (!fs) throw "add: invalid fsname";

        ReadWriter_ptr r(new FileReader(_srcpath, FileReader::readonly));
        fs->addfile(_romname, r);
    }
};
struct ren_file : action {
    std::string _fsname;
    std::string _romname;
    std::string _newname;

    virtual ~ren_file() { }
    ren_file(const std::string& filesystemname, const std::string&curname, const std::string&newname)
        : _fsname(filesystemname), _romname(curname), _newname(newname)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose > 1)
            printf("renaming %s:%s to %s\n", _fsname.c_str(), _romname.c_str(), _newname.c_str());
        FileContainer_ptr fs= fslist.getbyname(_fsname);
        if (!fs) throw "ren: invalid fsname";

        fs->renamefile(_romname, _newname);
    }
};
struct del_file : action {
    std::string _fsname;
    std::string _romname;

    virtual ~del_file() { }
    del_file(const std::string& filesystemname, const std::string&romname)
        : _fsname(filesystemname), _romname(romname)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose > 1)
            printf("deleting %s:%s\n", _fsname.c_str(), _romname.c_str());
        FileContainer_ptr fs= fslist.getbyname(_fsname);
        if (!fs) throw "del: invalid fsname";

        fs->deletefile(_romname);
    }
};
struct print_fileinfo : action {
    std::string _fsname;
    std::string _romname;

    virtual ~print_fileinfo() { }
    print_fileinfo(const std::string& filesystemname, const std::string&romname)
        : _fsname(filesystemname), _romname(romname)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        FileContainer_ptr fs= fslist.getbyname(_fsname);
        if (!fs) throw "dump: invalid fsname";

        fs->printfileinfo(_romname);
    }
};
struct extract_file : action {
    std::string _fsname;
    std::string _romname;
    std::string _dstpath;
    filetypefilter_ptr _filter;

    virtual ~extract_file() { }
    extract_file(const std::string&fsname, const std::string&romname, const std::string&dstpath, filetypefilter_ptr filter)
        : _fsname(fsname), _romname(romname), _dstpath(dstpath), _filter(filter)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        FileContainer_ptr fs= fslist.getbyname(_fsname);
        if (!fs) throw "extract: invalid fsname";

        fs->extractfile(_romname, _dstpath, _filter);
    }
};


struct dirhexdump : action {
    std::string _fsname;

    virtual ~dirhexdump() { }
    dirhexdump(const std::string& filesystemname)
        : _fsname(filesystemname)
    {
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        FileContainer_ptr fs= fslist.getbyname(_fsname);
        if (!fs) throw "dirhexdump: invalid fsname";
        fs->dirhexdump();
    }
};
struct getfrom_reader : action {
    std::string _readername;
    uint64_t _ofs;
    size_t _n;
    std::string _savename;

    virtual ~getfrom_reader() { }
    getfrom_reader(const std::string& readername, uint64_t ofs, size_t n, const std::string& savename)
        : _readername(readername), _ofs(ofs), _n(n), _savename(savename)
    {
        if (g_verbose>1)
            printf("mkgetbytes(%08llx, %08zx)\n", _ofs, _n);
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose>1)
            printf("dogetbytes(%s, %08llx, %08zx)\n", _readername.c_str(), _ofs, _n);

        ReadWriter_ptr rd= rdlist.getbyname(_readername);
        if (!rd) throw "getfrom: invalid rdname";

        rd->setpos(_ofs);

        ReadWriter_ptr w(new FileReader(_savename, FileReader::createnew));

        rd->copyto(w, _n);
    }
};

struct putto_reader : action {
    std::string _readername;
    uint64_t _ofs;
    size_t _n;
    std::string _loadname;

    virtual ~putto_reader() { }
    putto_reader(const std::string& readername, uint64_t ofs, size_t n, const std::string& loadname)
        : _readername(readername), _ofs(ofs), _n(n), _loadname(loadname)
    {
        if (g_verbose>1)
            printf("mkputbytes(%08llx, %08zx)\n", _ofs, _n);
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose>1)
            printf("doputbytes(%s, %08llx, %08zx)\n", _readername.c_str(), _ofs, _n);

        ReadWriter_ptr wr= rdlist.getbyname(_readername);
        if (!wr) throw "putto: invalid rdname";

        wr->setpos(_ofs);

        ReadWriter_ptr r(new FileReader(_loadname, FileReader::readonly));

        while (_n)
        {
            ByteVector data(std::min(_n, size_t(0x1000)));

            size_t rn= r->read(&data[0], data.size());
            wr->write(&data[0], rn);

            if (rn<data.size())
                break;

            _n -= rn;
            _ofs += rn;
        }
    }
};
struct saveas_reader : action {
    std::string _readername;
    std::string _savename;

    virtual ~saveas_reader() { }
    saveas_reader(const std::string& readername, const std::string& savename)
        : _readername(readername), _savename(savename)
    {
        if (g_verbose>1)
            printf("saveas(%s)\n", _savename.c_str());
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose>1)
            printf("dosaveas(%s, %s)\n", _readername.c_str(), _savename.c_str());

        ReadWriter_ptr rd= rdlist.getbyname(_readername);
        if (!rd)
            throw "saveas: invalid reader";

        rd->setpos(0);

        ReadWriter_ptr w(new FileReader(_savename, FileReader::createnew));

        rd->copyto(w);
    }
};

struct hexdump_reader : action {
    std::string _readername;
    uint64_t _ofs;
    size_t _storedsize;
    size_t _fullsize;
    std::string _comptype;

    virtual ~hexdump_reader() { }
    hexdump_reader(const std::string& readername, uint64_t ofs, size_t n)
        : _readername(readername), _ofs(ofs), _storedsize(n), _fullsize(0)
    {
        if (g_verbose>1)
            printf("mkhexdump(%08llx, %08zx)\n", _ofs, _storedsize);
    }
    hexdump_reader(const std::string& readername, uint64_t ofs, size_t compsize, size_t fullsize, const std::string& comptype)
        : _readername(readername), _ofs(ofs), _storedsize(compsize), _fullsize(fullsize), _comptype(comptype)
    {
        if (g_verbose>1)
            printf("mkhexdump(%08llx, %08zx, %08zx, %s)\n", _ofs, _storedsize, _fullsize, _comptype.c_str());
    }

    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose>1)
            printf("dohexdump(%s, %08llx, %08zx, %08zx, %s)\n", _readername.c_str(), _ofs, _storedsize, _fullsize, _comptype.c_str());

        ReadWriter_ptr rd= rdlist.getbyname(_readername);
        if (!rd) throw "hexdump: invalid rdname";

        rd->setpos(_ofs);

        if (_comptype.empty())
            dorawhexdump(rd);
#ifndef _NO_COMPRESS
        else
            docomphexdump(rd);
#endif
    }
    void dorawhexdump(ReadWriter_ptr rd)
    {
        while (_storedsize)
        {
            ByteVector data(std::min(_storedsize, size_t(0x1000)));
            size_t rn= rd->read(&data[0], data.size());

            if (rn==0)
                break;
            printf("%s\n", hexdump(_ofs, &data[0], rn).c_str());

            _storedsize -= rn;
            _ofs += rn;
        }
    }
#ifndef _NO_COMPRESS
    int decompresstype() const {
        if (stringicompare(_comptype,std::string("xpr"))==0) return ITSCOMP_XPR_DECODE;
        if (stringicompare(_comptype,std::string("lzx"))==0) return ITSCOMP_LZX_DECODE;
        if (stringicompare(_comptype,std::string("xph"))==0) return ITSCOMP_XPH_DECODE;
        if (stringicompare(_comptype,std::string("xip"))==0) return ITSCOMP_ROM4_DECODE;
        if (stringicompare(_comptype,std::string("rom"))==0) return ITSCOMP_ROM3_DECODE;
        throw "unknown decompression type";
    }
    void docomphexdump(ReadWriter_ptr rd)
    {
        ByteVector compdata(_storedsize);
        ByteVector data(_fullsize);
        rd->read(&compdata[0], compdata.size());
        win32compress_link  comp;
        int rs= comp.DoCompressConvert(decompresstype(), &data[0], data.size(), &compdata[0], compdata.size());
        printf("decompress result=0x%x\n", rs);

        if (rs>0)
            bighexdump(0, &data[0], data.size());
    }
#endif
};


struct hexedit_reader : action {
    std::string _readername;
    uint64_t _ofs;
    ByteVector _data;

    virtual ~hexedit_reader() { }
    hexedit_reader(const std::string& readername, uint64_t ofs, const ByteVector& data)
        : _readername(readername), _ofs(ofs), _data(data)
    {
        if (g_verbose>1)
            printf("mkhexedit(%08llx, %08zx)\n", _ofs, _data.size());
    }
    virtual void perform(filesystemcollection& fslist, readercollection& rdlist)
    {
        if (g_verbose>1)
            printf("dohexedit(%s, %08llx, %08zx)\n", _readername.c_str(), _ofs, _data.size());

        ReadWriter_ptr wr= rdlist.getbyname(_readername);
        if (!wr) throw "hexedit: invalid rdname";
        wr->setpos(_ofs);

        wr->write(&_data[0], _data.size());
    }
};



void usage()
{
    fprintf(stderr, "Usage: editimgfs imgfile [operations]\n");
    fprintf(stderr, "      -v                          : verbose\n");
    fprintf(stderr, "      -r                          : readonly\n");
    fprintf(stderr, "      -o OFFSET -l LENGTH         : look only at a section of the imgfile.\n");
    fprintf(stderr, "      -d path                     : where to save extrated files to\n");
    fprintf(stderr, "      -s SIZE                     : specify totalsize ( for motorola FLASH )\n");
    fprintf(stderr, "      -extractall                 : extract all to '-d' path\n");
                   //................................................................................
    fprintf(stderr, "      -list                       : list all files\n");
    fprintf(stderr, "      -info                       : list available readers/filesystems\n");
//  fprintf(stderr, "      -create    -- todo\n");
//  fprintf(stderr, "      -addmod    -- todo\n");
    fprintf(stderr, "      -filter      <EXE|SIGNED>   : only exe or signed binaries\n");
    fprintf(stderr, "      -resign                     : update nbh sigs after modifications\n");
    fprintf(stderr, "      -keyfile     KeyFile        : nbh key file\n");
    fprintf(stderr, "      -extractnbh                 : extract SPL/IPL/OS images from nbh\n");

    fprintf(stderr, "READER operations\n");
    fprintf(stderr, "      -rd          RdName         : specify reader to operate upon\n");
    fprintf(stderr, "      -saveas      Outfile        : save entire rd section\n");
    fprintf(stderr, "      -getbytes    offset size Outfile\n");
    fprintf(stderr, "      -putbytes    offset size Infile\n");
    fprintf(stderr, "      -hexdump     offset size\n");
#ifndef _NO_COMPRESS
    fprintf(stderr, "      -chexdump    {XPR|XPH|LZX|XIP|ROM} offset size fullsize : dump compressed\n");
#endif
    fprintf(stderr, "      -hexedit     offset bytes...\n");

    fprintf(stderr, "FILESYSTEM operations\n");
    fprintf(stderr, "      -fs          FsName         : specify fs to operate upon\n");
    fprintf(stderr, "      -add         RomName[=srcfile] ...  : adds a list of files\n");
    fprintf(stderr, "                                  you can also add all files from a directory\n");
    fprintf(stderr, "      -del         RomName\n");
    fprintf(stderr, "      -ren         RomName=NEWNAME\n");
    fprintf(stderr, "      -extract     RomName=dstfile\n");
    fprintf(stderr, "      -fileinfo    RomName        : print detailed info about file\n");
    fprintf(stderr, "      -dirhexdump                 : for debugging\n");

}
template<typename ACTION>
void handlepath(const std::string& arg, ACTION act)
{
    size_t lastslash= arg.find_last_of("/\\");
    std::string romname= lastslash==std::string::npos ? arg : arg.substr(lastslash+1);
    act(arg, romname);
}

// expands one argument, and passes all to 'act'
//    handles '@<listfile>'
//    or recurses directories
template<typename ACTION>
void processarg(const std::string& arg, ACTION act, bool mustexist)
{
    size_t ieq= arg.find('=');
    if (ieq!=std::string::npos) {
        //  <rom>=<src>
        std::string romname= arg.substr(0,ieq);
        std::string srcname= arg.substr(ieq+1);
        act(srcname, romname);
    }
    else if (arg[0]=='@') {
        // if name starts with '@' -> read list from file
        MmapReader rl(arg.substr(1), MmapReader::readonly);

        rl.line_enumerator([act,mustexist](const char *first, const char*last)->bool {
            processarg(std::string(first, last-first), act, mustexist);
            return true;
        });
    }
    else switch (GetFileInfo(arg)) {
        case AT_ISDIRECTORY:
            // if <arg> is a directory -> add all files in that directory
            dir_iterator(arg, [act](const std::string& srcpath) {
                    handlepath(srcpath, act);
                },
                [](const std::string& dirname)->bool { printf("NOTE: not processing subdirectory %s\n", dirname.c_str()); return false; }
            );
            break;
        case AT_ISFILE:
            handlepath(arg, act);
            break;
        default:
            if (mustexist)
                printf("WARNING: %s does not exist\n", arg.c_str());
            else
                handlepath(arg, act);
    }
}

// passes arguments until next '-option' or '--' to 'act'
template<typename ACTION>
void processargs(int& i, int argc, char**argv, bool mustexist, ACTION act)
{
    bool nomoreoptions=false;
    while (i<argc) {
        std::string arg= argv[i++];
        if (arg=="--") {
            nomoreoptions= true;
            continue;
        }
        if (!nomoreoptions && arg[0]=='-') {
            // main loop needs to process this argument
            i--;
            break;
        }

        processarg(arg, act, mustexist);
    }
}
void processhexdata(int& i, int argc, char**argv, ByteVector& data)
{
    int datasize= 0;
    while (i<argc)
    {
        std::string arg= argv[i++];
        if (arg[0]=='-')
            switch(arg[1])
            {
                // data size specifier
                case '1':
                case '2':
                case '4':
                case '8':
                    datasize= arg[1]-'0';
                    break;
                case '-':
                    // --: end of hexedit data
                    return;
                default:
                    // main loop needs to process this argument
                    i--;
                    return;
            }
        else {
            if (datasize==0) {
                // determine datasize from hex word size
                size_t sepix= arg.find_first_of(",: ");
                if (sepix==arg.npos) {
                    // no separators: assume bytes
                    datasize= 1;
                }
                else {
                    if (sepix&1)
                        throw "odd nr of hex digits";
                    datasize= sepix/2;
                }
            }
            if (datasize==0 || datasize==3 || (datasize>4 && datasize!=8))
                throw "datasize must be 1,2,4 or 8";
            switch(datasize)
            {
                case 1:
                    hex2binary(arg, data);
                    break;
                case 2: {
                    std::vector<uint16_t> data16;
                    hex2binary(arg, data16);

                    data.resize(sizeof(uint16_t)*data16.size());
                    memcpy(&data[0], &data16[0], data.size());
                        }
                    break;
                case 4: {
                    std::vector<uint32_t> data32;
                    hex2binary(arg, data32);

                    data.resize(sizeof(uint32_t)*data32.size());
                    memcpy(&data[0], &data32[0], data.size());
                        }
                    break;
                case 8: {
                    std::vector<uint64_t> data64;
                    hex2binary(arg, data64);

                    data.resize(sizeof(uint64_t)*data64.size());
                    memcpy(&data[0], &data64[0], data.size());
                        }
                    break;
            }
        }
    }
}
class exefilter : public filetypefilter {
    bool _checkcert;
public:
    exefilter() : _checkcert(false) { }
    exefilter(bool checkcert) : _checkcert(checkcert) { }
    virtual ~exefilter() { }
    virtual bool match(ReadWriter_ptr file)
    {
        if (!file)
            return false;
        ByteVector hdr(1024);
        file->setpos(0);
        size_t n= file->read(&hdr[0], hdr.size());
        hdr.resize(n);
        
        if (get16le(&hdr[0])!=0x5a4d) {
            //printf("not exe[1]: %s\n", hexdump(&hdr[0], 16).c_str());
            return false;
        }
        size_t peofs= get32le(&hdr[0x3c]);
        if (peofs>=hdr.size()) {
            //printf("not exe[2]: %s\n", hexdump(&hdr[0], 64).c_str());
            return false;
        }
        if (get32le(&hdr[peofs])!=0x4550) {
            //printf("not exe[3]: %s\n", hexdump(&hdr[0], 512).c_str());
            return false;
        }
        if (get16le(&hdr[peofs+0x18])!=0x010b) {
            //printf("not exe[4]: %s\n", hexdump(&hdr[0], 512).c_str());
            return false;
        }
        if (!_checkcert)
            return true;

        uint32_t secptr= get32le(&hdr[peofs+0x98]);
        uint32_t secsize= get32le(&hdr[peofs+0x9c]);

        //printf("secptr=%08x, secsize=%08x\n", secptr, secsize);
        return (secptr && secsize);
    }
};
class signedfilter : public exefilter {
public:
    signedfilter() : exefilter(true) { }
    virtual ~signedfilter() { }
};

// todo: add more extract filters
//    XML
//    HTML
//    DATA+<off>:<hexdata>
//    S00n+<off>:<hexdata>
//    or by source ( xip1, xip2, imgfs )

filetypefilter_ptr makefilter(const std::string& filter)
{
    if (stringicompare(filter,std::string("EXE"))==0) return filetypefilter_ptr(new exefilter());
//  if (filter=="XML") return filetypefilter_ptr(new xmlfilter());
//  if (filter=="HTML") return filetypefilter_ptr(new htmlfilter());
    if (stringicompare(filter,std::string("SIGNED"))==0) return filetypefilter_ptr(new signedfilter());

    throw "unknown filter type";
}




int main(int argc, char**argv)
{
    try {
#ifdef _NO_COMPRESS
    printf("(de)compression not supported in this build\n");
#endif
    bool readonly= false;
    std::string savedir=".";
    std::string nbh_save_dir;
    std::string imgname;

    std::string keyfile;
    bool resignnbh= false;
    uint64_t totalsize= 0;
    uint64_t imgoffset= 0;
    uint64_t imglength= 0;

    filetypefilter_ptr extractfilter;

    typedef std::vector<action_ptr> actionlist;
    actionlist actions;


    std::string filesystemname;
    std::string readername;
    uint32_t xip_rvabase=0;

    int i=1;
    while (i<argc)
    {
        std::string arg= argv[i++];

        // check for fs or rd presence
        if (arg=="-chexdump" || arg=="-hexdump" || arg=="-hexedit" || arg=="-getbytes" || arg=="-putbytes" || arg=="-saveas") {
            if (readername.empty()) {
                readername= "file";
                printf("defaulting to 'file' for option %s, override with the -rd option\n", arg.c_str());
            }
        }
        else if (arg=="-add" || arg=="-ren" || arg=="-del" || arg=="-dump" || arg=="-extract" || arg=="-dirhexdump") {
            if (filesystemname.empty()) {
                printf("option %s must be preceeded by -fs FSNAME\n", arg.c_str());
                break;
            }
        }
        
        // process arguments
        if (arg[0]!='-') {
            if (imgname.empty())
                imgname= arg;
            else {
                printf("Can have only one image name\n");
                usage();
                return 1;
            }
        }
        else if (arg=="-R") {
            if (i>=argc) throw "missing arg for -R";
            xip_rvabase= _strtoi64(argv[i++], 0, 0);
            exe_reconstructor::e32rom::g_wm2003= true;
        }
        else if (arg=="-s") {
            if (i>=argc) throw "missing arg for -s";
            totalsize= _strtoi64(argv[i++], 0, 0);
        }
        else if (arg=="-o") {
            if (i>=argc) throw "missing arg for -o";
            imgoffset = _strtoi64(argv[i++], 0, 0);
        }
        else if (arg=="-l") {
            if (i>=argc) throw "missing arg for -l";
            imglength = _strtoi64(argv[i++], 0, 0);
        }
        else if (arg=="-info") {
            actions.push_back(action_ptr(new print_info()));
        }
        else if (arg=="-filter") {
            if (i>=argc) throw "missing arg for -filter";
            extractfilter= makefilter(argv[i++]);
        }
        else if (arg=="-extractall") { // note: fsname is optional
            actions.push_back(action_ptr(new extract_all(filesystemname, savedir, extractfilter)));

            extractfilter.reset();
        }
        else if (arg=="-extractnbh") {
            nbh_save_dir= savedir;
        }
        else if (arg.size()>=2 && arg[0]=='-' && arg[1]=='v') {
            g_verbose+=countoptionmultiplicity(arg);
        }
        else if (arg=="-r") {
            readonly= true;
        }
        else if (arg=="-resign") {
            resignnbh= true;
        }
        else if (arg=="-keyfile") {
            if (i>=argc) throw "missing arg for -keyfile";
            keyfile= argv[i++];
        }
        else if (arg=="-d") {
            if (i>=argc) throw "missing arg for -d";
            savedir= argv[i++];
            CreateDirPath(savedir);
        }
        else if (arg=="-fs") {
            if (i>=argc) throw "missing arg for -fs";
            filesystemname= argv[i++];
        }
        else if (arg=="-rd") {
            if (i>=argc) throw "missing arg for -rd";
            readername= argv[i++];
        }
        else if (arg=="-list") {  // note: fsname is optional
            actions.push_back(action_ptr(new list_files(filesystemname)));
        }

//////////////////////////////////////////////////////////////////////////////
// filesystem ops
        else if (arg=="-add") {
            if (i>=argc) throw "missing arg for -add";
            processargs(i, argc, argv, true, [&actions, filesystemname](const std::string& srcpath, const std::string& romname)
                    {
                        actions.push_back(action_ptr(new add_file(srcpath, filesystemname, romname)));
                    }
            );
        }
        else if (arg=="-ren") {
            if (i>=argc) throw "missing arg for -ren";
            std::string curname= argv[i++];
            size_t ieq= curname.find('=');
            if (ieq==std::string::npos) throw "missing new name for rename";
            std::string newname(curname.substr(ieq+1));
            curname.resize(ieq);
            actions.push_back(action_ptr(new ren_file(filesystemname, curname, newname)));
        }
        else if (arg=="-del") {
            if (i>=argc) throw "missing arg for -del";
            processargs(i, argc, argv, false, [&actions, filesystemname](const std::string& /*srcpath*/, const std::string& romname)
                    {
                        actions.push_back(action_ptr(new del_file(filesystemname, romname)));
                    }
            );
        }
        else if (arg=="-fileinfo") {
            if (i>=argc) throw "missing arg for -fileinfo";
            processargs(i, argc, argv, false, [&actions, filesystemname](const std::string& /*srcpath*/, const std::string& romname)
                    {
                        actions.push_back(action_ptr(new print_fileinfo(filesystemname, romname)));
                    }
            );

        }
        else if (arg=="-extract") {
            if (i>=argc) throw "missing arg for -extract";
            processargs(i, argc, argv, false, [extractfilter, filesystemname, &actions, &savedir](const std::string& path, const std::string& romname)
                    {
                        if (romname==path) {
                            actions.push_back(action_ptr(new extract_file(filesystemname, romname, savedir+"/"+romname, extractfilter)));
                        }
                        else {
                            actions.push_back(action_ptr(new extract_file(filesystemname, romname, path, extractfilter)));
                        }
                    }
            );

            extractfilter.reset();
        }
        else if (arg=="-dirhexdump") {
            actions.push_back(action_ptr(new dirhexdump(filesystemname)));
        }

//////////////////////////////////////////////////////////////////////////////
// reader ops
        else if (arg=="-hexdump") {
            if ((i+1)>=argc) throw "missing args for -hexdump";
            char*p;
            uint64_t offset= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-hexdump: invalid offset";
            uint64_t size= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-hexdump: invalid size";

            if (size)
                actions.push_back(action_ptr(new hexdump_reader(readername, offset, size)));
        }
#ifndef _NO_COMPRESS
        else if (arg=="-chexdump") {
            if ((i+3)>=argc) throw "missing args for -chexdump";

            std::string comptype= argv[i++];

            char*p;
            uint64_t offset= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-chexdump: invalid offset";
            uint64_t compsize= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-chexdump: invalid compsize";
            uint64_t fullsize= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-chexdump: invalid fullsize";

            if (compsize && fullsize)
                actions.push_back(action_ptr(new hexdump_reader(readername, offset, compsize, fullsize, comptype)));
        }
#endif
        else if (arg=="-hexedit") {
            if (i>=argc) throw "missing args for -hexedit";
            char*p;
            uint64_t offset= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-hexedit: invalid offset";
            ByteVector data;
            processhexdata(i, argc, argv, data);

            if (!data.empty())
                actions.push_back(action_ptr(new hexedit_reader(readername, offset, data)));
        }
        else if (arg=="-getbytes") {
            if ((i+2)>=argc) throw "missing args for -getbytes";
            char*p;
            uint64_t offset= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-getbytes: invalid offset";
            uint64_t size= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-getbytes: invalid size";
            std::string outname= argv[i++];
            if (size)
                actions.push_back(action_ptr(new getfrom_reader(readername, offset, size, outname)));
        }
        else if (arg=="-saveas") {
            if (i>=argc) throw "missing args for -saveas";
            std::string outname= argv[i++];
            actions.push_back(action_ptr(new saveas_reader(readername, outname)));
        }
        else if (arg=="-putbytes") {
            if ((i+2)>=argc) throw "missing args for -putbytes";
            char*p;
            uint64_t offset= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-putbytes: invalid offset";
            uint64_t size= _strtoi64(argv[i++], &p, 0);
            if (p && *p)
                throw "-putbytes: invalid size";
            std::string inname= argv[i++];
            if (size)
                actions.push_back(action_ptr(new putto_reader(readername, offset, size, inname)));
        }
        else {
            printf("unknown option: %s\n", arg.c_str());
            usage();
            return 1;
        }
    }

    if (imgname.empty()) {
        printf("Missing image name\n");
        usage();
        return 1;
    }

    readercollection rdlist;
    filesystemcollection fslist;


    //////////////////////////////////////////////////////////////////////////////
    // decode image
    ReadWriter_ptr rd= ReadWriter_ptr
#ifndef _NO_MMAP
            (readonly ? new MmapReader(imgname, MmapReader::readonly)
                     : totalsize ?  new MmapReader(imgname, MmapReader::readwrite, totalsize)
                         : new MmapReader(imgname, MmapReader::readwrite));
#else
            (readonly ? new FileReader(imgname, FileReader::readonly)
                     : new FileReader(imgname, FileReader::readwrite));
#endif

    rdlist.addreader(rd, "file");
    if (imgoffset) {
        if (imglength==0)
            imglength = rd->size() - imgoffset;
        rd = ReadWriter_ptr(new OffsetReader(rd, imgoffset, imglength));
    }

    ByteVector sec0(512);
    rd->setpos(0);
    rd->read(&sec0[0], sec0.size());
    if (B000FFReadWriter::isB000FF(sec0)) {
        rdlist.setparent(rd);
        rd.reset(new B000FFReadWriter(rd));

        rdlist.addreader(rd, "b00");

        // todo: add reader for motorola bootsplash
        //    format: see decodexprs.pl + XPR_DECODE

        // specific for motorola roms - skipping the bitmaps part
        //  todo: fix FFFBFFFDReader to accept an initial block without blkids
        //     -> so i can skip with offset 0x320000
        rdlist.setparent(rd);
        rd.reset(new FFFBFFFDReader(rd, 0x800));
        rdlist.addreader(rd, "fffb");

        rd->setpos(0);
        rd->read(&sec0[0], sec0.size());
        // todo: handle virtual offset + entry point from B000FF
    }
    if (NbhReadWriter::isNbh(sec0)) {
        rdlist.setparent(rd);
        rd.reset(new NbhReadWriter(rd, keyfile, resignnbh));
        rdlist.addreader(rd, "nbh");
        rd->setpos(0);
        rd->read(&sec0[0], sec0.size());
    }
    if (HtcImageFile::isHtcImage(sec0)) {
        HtcImageFile htc(rd);

        ReadWriter_ptr osrd;

        int n= htc.count();
        for (int i=0 ; i<n ; i++)
        {
            ReadWriter_ptr nbhrd= htc.getsectionbyidx(i);
            if (nbhrd && !nbh_save_dir.empty()) {
                std::string outname= nbh_save_dir+"/"+htc.nbhtypename(htc.gettypebyidx(i));
                if (GetFileInfo(outname+".nb")==AT_ISFILE)
                    outname += stringformat(".%d", i);
                outname += ".nb";

                ReadWriter_ptr nbhwr(new FileReader(outname, FileReader::createnew));

                nbhrd->copyto(nbhwr);
            }
            if (nbhrd) {
                rdlist.setparent(rd);
                rdlist.addreader(nbhrd, htc.nbhtypename(htc.gettypebyidx(i)));

                if (htc.gettypebyidx(i)==0x400)
                    osrd= nbhrd;
            }
        }

        if (osrd)
            rd= osrd; // htc.getsection(0x400);      // OS
    }
    uint32_t fffbblocksize= rd ? FFFBFFFDReader::findblocksize(rd) : 0;
    if (fffbblocksize) {
        // note: qualcomm based phones have the diskblocknr+tag after each fileblock
        // -> the fileoffset != diskblocknr*fileblocksize for the imgfs partition
        rdlist.setparent(rd);
        rd.reset(new FFFBFFFDReader(rd, fffbblocksize));
        rdlist.addreader(rd, "fffb");
        rd->setpos(0);
        rd->read(&sec0[0], sec0.size());
    }

    size_t sectorsize= 0x800;   // todo: this can also be 0x200 for old roms

    if (PartitionTable::isvalidptable(sec0)) {
        PartitionTable pt(sec0, sectorsize);

        pt.partition_enumerator([xip_rvabase, rd, &rdlist, &fslist](uint8_t type, uint64_t ofs, uint64_t size)
            {
                if (size>rd->size()-ofs) {
                    printf("partition[type:%02x] beyond image: resizing %08x -> %08x\n", type, (int)size, (int)(rd->size()-ofs));
                    size= rd->size()-ofs;
                }
                if (size==0)
                    return;

                // todo: add option to use CheckedOffsetReader, so we will not crash on truncated files
                ReadWriter_ptr rp(new OffsetReader(rd, ofs, size));
                rdlist.setparent(rd);
                rdlist.addreader(rp, stringformat("part%02x", type));
                switch(type)
                {
                case 0x20: // update xip
                case 0x23: // boot xip
                {
                    if (CompressedXipReader::isCompressedXip(rp, 0)) {
                        rdlist.setparent(rp);
                        rp.reset(new CompressedXipReader(rp));
                        rdlist.addreader(rp, stringformat("cxip%02x", type));
                    }

                    if (XipFile::isXipFile(rp, xip_rvabase)) {
                        fslist.addfs(FileContainer_ptr(new XipFile(rp, xip_rvabase)), stringformat("xip%02x", type));
                    }
                    else {
                        printf("Partition %02x %x/%x : not xip\n", type, (int)ofs, (int)size);
                    }
                }
                break;
                case 0x25: // imgfs
                {
                    fslist.addfs(FileContainer_ptr(new ImgfsFile(rp)), "imgfs");
                }
                break;
                }
            });

        ByteVector sec1(0x800);
        rd->setpos(0x800);
        rd->read(&sec1[0], sec0.size());
        if (MsFlash50::isMSFLASH50(sec1)) {
            MsFlash50 m50(sec1);
        }
    }
    else {
        // check for raw xip
        ReadWriter_ptr xiprd(rd);
        if (CompressedXipReader::isCompressedXip(xiprd, 0)) {
            printf("found cxip\n");
            rdlist.setparent(xiprd);
            xiprd.reset(new CompressedXipReader(xiprd));
            rdlist.addreader(xiprd, "cxip");
        }
        if (XipFile::isXipFile(xiprd, xip_rvabase)) {
            printf("found xip\n");
            fslist.addfs(FileContainer_ptr(new XipFile(xiprd, xip_rvabase)), "xip");
        }

        // check for raw imgfs
        try {
        uint64_t hdrofs= ImgfsFile::find_header(rd);
        printf("imgfs @ %08llx\n", hdrofs);

        rdlist.setparent(rd);
        rd.reset(new OffsetReader(rd, hdrofs, rd->size()-hdrofs));

        rdlist.addreader(rd, "imgfs");
        fslist.addfs(FileContainer_ptr(new ImgfsFile(rd)), "imgfs");
        }
        catch(const char*msg)
        {
            printf("imgfs: %s\n", msg);
        }
        catch(...)
        {
            printf("imgfs: ?\n");
        }
    }

    // set cputype for imgfs
    FileContainer_ptr xip23= fslist.getbyname("xip23");
    xip23= xip23 ? xip23 : fslist.getbyname("xip");

    FileContainer_ptr imgfs= fslist.getbyname("imgfs");
    if (xip23 && imgfs) {
        std::dynamic_pointer_cast<ImgfsFile>(imgfs)->setcputype( std::dynamic_pointer_cast<XipFile>(xip23)->cputype() );
    }

    //////////////////////////////////////////////////////////////////////////////
    //  now perform actions
    for (actionlist::iterator i= actions.begin() ; i!=actions.end() ; i++)
        (*i)->perform(fslist, rdlist);

    }
    catch(const char*msg)
    {
        printf("EXCEPTION: %s\n", msg);
        return 1;
    }
    catch(const std::string& msg)
    {
        printf("EXCEPTION: %s\n", msg.c_str());
        return 1;
    }
    catch(...)
    {
        printf("EXCEPTION\n");
        return 1;
    }

    return 0;
}
