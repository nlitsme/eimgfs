#ifndef _UTIL_RW_RANGEREADER_H__
#define _UTIL_RW_RANGEREADER_H__

// restricts reads to a specified firstofs-lastofs range
class RangeReader : public ReadWriter {
    ReadWriter_ptr _r;
    uint64_t _startofs;
    uint64_t _endofs;
    uint64_t _size;
    uint64_t _curpos;
public:
    RangeReader(ReadWriter_ptr r, uint64_t startofs, uint64_t size)
        : _r(r), _startofs(startofs), _endofs(startofs+size), _size(size), _curpos(startofs)
    { }
    virtual size_t read(uint8_t *p, size_t n)
    {
        size_t want= (size_t)std::min(uint64_t(n), _endofs-_curpos);
        size_t nread= _r->read(p, want);
        _curpos += nread;
        return nread;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        size_t want= (size_t)std::min(uint64_t(n), _endofs-_curpos);
        if (want<n)
            throw "write beyond limit";
        _r->write(p, want);
        _curpos += want;
    }
    virtual void setpos(uint64_t off)
    {
        if ((_startofs < _endofs && (off<_startofs || off>_endofs)) || off!=_startofs) {
            printf("setpos(%llx) [%llx .. %llx]\n", off, _startofs, _endofs);
            throw "setpos beyond limit";
        }
        _r->setpos(off);
    }
    virtual void truncate(uint64_t off)
    {
        if (off<_startofs || off>_endofs)
            throw "truncate beyond limit";
        _r->truncate(off);
    }
    virtual uint64_t size()
    {
        return _endofs;
    }
    virtual uint64_t getpos() const
    {
        return _curpos;
    }
    virtual bool eof()
    {
        return _curpos>=size();
    }
};
#endif
