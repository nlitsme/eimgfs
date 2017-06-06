#ifndef _UTIL_RW_CHECKEDOFFSETEADER_H__
#define _UTIL_RW_CHECKEDOFFSETEADER_H__

// translates a specified range to 0..size
// checks size
class CheckedOffsetReader : public ReadWriter {
    ReadWriter_ptr _r;
    uint64_t _baseofs;
    uint64_t _size;
    uint64_t _curpos;
public:
    CheckedOffsetReader(ReadWriter_ptr r, uint64_t baseofs, uint64_t size)
        : _r(r), _baseofs(baseofs), _size(size), _curpos(0)
    {
        if (size > _r->size()-_baseofs) {
            printf("off=%08llx, size=%08llx,  src: %08llx\n", baseofs, size, _r->size());
            throw "CheckedOffsetReader larger then source disk";
        }

        //printf("CHECKED: %llx/%llx\n", baseofs, size);
        setpos(_curpos);
    }
    virtual size_t read(uint8_t *p, size_t n)
    {
        size_t want= (size_t)std::min(uint64_t(n), _size-_curpos);
        if (want==0)
            return 0;
        size_t nread= _r->read(p, want);
        //printf("CHECKED.read: @%llx n=%zx, want=%zx, got=%zx\n", _curpos, n, want, nread);
        _curpos += nread;
        return nread;
    }
    virtual void write(const uint8_t *p, size_t n)
    {
        size_t want= (size_t)std::min(uint64_t(n), _size-_curpos);
        if (want<n)
            throw "write beyond limit";
        _r->write(p, want);
        _curpos += want;
    }
    virtual void setpos(uint64_t off)
    {
        if (off>_size) {
            printf("setpos(%llx) [%llx .. %llx]\n", off, _baseofs, _size);
            throw "setpos beyond limit";
        }
        _r->setpos(off+_baseofs);
        _curpos= off;
    }
    virtual void truncate(uint64_t off)
    {
        if (off>_size)
            throw "truncate beyond limit";
        _r->truncate(off+_baseofs);
    }
    virtual uint64_t size()
    {
        return _size;
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

