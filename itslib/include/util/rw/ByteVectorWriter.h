#ifndef _UTIL_RW_BYTEVECTORWRITER_H__
#define _UTIL_RW_BYTEVECTORWRITER_H__

#include "vectorutils.h"
#include "util/rw/MemoryReader.h"
class ByteVectorWriter : public MemoryReader {
    ByteVector &_bv;
public:
    // constructor for read/writing from/to a ByteVector
    ByteVectorWriter(ByteVector& bv)
        : _bv(bv)
    {
        setgrowable();
        setbuf(&_bv.front(), _bv.size());
    }

    // constructor for reading from a const ByteVector
    ByteVectorWriter(const ByteVector& bv)
        : _bv(const_cast<ByteVector&>(bv))
    {
        setreadonly();
        setbuf(&_bv.front(), _bv.size());
    }

    virtual ~ByteVectorWriter()
    {
    }

    virtual void truncate(uint64_t off)
    {
        _bv.resize(off);
        setbuf(&_bv.front(), _bv.size());
    }
    virtual void grow(size_t n)
    {
        _bv.resize(_bv.size()+n);
        setbuf(&_bv.front(), _bv.size());
    }
};
#endif

