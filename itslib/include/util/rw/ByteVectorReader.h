#ifndef _UTIL_RW_BYTEVECTORREADER_H__
#define _UTIL_RW_BYTEVECTORREADER_H__

#include "vectorutils.h"
#include "util/rw/MemoryReader.h"
class ByteVectorReader : public MemoryReader {
    ByteVector _bv;
public:
    // no vector provided
    ByteVectorReader()
    {
        setgrowable();
    }

    // constructor copies contents of provided vector
    ByteVectorReader(const ByteVector& bv)
    {
        _bv= bv;
        setgrowable();
        setbuf(&_bv.front(), _bv.size());
    }

    // constructor swaps contents of provided vector
    ByteVectorReader(ByteVector& bv)
    {
        _bv.swap(bv);
        setgrowable();
        setbuf(&_bv.front(), _bv.size());
    }

    virtual ~ByteVectorReader()
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
