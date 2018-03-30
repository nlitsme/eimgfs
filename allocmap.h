#pragma once
#include <map>
#include <stdint.h>

class allocmap {
    // this maps offset -> chunksize
    // consecutive chunks are merged, such that for 2 consecutive iteraters
    // the following is always true:
    //     endofs(i) < i->first
    typedef std::map<uint32_t,uint32_t> allocmap_t;

    allocmap_t _m;
public:
    void printallocmap() const
    {
        for (auto i= _m.begin() ; i!=_m.end() ; ++i)
            printf("%08x-%08x: %8x\n", i->first, endofs(i), i->second);
    }
    static uint32_t endofs(allocmap_t::iterator i) { return i->first+i->second; }
    static uint32_t endofs(allocmap_t::const_iterator i) { return i->first+i->second; }
    void markused(uint32_t ofs, uint32_t size, const char *tag)
    {
//        printf("mark %08x-%08x (%8x): %s\n", ofs, ofs+size, size, tag);
        if (size==0)
            return;
        uint32_t end= ofs+size;
        //printf("used(%08x-%08x) %s\n", ofs, end, tag);

        auto i= _m.upper_bound(ofs);
        if (i==_m.begin()) {
            // first item
            _m.insert(allocmap_t::value_type(ofs, size));
            return;
        }
        auto next= i;
        --i;
        // now  i->first <= ofs  < (i+1)->first

        if (endofs(i)==ofs) {
            //  --------<.......>----------<....>
            //          i      ie
            //                 ofs...end
            if (next!=_m.end() && end > next->first)
                printf("overlap: mark(%08x-%08x) / i=%08x-%08x, n=%08x-%08x\n", ofs, end, i->first, endofs(i), next->first, endofs(next));
                //throw "overlap";
            i->second += size;
        }
        else if (endofs(i) > ofs) {
            //  --------<.......>----------<....>
            //          i      ie
            //               ofs...end
            printf("overlap: mark(%08x-%08x) / i=%08x-%08x, n=%08x-%08x\n", ofs, end, i->first, endofs(i), next->first, endofs(next));
            //throw "overlap";
        }
        else {
            //  --------<.......>----------<....>
            //          i      ie
            //                    ofs...end
            if (next!=_m.end() && end > next->first) {
                //  --------<.......>----------<......>
                //          i      ie
                //                    ofs........end
                
                printf("overlap: mark(%08x-%08x) / i=%08x-%08x, n=%08x-%08x\n", ofs, end, i->first, endofs(i), next->first, endofs(next));
                //throw "overlap";
            }
            auto ins= _m.insert(allocmap_t::value_type(ofs, size));
            if (!ins.second)
                throw "failed to free";
            i= ins.first;

            next= i; ++next;
        }

        if (next==_m.end())
            return;

        // now check if we need to merge with 'next'
        if (endofs(i) == next->first) {
            i->second += next->second;
            _m.erase(next);
        }
        else if (endofs(i) > next->first) {
            printf("overlap: mark(%08x-%08x) / i=%08x-%08x, n=%08x-%08x\n", ofs, end, i->first, endofs(i), next->first, endofs(next));
            //throw "overlap";
        }
    }
    void markfree(uint32_t ofs, uint32_t size)
    {
        uint32_t  end= ofs+size;

        auto i= _m.upper_bound(ofs);
        if (i==_m.begin())
            throw "nothing to free";
        --i;

        if (end > endofs(i))
            throw "freeing empty";

        if (end == endofs(i)) {
            // -----<.........>-------
            //            |   |
            //           ofs  end
            i->second -= size;
        }
        else if (ofs==i->first) {
            // -----<.........>-------
            //      |   |
            //     ofs  end
            auto ins= _m.insert(allocmap_t::value_type(end, endofs(i)-end));
            if (!ins.second)
                throw "failed to free";
            _m.erase(i);
        }
        else if (ofs>i->first && end<endofs(i)) {
            // -----<.........>-------
            //         |   |
            //        ofs  end
            auto ins= _m.insert(allocmap_t::value_type(end, endofs(i)-end));
            if (!ins.second)
                throw "failed to free";
            i->second= ofs-i->first;
        }
        else {
            throw "markfree: case not implemented";
        }
    }

    uint32_t findfree(uint32_t size)
    {
        uint32_t ofs= _m.begin()->first;
        for (auto i=_m.begin() ; i!=_m.end() ; ++i)
        {
            if (i->first-ofs >= size) {
                markused(ofs, size, "findfree");
                return ofs;
            }

            ofs= i->first + i->second;
        }
        // allocate new item at end
        markused(ofs, size, "findfree");
        return ofs;
    }
};
