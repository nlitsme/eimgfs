#include <stdio.h>
#include "allocmap.h"

struct maptest_t {
    bool use; uint32_t ofs; uint32_t size;
};
maptest_t tests[]= {
    { 1, 0x80080000, 0x123 }, 
    { 1, 0x80080124, 0x121 }, 
    { 1, 0x80001000, 0x2000 }, 
    { 0, 0x80001200, 0x123 }, 
    { 0, 0x80002000, 0x120 }, 
    { 0, 0x80002200, 0x121 }, 
    { 0, 0x80002400, 0x122 }, 
    { 0, 0x80002600, 0x123 }, 
    { 0, 0x80002800, 0x124 }, 
};
void tstamap()
{
    allocmap m;
    printf("free of empty map\n");
    for (unsigned n= 0 ; n<16 ; n++)
        printf("%04x: %08x\n", n, m.findfree(n));

    for (unsigned i=0 ; i<sizeof(tests)/sizeof(*tests) ; ++i)
    {
        if (tests[i].use)
            m.markused(tests[i].ofs, tests[i].size, "test");
        else
            m.markfree(tests[i].ofs, tests[i].size);
        printf("exec %s %08x, %x\n", tests[i].use? "use":"free", tests[i].ofs, tests[i].size);
        m.printallocmap();
    }

    printf("free\n");
    for (unsigned n= 0 ; n<0x4000 ; n++)
        printf("%04x: %08x\n", n, m.findfree(n));
}
struct maptest2_t {
    int n;
    maptest_t  init[4];
};
maptest2_t tests2[]= {
    { 2, {{ 1, 0x10000, 0x100}, { 1, 0x10100, 0x100 } }},
    //{ 2, {{ 1, 0x10000, 0x100}, { 1, 0x100f0, 0x100 } }}, -> overlap
    //{ 2, {{ 1, 0x10000, 0x100}, { 1, 0x10080, 0x10 }  }}, -> overlap
    { 2, {{ 1, 0x10000, 0x100}, { 0, 0x10080, 0x80 }  }},
    { 2, {{ 1, 0x10000, 0x100}, { 0, 0x10000, 0x80 }  }},
    { 2, {{ 1, 0x10000, 0x100}, { 0, 0x10080, 0x10 }  }},
};
void tstamap2()
{
    for (unsigned i=0 ; i<sizeof(tests2)/sizeof(*tests2) ; ++i)
    {
        printf("test2: %d\n", i);
        maptest2_t & t= tests2[i];
        allocmap m;
        for (unsigned j=0 ; j<t.n ; j++) {
            maptest_t & I= t.init[j];
            if (I.use)
                m.markused(I.ofs, I.size, "test2");
            else
                m.markfree(I.ofs, I.size);
        }
        m.printallocmap();
    }
}

int main(int,char**)
{
    try {
    tstamap();
    tstamap2();
    }
    catch(const char*msg)
    {
        printf("E: %s\n", msg);
        return 1;
    }
    catch(...)
    {
        printf("EXCEPTION\n");
        return 1;
    }
    return 0;
}
