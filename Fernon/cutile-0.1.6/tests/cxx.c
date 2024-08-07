#define CUTILE_IMPLEM
#include "../cxx.h"
#include "../test.h"

int main()
{
    cutile_test_begin_m();

    // bswap
    {
        u16 nb = 0x1234;
        nb = cutile_bswap_u16(nb);
        cutile_test_assert_m(nb == 0x3412);

        u32 nb32 = 0x12345678;
        nb32 = cutile_bswap_u32(nb32);
        cutile_test_assert_m(nb32 == 0x78563412);

        u64 nb64 = 0x1234567898765432;
        nb64 = cutile_bswap_u64(nb64);
        cutile_test_assert_m(nb64 == 0x3254769878563412);
    }

    // cast
    {
        u32 nb = 0xFFFF;
        cutile_test_assert_m(cast(u16, nb) == 0xFFFF);
    }

    // packed_struct
    {
        packed_struct(packed_test
        {
            char  a;
            int   b;
            short c;
            char  d;
        });

        cutile_test_assert_m(sizeof(struct packed_test) == 8);
    }

    cutile_test_end_m();
}
