#define CUTILE_IMPLEM
#include "../blowfish.h"
#include "../test.h"

int main(int ac, char** av)
{
    cutile_test_begin_m();

    blowfish_context bctx;
    init_blowfish_context(&bctx, (u8*)"TESTKEY", 7);
    u32 l = 1, r = 2;
    blowfish_encrypt(&bctx, &l, &r);
    cutile_test_assert_m(l == 0xDF333FD2 && r == 0x30A71BB4);
    blowfish_decrypt(&bctx, &l, &r);
    cutile_test_assert_m(l == 1 && r == 2);
    
    cutile_test_end_m();
}
