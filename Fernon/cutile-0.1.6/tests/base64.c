#define CUTILE_IMPLEM
#include "../base64.h"
#include "../test.h"

int main(int ac, char** av)
{
    cutile_test_begin_m();

    heap_allocator heapalloc = create_default_heap_allocator();
    allocator* heap = (allocator*)&heapalloc;
    
    const char text1[] = "Many hands make light work.";
    const char text2[] = "light work.";
    const char text3[] = "light wor";
    const char text4[] = "light w";
    const char text5[] = "light wo";
    const char text6[] = "aefjklfeaaaaa";
    const char etext1[] = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu";
    const char etext2[] = "bGlnaHQgd29yay4=";
    const char etext3[] = "bGlnaHQgd29y";
    const char etext4[] = "bGlnaHQgdw==";
    const char etext5[] = "bGlnaHQgd28=";
    const char etext6[] = "YWVmamtsZmVhYWFhYQ==";

    u64 len;
    u8* buf;

    buf = base64_encode_cstr(text1, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)etext1, len));

    buf = base64_encode_cstr(text2, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)etext2, len));

    buf = base64_encode_cstr(text3, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)etext3, len));

    buf = base64_encode_cstr(text4, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)etext4, len));

    buf = base64_encode_cstr(text5, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)etext5, len));

    buf = base64_encode_cstr(text6, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)etext6, len));

    buf = base64_decode_cstr(etext1, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)text1, len));

    buf = base64_decode_cstr(etext2, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)text2, len));

    buf = base64_decode_cstr(etext3, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)text3, len));

    buf = base64_decode_cstr(etext4, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)text4, len));

    buf = base64_decode_cstr(etext5, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)text5, len));

    buf = base64_decode_cstr(etext6, &len, heap);
    cutile_test_assert_m(memory_equals(buf, (u8*)text6, len));

    cutile_test_end_m();
}
