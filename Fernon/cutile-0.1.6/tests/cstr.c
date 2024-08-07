#define CUTILE_IMPLEM
#include "../cstr.h"
#include "../test.h"

int main(int ac, char** av)
{
    cutile_test_begin_m();

    cutile_allocator* default_allocator;
    cutile_heap_allocator heapallocator = cutile_create_default_heap_allocator();
    default_allocator = (allocator*)&heapallocator;

    // cstr<->number conversions tests.
    {
        cutile_test_assert_m(cstr_equals(u8_to_cstr(u8_max, default_allocator), "255"));
        cutile_test_assert_m(cstr_equals(u8_to_cstr(u8_min, default_allocator), "0"));
        cutile_test_assert_m(cstr_equals(s8_to_cstr(s8_max, default_allocator), "127"));
        cutile_test_assert_m(cstr_equals(s8_to_cstr(s8_min, default_allocator), "-128"));

        cutile_test_assert_m(cstr_equals(u16_to_cstr(u16_max, default_allocator), "65535"));
        cutile_test_assert_m(cstr_equals(u16_to_cstr(u16_min, default_allocator), "0"));
        cutile_test_assert_m(cstr_equals(s16_to_cstr(s16_max, default_allocator), "32767"));
        cutile_test_assert_m(cstr_equals(s16_to_cstr(s16_min, default_allocator), "-32768"));

        cutile_test_assert_m(cstr_equals(u32_to_cstr(u32_max, default_allocator), "4294967295"));
        cutile_test_assert_m(cstr_equals(u32_to_cstr(u32_min, default_allocator), "0"));
        cutile_test_assert_m(cstr_equals(s32_to_cstr(s32_max, default_allocator), "2147483647"));
        cutile_test_assert_m(cstr_equals(s32_to_cstr(s32_min, default_allocator), "-2147483648"));

        cutile_test_assert_m(cstr_equals(u64_to_cstr(u64_max, default_allocator), "18446744073709551615"));
        cutile_test_assert_m(cstr_equals(u64_to_cstr(u64_min, default_allocator), "0"));
        cutile_test_assert_m(cstr_equals(s64_to_cstr(s64_max, default_allocator), "9223372036854775807"));
        cutile_test_assert_m(cstr_equals(s64_to_cstr(s64_min, default_allocator), "-9223372036854775808"));
    }
}
