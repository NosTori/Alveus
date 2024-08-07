#define CUTILE_IMPLEM
#include "../str.h"
#include "../test.h"
#include "../number.h"

int main(int ac, char** av)
{
    cutile_test_begin_m();

    cutile_allocator* default_allocator;
    cutile_heap_allocator heapallocator = cutile_create_default_heap_allocator();
    default_allocator = (allocator*)&heapallocator;

    // UTF-8
    {
        #ifdef CUTILE_CPP
            string s1 = create_str("こんにちは！", default_allocator);
            cutile_string s2 = cutile_create_str("プログラングが好き", default_allocator);
        #else
            string s1 = create_str_from_cstr("こんにちは！", default_allocator);
            cutile_string s2 = cutile_create_str_from_cstr("プログラングが好き", default_allocator);
        #endif
        str_insert_utf8_cp(&s2, 4, 0xe3839f/*'ミ'*/);
        str_push_back_utf8_cp(&s2, 0xe38082/*'。'*/);
        cutile_string s3 = cutile_create_str_from_cstr("ASCIIとUTF-8.", default_allocator);

        cutile_test_assert_m(str_is_valid_utf8(&s1));
        cutile_test_assert_m(str_is_valid_utf8(&s2));
        cutile_test_assert_m(str_is_valid_utf8(&s3));

        cutile_test_assert_m(str_utf8_count(&s1) == 6);
        cutile_test_assert_m(str_utf8_count(&s2) == 11);
        cutile_test_assert_m(str_utf8_count(&s3) == 12);

        // 11 is the number of Japanese characters inside s2.
        b8 s2_found[11] = {0,0,0,0,0,0,0,0,0,0,0};

        for (string_utf8_iterator it = str_create_utf8_iterator(&s2);
             it.valid;
             str_utf8_iterate(&it))
        {
            switch (it.value) {
                case 0xe38397/*'プ'*/: s2_found[0] = b8_true; break;
                case 0xe383ad/*'ロ'*/: s2_found[1] = b8_true; break;
                case 0xe382b0/*'グ'*/: 
                {
                    if (s2_found[2]) s2_found[6] = b8_true;
                    else s2_found[2] = b8_true; 
                    break;
                }
                case 0xe383a9/*'ラ'*/: s2_found[3] = b8_true; break;
                case 0xe3839f/*'ミ'*/: s2_found[4] = b8_true; break;
                case 0xe383b3/*'ン'*/: s2_found[5] = b8_true; break;
                case 0xe3818c/*'が'*/: s2_found[7] = b8_true; break;
                case 15050173/*'好'*/: s2_found[8] = b8_true; break;
                case 0xe3818d/*'き'*/: s2_found[9] = b8_true; break;
                case 0xe38082/*'。'*/: s2_found[10] = b8_true; break;
            }
        }

        cutile_test_assert_m(s2_found[0]);
        cutile_test_assert_m(s2_found[1]);
        cutile_test_assert_m(s2_found[2]);
        cutile_test_assert_m(s2_found[3]);
        cutile_test_assert_m(s2_found[4]);
        cutile_test_assert_m(s2_found[5]);
        cutile_test_assert_m(s2_found[6]);
        cutile_test_assert_m(s2_found[7]);
        cutile_test_assert_m(s2_found[8]);
        cutile_test_assert_m(s2_found[9]);
        cutile_test_assert_m(s2_found[10]);
    }

    // Number to string conversions tests.
    {
        u32 i = 50;
        s32 j = -12893;
        s64 k = 2438750912;
    
        int dig; cutile_get_s32_digits_m(j, dig);
        cutile_string si = u32_to_str(i, default_allocator);
        cutile_string sj = s32_to_str(j, default_allocator);
        cutile_string sk = s64_to_str(k, default_allocator);
        u32_into_str(i, &sk);

        cutile_test_assert_m(str_equals_cstr(&si, "50"));
        cutile_test_assert_m(str_equals_cstr(&sj, "-12893"));
        cutile_test_assert_m(str_equals_cstr(&sk, "243875091250"));

        cutile_test_assert_m(str_equals_cstr2(u8_to_str(u8_max, default_allocator), "255"));
        cutile_test_assert_m(str_equals_cstr2(u8_to_str(u8_min, default_allocator), "0"));
        cutile_test_assert_m(str_equals_cstr2(s8_to_str(s8_max, default_allocator), "127"));
        cutile_test_assert_m(str_equals_cstr2(s8_to_str(s8_min, default_allocator), "-128"));
 
        cutile_test_assert_m(str_equals_cstr2(u16_to_str(u16_max, default_allocator), "65535"));
        cutile_test_assert_m(str_equals_cstr2(u16_to_str(u16_min, default_allocator), "0"));
        cutile_test_assert_m(str_equals_cstr2(s16_to_str(s16_max, default_allocator), "32767"));
        cutile_test_assert_m(str_equals_cstr2(s16_to_str(s16_min, default_allocator), "-32768"));

        cutile_test_assert_m(str_equals_cstr2(u32_to_str(u32_max, default_allocator), "4294967295"));
        cutile_test_assert_m(str_equals_cstr2(u32_to_str(u32_min, default_allocator), "0"));
        cutile_test_assert_m(str_equals_cstr2(s32_to_str(s32_max, default_allocator), "2147483647"));
        cutile_test_assert_m(str_equals_cstr2(s32_to_str(s32_min, default_allocator), "-2147483648"));

        string adfjk = u64_to_str(u64_max, default_allocator);
        cutile_test_assert_m(str_equals_cstr2(u64_to_str(u64_max, default_allocator), "18446744073709551615"));
        cutile_test_assert_m(str_equals_cstr2(u64_to_str(u64_min, default_allocator), "0"));
        cutile_test_assert_m(str_equals_cstr2(s64_to_str(s64_max, default_allocator), "9223372036854775807"));
        cutile_test_assert_m(str_equals_cstr2(s64_to_str(s64_min, default_allocator), "-9223372036854775808"));
    }

    // String to number conversions tests.
    {
        cutile_string s;

        s = create_str_from_cstr("255", default_allocator);
        cutile_test_assert_m(str_to_u8(&s) == 255);
        s = create_str_from_cstr("0", default_allocator);
        cutile_test_assert_m(str_to_u8(&s) == 0);
        s = create_str_from_cstr("127", default_allocator);
        cutile_test_assert_m(str_to_s8(&s) == 127);
        s = create_str_from_cstr("-128", default_allocator);
        cutile_test_assert_m(str_to_s8(&s) == -128);

        s = create_str_from_cstr("65535", default_allocator);
        cutile_test_assert_m(str_to_u16(&s) == 65535);
        s = create_str_from_cstr("0", default_allocator);
        cutile_test_assert_m(str_to_u16(&s) == 0);
        s = create_str_from_cstr("32767", default_allocator);
        cutile_test_assert_m(str_to_s16(&s) == 32767);
        s = create_str_from_cstr("-32768", default_allocator);
        cutile_test_assert_m(str_to_s16(&s) == -32768);

        s = create_str_from_cstr("4294967295", default_allocator);
        cutile_test_assert_m(str_to_u32(&s) == 4294967295);
        s = create_str_from_cstr("0", default_allocator);
        cutile_test_assert_m(str_to_u32(&s) == 0);
        s = create_str_from_cstr("2147483647", default_allocator);
        cutile_test_assert_m(str_to_s32(&s) == 2147483647);
        s = create_str_from_cstr("-2147483648", default_allocator);
        cutile_test_assert_m(str_to_s32(&s) == -2147483648);

        s = create_str_from_cstr("18446744073709551615", default_allocator);
        cutile_test_assert_m(str_to_u64(&s) == 18446744073709551615ULL);
        s = create_str_from_cstr("0", default_allocator);
        cutile_test_assert_m(str_to_u64(&s) == 0);
        s = create_str_from_cstr("9223372036854775807", default_allocator);
        cutile_test_assert_m(str_to_s64(&s) == 9223372036854775807);
        s = create_str_from_cstr("-9223372036854775808", default_allocator);
        cutile_test_assert_m(str_to_s64(&s) == -9223372036854775808ULL);

        s = create_str_from_cstr("EXTRACT 2 SUB -4839 NB 777!-1", default_allocator);
        cutile_test_assert_m(sub_str_to_u8(&s, 8, 1) == 2);
        cutile_test_assert_m(sub_str_to_s16(&s, 14, 5) == -4839);
        cutile_test_assert_m(sub_str_to_s16(&s, 23, 3) == 777);
        cutile_test_assert_m(sub_str_to_s64(&s, s.count-2, 2) == -1);
    }

    cutile_test_end_m();
}
