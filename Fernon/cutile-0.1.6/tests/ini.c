#define CUTILE_IMPLEM
#include "../test.h"
#include "../ini.h"

int main(int ac, char** av)
{
    cutile_test_begin_m();

    cutile_heap_allocator heap_allocator = cutile_create_default_heap_allocator();
    cutile_allocator* allocator = (cutile_allocator*)&heap_allocator;

    const char ini_data[] =
        "foo=123\n"
        "bar=Value\n"
        "[SectionA]\n"
        "rab=321\n"
        ";; comment\n"
        "oof=uelaV";

    cutile_parse_ini_result result = cutile_parse_ini((const u8*)ini_data, sizeof(ini_data)/sizeof(char) - 1 /*  */, allocator);

    cutile_test_assert_m(result.error.msg == nullptr);
    if (result.error.msg)
    {
        println_cstr(result.error.msg);
        cutile_test_end_m();
    }

    cutile_ini_entry_value_result entry_value;
    entry_value = cutile_get_ini_global_entry_value("foo", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_true);
        if (entry_value.found)
        {
            cutile_test_assert_m(entry_value.value_start[0] == '1');
            cutile_test_assert_m(entry_value.value_start[1] == '2');
            cutile_test_assert_m(entry_value.value_start[2] == '3');
            cutile_test_assert_m(entry_value.value_size == 3);
        }
    }
    entry_value = cutile_get_ini_global_entry_value("bar", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_true);
        if (entry_value.found)
        {
            cutile_test_assert_m(entry_value.value_start[0] == 'V');
            cutile_test_assert_m(entry_value.value_size == 5);
        }
    }
    entry_value = cutile_get_ini_entry_value("SectionA", "rab", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_true);
        if (entry_value.found)
        {
            cutile_test_assert_m(entry_value.value_start[0] == '3');
            cutile_test_assert_m(entry_value.value_size == 3);
        }
    }
    entry_value = cutile_get_ini_entry_value("SectionA", "oof", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_true);
        if (entry_value.found)
        {
            cutile_test_assert_m(entry_value.value_start[0] == 'u');
            cutile_test_assert_m(entry_value.value_size == 5);
        }
    }
    entry_value = cutile_get_ini_entry_value("SectionA", "bar", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_false);
    }
    entry_value = cutile_get_ini_entry_value("SectionC", "oof", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_false);
    }
    entry_value = cutile_get_ini_global_entry_value("oof", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_false);
    }
    entry_value = cutile_get_ini_global_entry_value("not_existing_entry", &result);
    {
        cutile_test_assert_m(entry_value.found == b8_false);
    }
    cutile_destroy_ini_parsed_data(&result);
    
    cutile_test_end_m();
}
