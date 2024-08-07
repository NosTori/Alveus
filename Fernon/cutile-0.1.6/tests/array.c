#define CUTILE_IMPLEM
#include "../array.h"
#include "../test.h"

cutile_allocator* cutile_default_allocator;

int main(int ac, char** av)
{
    cutile_test_begin_m();

    cutile_heap_allocator heap_allocator = create_default_heap_allocator();
    cutile_set_default_allocator_m(&heap_allocator);

    array(s16) array = cutile_create_s16_array(10, 5, cutile_default_allocator);

    cutile_s16_array_push(&array, 5);
    {
        cutile_test_assert_m(array.count == 1);
        cutile_test_assert_m(array.size == 10);
        cutile_test_assert_m(array.data[0] == 5);
    }

    cutile_s16_array_push_repeated(&array, 10, 20);
    {
        cutile_test_assert_m(array.count == 21);
        cutile_test_assert_m(array.size == 21);
        cutile_test_assert_m(array.data[0] = 5);
        for (u32 i = 1; i < array.count; ++i)
        {
            cutile_test_assert_m(array.data[i] == 10);
        }
    }

    s16 buf[] = { 7, 8, 9 };
    s16_array_push_buffer(&array, buf, cutile_fixed_array_length_m(buf));
    {
        cutile_test_assert_m(array.count == 24);
        cutile_test_assert_m(array.size == 24);
        cutile_test_assert_m(array.data[0] = 5);
        for (u32 i = 1; i < 21; ++i)
        {
            cutile_test_assert_m(array.data[i] == 10);
        }
        cutile_test_assert_m(array.data[21] = 7);
        cutile_test_assert_m(array.data[22] = 8);
        cutile_test_assert_m(array.data[23] = 9);
    }
    cutile_test_end_m();
}
