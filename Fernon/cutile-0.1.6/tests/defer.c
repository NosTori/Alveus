#define CUTILE_IMPLEM
#include "../test.h"

cutile_test_begin_m();

void test_defer(int* value_to_change, b8 branch)
{
    int value_dump = *value_to_change;
    defer(*value_to_change = branch ? 0 : 1);

    // Value should not have changed yet at this point.
    cutile_test_assert_m(value_dump == *value_to_change);
}

int main()
{
    int val = 10;

    test_defer(&val, b8_true);
    cutile_test_assert_m(val == 0);

    test_defer(&val, b8_false);
    cutile_test_assert_m(val == 1);

    cutile_test_end_m();
}
