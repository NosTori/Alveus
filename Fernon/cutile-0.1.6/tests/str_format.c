#define CUTILE_IMPLEM
#include "../test.h"
#include "../str_format.h"

int main()
{
    cutile_test_begin_m();

    cutile_heap_allocator heapallocator = create_default_heap_allocator();
    cutile_allocator* allocator = (cutile_allocator*)&heapallocator;

    cutile_string fmt = cutile_format_str(allocator, "Welcome % sailor ! %", "aboard", -485);
    cutile_test_assert_m(str_equals(&fmt, "Welcome aboard sailor ! -485"));

    cutile_test_end_m();
}
