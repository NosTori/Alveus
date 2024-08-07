#define CUTILE_IMPLEM
#include "../stacktrace.h"
#include "../test.h"

cutile_allocator* default_allocator;

cutile_test_begin_m();

void depth_two()
{
    cutile_stacktrace st = cutile_get_stacktrace(0, u16_max, default_allocator);
    cutile_destroy_stacktrace(&st);
}

void depth_one()
{
    cutile_stacktrace st = cutile_get_stacktrace(0, u16_max, default_allocator);
    {
        cutile_stacktrace_frame* st_elem;
        
        cutile_test_require_m(st.count > 2);
        
        st_elem = &st.data[0];
        cutile_test_assert_m(st_elem->symbol_name_length == 9)
        cutile_test_assert_m(memory_equals((u8*)"depth_one", (u8*)st_elem->symbol_name, 9));
        
        st_elem = &st.data[1];
        cutile_test_assert_m(st_elem->symbol_name_length == 4)
        cutile_test_assert_m(memory_equals((u8*)"main", (u8*)st_elem->symbol_name, 4));

        cutile_destroy_stacktrace(&st);
    }
    depth_two();
}

int main(void)
{
    heap_allocator heapall = create_default_heap_allocator();
    default_allocator = (cutile_allocator*)&heapall;

    depth_one();

    cutile_test_end_m();
}
