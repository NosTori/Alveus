#define CUTILE_IMPLEM
#define CUTILE_IMPLEM_PRINT_STRING_API
#include "../memory_allocator_analyzer.h"
#include "../memory_allocator_analyzer_print.h"
#include "../str.h"
#include "../test.h"

u8         allocation_table_data[20000000];
allocator* default_allocator;

int main(int ac, char** av)
{
    cutile_test_begin_m();

    // The allocator used by the allocation table to store allocation data.
    cutile_arena_allocator allocation_table_arena = cutile_create_arena_allocator(allocation_table_data, cutile_fixed_array_length_m(allocation_table_data));

    // Where our allocation informations goes.
    cutile_allocation_table allocations_data = cutile_start_allocators_analysis_m(&allocation_table_arena);

    // The allocator we want to analyze.
    cutile_analyzable_heap_allocator heap_allocator_to_analyze = cutile_create_analyzable_heap_allocator(&allocations_data);
    default_allocator = (cutile_allocator*)&heap_allocator_to_analyze;

    cutile_string str1 = cutile_create_sized_empty_str(2048, default_allocator);
    cutile_string str2 = cutile_create_sized_empty_str(4096, default_allocator);

    cutile_print_allocation_table(&allocations_data, (allocator*)&allocation_table_arena);

    cutile_finish_allocators_analysis(&allocations_data);

    cutile_test_end_m();
}
