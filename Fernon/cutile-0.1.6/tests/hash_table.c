#define CUTILE_IMPLEM
#include "../hash_table.h"
#include "../test.h"

u64 dummy_hash(u8* data, u64 data_size)
{
    return data[0];
};

b8 dummy_compare(u8* lhs, u64 lhs_size, u8* rhs, u64 rhs_size)
{
    if (rhs_size != lhs_size) return b8_false;
    for (u32 i = 0; i < rhs_size; ++i)
    {
        if (lhs[i] != rhs[i]) return b8_false;
    }
    return b8_true;
}

allocator* cutile_default_allocator;

int main(int ac, char** av)
{
    cutile_test_begin_m();

    heap_allocator allocator = create_default_heap_allocator();
    cutile_set_default_allocator_m(&allocator);

    hash_table tbl = create_hash_table(24, &dummy_hash, &dummy_compare, sizeof(u8),
                                       cutile_default_allocator);

    u8* val = hash_table_emplace(&tbl, (u8*)"1", 1);
    *val = 55;
    cutile_test_assert_m(*hash_table_get(&tbl, (u8*)"1", 1) == 55);

    u8* val2 = hash_table_emplace(&tbl, (u8*)"2", 1);
    *val2 = 128;
    cutile_test_assert_m(*hash_table_get(&tbl, (u8*)"2", 1) == 128);

    u8* val5 = hash_table_emplace(&tbl, (u8*)"5", 1);
    *val5 = 3;
    cutile_test_assert_m(*hash_table_get(&tbl, (u8*)"5", 1) == 3);
    
    u8* val11 = hash_table_emplace(&tbl, (u8*)"11", 2);
    *val11 = 12;
    cutile_test_assert_m(*hash_table_get(&tbl, (u8*)"11", 2) == 12);

    cutile_test_assert_m(tbl.count == 4);

    hash_table_remove(&tbl, (u8*)"1", 1);
    cutile_test_assert_m(hash_table_get(&tbl, (u8*)"1", 1) == nullptr);

    cutile_test_assert_m(tbl.count == 3);

    cutile_test_assert_m(*hash_table_get(&tbl, (u8*)"11", 2) == 12);

    cutile_destroy_hash_table(&tbl);

    cutile_test_end_m();
}
