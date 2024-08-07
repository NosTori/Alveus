#define CUTILE_IMPLEM
#define CUTILE_IMPLEM_FILESYSTEM_STRING_API
#include "../filesystem.h"
#include "../test.h"
#include "../cstr.h"

int main()
{
    cutile_test_begin_m();

    cutile_heap_allocator heap_allocator = cutile_create_default_heap_allocator();
    cutile_allocator* allocator = (cutile_allocator*)&heap_allocator;


    cutile_string program_dir_path = cutile_get_current_executable_dir_path_str(allocator);
    cutile_string test_dir_name = create_str_from_cstr("filesystem_test_dir", allocator);
    cutile_string dummy_file_name = create_str_from_cstr("dummy_file.txt", allocator);
    cutile_string dummy_relative_path = cutile_concat_file_paths_str(&test_dir_name, &dummy_file_name, allocator);
    cutile_string dummy_absolute_path = cutile_concat_file_paths_str(&program_dir_path, &dummy_relative_path, allocator);

    const char* p1 = "foo/bar/t";
    const char* p2 = "u/vv";
    const char* p3 = cutile_concat_file_paths(p1, p2, allocator);

    #if WINDOWS
        cutile_test_assert_m(cutile_str_equals_cstr(&dummy_relative_path, "filesystem_test_dir\\dummy_file.txt"));
        cutile_test_assert_m(cutile_cstr_equals(p3, "foo/bar/t\\u/vv"));
    #elif UNIX_LIKE
        cutile_test_assert_m(cutile_str_equals_cstr(&dummy_relative_path, "filesystem_test_dir/dummy_file.txt"));
        cutile_test_assert_m(cutile_cstr_equals(p3, "foo/bar/t/u/vv"));
    #endif
    cutile_test_assert_m(cutile_file_exists_str(&dummy_absolute_path, allocator));

    cutile_destroy_str(&program_dir_path);
    cutile_destroy_str(&test_dir_name);
    cutile_destroy_str(&dummy_file_name);
    cutile_destroy_str(&dummy_relative_path);
    cutile_destroy_str(&dummy_absolute_path);

    cutile_test_end_m();
}
