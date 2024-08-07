#define CUTILE_IMPLEM
#include "../shared_library.h"
#include "../test.h"

int main()
{
    cutile_test_begin_m();

    cutile_shared_library sl = {0};
    #if LINUX
        sl = cutile_load_shared_library("./shared_library_sample.so");
    #elif WINDOWS
        sl = cutile_load_shared_library("shared_library_sample.dll");
    #endif
    cutile_test_require_m(sl.handle);

    void (*proc)();
    proc = cutile_get_shared_library_T_proc(void(*)(), &sl, "dummy_func");
    cutile_test_require_m(proc);
    proc = get_shared_library_T_proc(void(*)(), &sl, "dummy_func");
    cutile_test_require_m(proc);

    cutile_test_end_m();
}
