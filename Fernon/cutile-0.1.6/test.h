#ifndef CUTILE_TEST_H

    #include "print.h"
    #include "process.h"

    #define cutile_test_begin_m() int __cutile_test_result = 0;

    #define cutile_test_assert_m(predicate)                                                                     \
    {                                                                                                           \
        if (!(predicate))                                                                                       \
        {                                                                                                       \
            cutile_println_cstr("Assertion failed, " __FILE__ "." cutile_current_line_cstr_m ": " #predicate);  \
            __cutile_test_result = 1;                                                                           \
        }                                                                                                       \
    }

    #define cutile_test_require_m(predicate)                                    \
    {                                                                           \
        cutile_test_assert_m(predicate);                                        \
        if (__cutile_test_result) cutile_exit_process(__cutile_test_result);    \
    }

    #define cutile_test_end_m() cutile_println_cstr(__cutile_test_result ? "Test failed !" : "Test success !"); return __cutile_test_result;

    #define CUTILE_TEST_H
#endif
