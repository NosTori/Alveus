#ifndef CUTILE_PROCESS_H

    #include "cxx.h"

    CUTILE_C_API void cutile_exit_process(unsigned int exit_code);

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define exit_process(exit_code) cutile_exit_process(exit_code)
    #endif

    #ifdef CUTILE_IMPLEM
        #if WINDOWS
            #include <processthreadsapi.h>
        #elif UNIX_LIKE
            #include <unistd.h>
        #endif

        void cutile_exit_process(unsigned int exit_code)
        {
            #if WINDOWS
            {
                ExitProcess(exit_code);
            }
            #elif UNIX_LIKE
            {
                _exit(exit_code);
            }
            #else
                #error "cutile_exit_process: Unsupported platform."
            #endif
        }
    #endif

    #define CUTILE_PROCESS_H
#endif
