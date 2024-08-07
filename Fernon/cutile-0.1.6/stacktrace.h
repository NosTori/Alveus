#ifndef CUTILE_STACKTRACE_H

    #ifndef _WIN32
        #error "stacktrace.h is not supported yet on other platforms than WIN32"
    #endif

    #include "array.h"

    #ifndef     CUTILE_STACKTRACE_FRAME_FILENAME_MAX_LEN
        #define CUTILE_STACKTRACE_FRAME_FILENAME_MAX_LEN 512
    #endif
    #ifndef     CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN
        #define CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN 64
    #endif

    typedef struct
    {
        u32               line;
        s8                filename[CUTILE_STACKTRACE_FRAME_FILENAME_MAX_LEN];
        s8                symbol_name[CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN];

        u16               filename_length;
        u16               symbol_name_length;
    } cutile_stacktrace_frame; 
    // I really have no idea how I should name this thing 

    cutile_generate_named_array_m(cutile_stacktrace_frame, cutile_stacktrace);

    cutile_stacktrace cutile_get_stacktrace(u16 skip, u16 depth, cutile_allocator* allocator);
    b8                cutile_fill_stacktrace(cutile_stacktrace* stacktrace, u16 skip, u16 depth);
    void              cutile_destroy_stacktrace(cutile_stacktrace* stacktrace);

    #ifdef CUTILE_IMPLEM

        #ifdef _WIN32
            #include <windows.h>
            #ifdef _MSC_VER
                #pragma comment(lib, "DbgHelp.lib")
            #endif
            #include <dbghelp.h>
        #endif

        cutile_stacktrace cutile_get_stacktrace(u16 skip, u16 depth, cutile_allocator* allocator)
        {
            cutile_stacktrace result;
            result = cutile_create_cutile_stacktrace(20, 20, allocator);
            cutile_fill_stacktrace(&result, skip + 1, depth);
            return result;
        }

        b8 cutile_fill_stacktrace(cutile_stacktrace* stacktrace, u16 skip, u16 depth)
        {
            u16 current_skip = 0;
            u16 current_depth = 0;
            #ifdef _WIN32
                persist HANDLE current_process = nullptr;
                HANDLE current_thread = GetCurrentThread();
                CONTEXT context;
                STACKFRAME64 stackframe = {0};

                if (!current_process)
                {
                    current_process = GetCurrentProcess();
                    if (!SymInitialize(current_process, nullptr, TRUE))
                    {
                        return b8_false;
                    }
                }
                RtlCaptureContext(&context);
                stackframe.AddrPC.Offset = context.Rip;
                stackframe.AddrPC.Mode = AddrModeFlat;
                stackframe.AddrFrame.Offset = context.Rbp;
                stackframe.AddrFrame.Mode = AddrModeFlat;
                stackframe.AddrStack.Offset = context.Rsp;
                stackframe.AddrStack.Mode = AddrModeFlat;

                do
                {
                    if (StackWalk(IMAGE_FILE_MACHINE_AMD64, current_process, current_thread, &stackframe, &context, nullptr, &SymFunctionTableAccess64, &SymGetModuleBase64, nullptr))
                    {
                        if (current_skip < skip + 1)
                        {
                            ++current_skip;
                            continue;
                        }

                        if (current_depth < depth) ++current_depth;
                        else break;
    
                        DWORD64         displacement;
                        DWORD           line_displacement;
                        s8              symbol_info[sizeof(SYMBOL_INFO) + CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN];
                        IMAGEHLP_LINE64 line_info;
                        PSYMBOL_INFO    psymbol_info = (PSYMBOL_INFO)symbol_info;
                        
                        psymbol_info->SizeOfStruct = sizeof(SYMBOL_INFO);
                        psymbol_info->MaxNameLen = CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN;
                        line_info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
                        if (SymFromAddr(current_process, stackframe.AddrPC.Offset, &displacement, (PSYMBOL_INFO)symbol_info) &&
                            SymGetLineFromAddr(current_process, stackframe.AddrPC.Offset, &line_displacement, &line_info))
                        {
                            cutile_stacktrace_frame frame = {0};
                            frame.line = line_info.LineNumber;
                            while (line_info.FileName[frame.filename_length]) frame.filename_length++;
                            if (frame.filename_length > CUTILE_STACKTRACE_FRAME_FILENAME_MAX_LEN) frame.filename_length = CUTILE_STACKTRACE_FRAME_FILENAME_MAX_LEN;
                            cutile_copy_memory_m((u8*)frame.filename, (u8*)line_info.FileName, frame.filename_length);
                            if (psymbol_info->NameLen > CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN)
                                frame.symbol_name_length = CUTILE_STACKTRACE_FRAME_SYMBOL_NAME_MAX_LEN;
                            else
                                frame.symbol_name_length = psymbol_info->NameLen;
                            cutile_copy_memory_m(frame.symbol_name, psymbol_info->Name, frame.symbol_name_length);

                            cutile_stacktrace_push(stacktrace, frame);
                        }
                        else break;
                    }
                    else break;
                } while (b8_true);
    
            return b8_true;
    
            #endif
        }
    
        void cutile_destroy_stacktrace(cutile_stacktrace* stacktrace)
        {
            cutile_destroy_cutile_stacktrace(stacktrace);
        }
    
    #endif // CUTILE_IMPLEM

    #define CUTILE_STACKTRACE_H
#endif
