#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <shellapi.h>
#include <psapi.h>

#define CUTILE_IMPLEM
#define CUTILE_IMPLEM_PRINT_STRING_API
#include "Fernon/cutile-0.1.6/filesystem.h"
#include "Fernon/cutile-0.1.6/cstr.h"
#include "Fernon/cutile-0.1.6/network.h"
#include "Fernon/cutile-0.1.6/print.h"
#include "Fernon/login.h"
#include "Fernon/client_constants.h"

struct alveus_state
{
    u8          ip[15+1] = {0};
    b8          ip_set = b8_false;

    const char* nostale_directory = nullptr;

    b8          dx_client = b8_true;                    // True for DirectX client, false for OpenGL client.

    b8          run_temporary_patched_client = b8_true;

    b8          out_path_relative_to_nostale_directory;
    const char* out_path = nullptr;
    b8          run_patched_client = b8_false;

    b8          run_specific_client = b8_false;
    const char* specific_client_path = nullptr;

    b8          show_help = b8_false;
    b8          show_version = b8_false;
};

internal b8 patch_process(HANDLE HProcess, u32 address, u8* patch_bytes, u32 patch_size)
{
    void* remote_address = cast(void*, address);

    DWORD old_protect = 0;
    if (!VirtualProtectEx(HProcess, remote_address, patch_size, PAGE_READWRITE, &old_protect))
    {
        println("Failed to change page protection.");
        return b8_false;
    }

    SIZE_T num_written = 0;

    if (!WriteProcessMemory(HProcess, remote_address, patch_bytes, patch_size, &num_written) ||
        num_written != patch_size)
    {
        println("Failed to apply patch.");
        return b8_false;    
    }

    if (!VirtualProtectEx(HProcess, remote_address, patch_size, old_protect, &old_protect))
    {
        println("Failed to restore page protection.");
        return b8_false;
    }

    return b8_true;
}

internal b8 run_specific_client(const char* client_path, HANDLE* out = nullptr, b8 close_handle = b8_true)
{
    string work_dir = format_str("%\\..\\", client_path);

    SHELLEXECUTEINFO shExInfo = {0};
    shExInfo.cbSize = sizeof(shExInfo);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = 0;
    shExInfo.lpVerb = "runas";            // Operation to perform
    shExInfo.lpFile = client_path;       // Application to start    
    shExInfo.lpParameters = "EntwellNostaleClient";                  // Additional parameters
    shExInfo.lpDirectory = create_cstr_from_str(&work_dir, default_allocator);
    shExInfo.nShow = SW_SHOW;
    shExInfo.hInstApp = 0;  

    if (!ShellExecuteEx(&shExInfo)) return b8_false;

    if (out) *out = shExInfo.hProcess;
    if (close_handle) CloseHandle(shExInfo.hProcess);

    return b8_true;
}

internal b8 run_and_patch_client(alveus_state* state)
{
    string path;
    if (state->dx_client)
    {
        path = format_str("%\\NostaleClientX.exe", state->nostale_directory);
    }
    else
    {
        path = format_str("%\\NostaleClient.exe", state->nostale_directory);
    }
    const char* cstr_path = create_cstr_from_str(&path, default_allocator);

    HANDLE hProcess;
    if (!run_specific_client(cstr_path, &hProcess, b8_false))
    {
        println_fmt("Failed to start %.", path);
        return b8_false;
    }

    Sleep(10000); // Ugly workaround that waits until the splash screen is finished. TODO: Find something more reliable.

    DWORD   modules_size;    
    if (!EnumProcessModules(hProcess, nullptr, 0, &modules_size))
    {
        println_fmt("Failed to get modules size. Win32 returned %.", (u32)GetLastError());
        return b8_false;
    }

    HMODULE* modules = cast(HMODULE*, allocate(default_allocator, modules_size));
    if (!EnumProcessModules(hProcess, cast(HMODULE*, modules), modules_size, &modules_size))
    {
        println_fmt("Failed to enumerate modules. Win32 returned %.", (u32)GetLastError());
        return b8_false;
    }

    MODULEINFO wished_module_info;
    b8         module_found = b8_false;
    for (u32 i = 0; i < modules_size / sizeof(HMODULE); ++i)
    {
        char file_path[256+1] = {0};

        if (!GetModuleFileNameExA(hProcess,
                                  modules[i],
                                  file_path,
                                  256))
        {
            println_fmt("Failed to get module file name. Win32 returned %.", (u32)GetLastError());
            return b8_false;
        }

        if (cstr_equals(cutile_get_last_path_element(cstr_path), cutile_get_last_path_element(file_path)))
        {
            if (!GetModuleInformation(hProcess, modules[i], &wished_module_info, sizeof(wished_module_info)))
            {
                println_fmt("Failed to get module info. Win32 returned %.", (u32)GetLastError());
                return b8_false;
            }

            module_found = b8_true;
            break;
        }
        else
        {
            println_fmt("% vs %", path, file_path);
        }
    }

    if (!module_found)
    {
        println_fmt("Failed to find executable module.");
        return b8_false;
    }

    u32 image_base_address_ptr = cast(u32, wished_module_info.lpBaseOfDll);
    u32 imageBaseAddress;
    SIZE_T numRead;
    if(!ReadProcessMemory(hProcess, (void*)image_base_address_ptr, &imageBaseAddress, 4, &numRead))
	{
        println("Failed to read base address ptr");
        return b8_false;
	}

    println_fmt("Base address is %, IP is %.", (u32)image_base_address_ptr, (u32)image_base_address_ptr + NostaleClientX_LOGIN_IP_ADDRESS_START_ADDRESS);

    char tmp[15];
    SIZE_T read = 0;
    if (state->dx_client)
    {
        if (!patch_process(hProcess,
                           image_base_address_ptr + NostaleClientX_LOGIN_IP_ADDRESS_START_ADDRESS + NostaleClientX_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET,
                           (u8*)state->ip,
                           NostaleClientX_LOGIN_IP_ADDRESS_LENGTH))
        {
            println("Failed to patch Nostale executable.");
            return b8_false;
        }
    }
    else
    {
        if (!patch_process(hProcess,
                           image_base_address_ptr + NostaleClient_LOGIN_IP_ADDRESS_START_ADDRESS + NostaleClient_SECTION_CODE_RUNTIME_START_ADDRESS_OFFSET,
                           (u8*)state->ip,
                           NostaleClient_LOGIN_IP_ADDRESS_LENGTH))
        {
            println("Failed to patch Nostale executable.");
            return b8_false;
        }
    }

    println("Successfully patched Nostale executable.");

    CloseHandle(hProcess);

    return b8_true;
}

internal b8 create_patched_client(alveus_state* state)
{
    u32 login_ip_address_start = state->dx_client ? NostaleClientX_LOGIN_IP_ADDRESS_START_ADDRESS : NostaleClient_LOGIN_IP_ADDRESS_START_ADDRESS;
    u32 login_ip_address_length = state->dx_client ? NostaleClientX_LOGIN_IP_ADDRESS_LENGTH : NostaleClient_LOGIN_IP_ADDRESS_LENGTH;

    const char* in_path = concat_file_paths(state->nostale_directory, state->dx_client ? "NostaleClientX.exe" : "NostaleClient.exe", default_allocator);
    const char* out_path = state->out_path_relative_to_nostale_directory ? concat_file_paths(state->nostale_directory, state->out_path, default_allocator) : state->out_path;
    if (!in_path || !out_path) return 1;

    u8* content;
    u64 size;
    if (!get_file_content_from_path(in_path, default_allocator, &content, &size))
    {
        println_fmt("Failed to get file content of %.", in_path);
        return b8_false;
    }

    if (size < login_ip_address_start + login_ip_address_length)
    {
        println_fmt("% cannot be patched because its size does not match to a valid Nostale client's size.", in_path);
        return b8_false;
    }

    u32 i = 0;
    while (state->ip[i])
    {
        content[login_ip_address_start + i] = state->ip[i];
        ++i;
    }
    while (i < login_ip_address_length)
    {
        content[i] = 0x00;
        ++i;
    }

    file new_client;
    if (!create_file(cutile_file_always_create, file_access_mode_write, out_path, &new_client))
    {
        println_fmt("Failed to create a new file at %.", out_path);
        return b8_false;
    }

    // TODO: cutile does not return any info about whether the call succeeded or not. Are we good about this ?
    write_in_file(&new_client, content, size);
    close_file(&new_client);

    println_fmt("Client successfully created at %.", out_path);

    return b8_true;
}

struct cmd_arg
{
    const char*  name;
    int          next_params_nb;
    const char*  valid_next_params[8+1]; // Must end by a null pointer.
    const char*  help_desc;

    b8           (*handler)(alveus_state*, const char** params);
};

internal b8 change_client_type(alveus_state* state, const char** params)
{
    if (cstr_equals(params[0], "dx")) state->dx_client = b8_true;
    else state->dx_client = b8_false;

    return b8_true;
}

internal b8 set_out_path_relative(alveus_state* state, const char** params)
{
    state->run_temporary_patched_client = b8_false;
    state->out_path_relative_to_nostale_directory = b8_true;
    state->out_path = params[0];
    return b8_true;
}

internal b8 set_out_path_absolute(alveus_state* state, const char** params)
{
    state->run_temporary_patched_client = b8_false;
    state->out_path_relative_to_nostale_directory = b8_false;
    state->out_path = params[0];
    return b8_true;
}

internal b8 set_show_help(alveus_state* state, const char** params)
{
    state->show_help = b8_true;
    return b8_true;
}

internal b8 set_show_version(alveus_state* state, const char** params)
{
    state->show_version = b8_true;
    return b8_true;
}

internal b8 set_ip(alveus_state* state, const char** params)
{
    for (u32 i = 0; params[0][i]; ++i)
    {
        if (i >= 15)
        {
            println("Given IP is invalid because too long.");
            return b8_false;
        }
        state->ip[i] = params[0][i];
    }
    if (!is_ipv4_cstr_valid(cast(const char*, state->ip)))
    {
        println("Given IP is invalid.");
        return b8_false;
    }

    state->ip_set = b8_true;

    return b8_true;
}

internal b8 set_nostale_directory(alveus_state* state, const char** params)
{
    state->nostale_directory = params[0];
    return b8_true;
}

internal b8 set_run_patched_client(alveus_state* state, const char** params)
{
    state->run_patched_client = b8_true;
    return b8_true;
}

internal b8 set_run_specific_client(alveus_state* state, const char** params)
{
    state->run_specific_client = b8_true;
    state->specific_client_path = params[0];
    return b8_true;
}

internal cmd_arg cmd_args[] =
{
    {
        "/c",
        1,
        { "dx", "gl", 0 },
        "Specifies the type of client you want to patch: dx is for the DirectX client aka NostaleClientX.exe, gl is for the OpenGL client aka NostaleClient.exe. DirectX client will be chosen by default if this argument is omitted.",
        &change_client_type
    },
    {
        "/h",
        0,
        {0},
        "Shows this argument list.",
        &set_show_help
    },
    {
        "/ip",
        1,
        {0},
        "Specifies the IP by which you want to patch your client.",
        &set_ip
    },
    {
        "/nd",
        1,
        {0},
        "[NOSTALE_DIRECTORY] Specifies the working Nostale directory.",
        &set_nostale_directory
    },
    {
        "/o",
        1,
        {0},
        "[PATCHED_CLIENT_NAME] Creates a patched client in your filesystem at the specified path relative to the given Nostale directory.",
        &set_out_path_relative
    },
    {
        "/oa",
        1,
        {0},
        "[PATCHED_CLIENT_PATH] Creates a patched client in your filesystem at the specified path.",
        &set_out_path_absolute
    },
    {
        "/r",
        0,
        {0},
        "Run the patched client.",
        &set_run_patched_client
    },
    {
        "/rs",
        1,
        {0},
        "[CLIENT_PATH] Run specific client.",
        &set_run_specific_client
    },
    {
        "/v",
        0,
        {0},
        "Shows version of Alveus and other information.",
        &set_show_version
    }
};

internal b8 show_help()
{
    println_fmt("Alveus [NOSTALE_DIRECTORY] [IPv4_ADDRESS] args...\n");

    for (u32 i = 0; i < fixed_array_length_m(cmd_args); ++i)
    {
        cmd_arg* arg = &cmd_args[i];

        print_fmt("% ", arg->name);

        if (arg->valid_next_params[0])
        {
            print_fmt(" [%", arg->valid_next_params[0]);
            for (u32 i = 1; arg->valid_next_params[i]; i++)
            {
                print_fmt("|%", arg->valid_next_params[i]);
            }
            print("] ");
        }

        if (arg->help_desc) println(arg->help_desc);
        else println("");
    }

    return b8_true;
}

internal b8 show_version()
{
    return b8_true;
}

allocator* default_allocator;

int main(int ac, const char** av)
{
    heap_allocator default_heap_allocator = create_default_heap_allocator();
    default_allocator = cast(allocator*, &default_heap_allocator);

    alveus_state state = {};

    // Command line parsing.
    #define __expand(...) __VA_ARGS__
    #define cmd_error(what, ...) { println_fmt(what, __expand(__VA_ARGS__)); println("Use /h to show usage."); return 1; }
    for (u32 i = 1; i < ac; ++i)
    {
        b8 arg_valid = b8_false;
        for (u32 j = 0; j < fixed_array_length_m(cmd_args); j++)
        {
            if (cstr_equals(av[i], cmd_args[j].name))
            {
                if (i + cmd_args[j].next_params_nb >= ac)
                { 
                    cmd_error("Invalid number of params after %.", av[i]); 
                }

                if (cmd_args[j].handler(&state, &av[i + 1]) == b8_false) return 1;

                i += cmd_args[j].next_params_nb;
                arg_valid = b8_true;
                break;
            }
        }

        if (!arg_valid)
        {
            cmd_error("Unknown argument %.", av[i]);
        }
    }

    if (state.show_help)
    {
        show_help();
    }

    else if (state.show_version)
    {
        show_version();
    }

    else if (state.run_temporary_patched_client)
    {
        if (!state.ip_set)
        {
            println("Patch IP has not been set. Please use /ip.");
            return 1;
        }

        if (state.nostale_directory == nullptr)
        {
            println("Nostale directory has not been set. Please use /nd.");
            return 1;
        }

        if (!run_and_patch_client(&state))
        {
            return 1;
        }
    }

    else if (state.out_path)
    {
        if (!state.ip_set)
        {
            println("Patch IP has not been set. Please use /ip.");
            return 1;
        }

        if (state.nostale_directory == nullptr)
        {
            println("Nostale directory has not been set. Please use /nd.");
            return 1;
        }

        if (!create_patched_client(&state)) return 1;

        if (state.run_patched_client)
        {
            const char* out_path = state.out_path_relative_to_nostale_directory ? concat_file_paths(state.nostale_directory, state.out_path, default_allocator) : state.out_path;
            if (!out_path) return 1;

            if (!run_specific_client(out_path))
            {
                return 1;
            }
        }
    }

    else if (state.run_specific_client)
    {
        if (!run_specific_client(state.specific_client_path))
        {
            return 1;
        }
    }

    return 0;
}
