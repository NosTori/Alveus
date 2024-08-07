#ifndef CUTILE_FILESYSTEM_H

    // This API has optional functions using cutile_string.
    // In order to get the symbols you need to define CUTILE_FILESYSTEM_STRING_API
    // In order to compile them you need to define CUTILE_IMPLEM_FILESYSTEM_STRING_API.

    #include "cxx.h"
    #include "memory.h"

    // Defined in str.h.
    typedef struct cutile_string cutile_string;

    // file_exists*: Tells if the path given corresponds to an existing file in your filesystem.
    CUTILE_C_API b8 cutile_file_exists(const char* path); 

    // directory_exists*: Tells if the path given corresponds to an existing directory in your filesystem.
    CUTILE_C_API b8 cutile_directory_exists(const char* path);

    // This function copies a file to a new path.
    // If the new path corresponds to an existing file, overwrite parameters tells if it should be overwritten. Therefore, if the new path already correponds to an existing file and overwritten is set to false, the function returns false.
    CUTILE_C_API b8 cutile_copy_file(const char* path_of_file_to_copy, const char* path_of_new_file, b8 overwrite);

    typedef enum cutile_file_access_mode
    {
        cutile_file_access_mode_read          = 1 << 0,
        cutile_file_access_mode_write         = 1 << 1,
        cutile_file_access_mode_read_write    = cutile_file_access_mode_read | cutile_file_access_mode_write
    } cutile_file_access_mode;

    typedef enum cutile_file_create_mode
    {
        cutile_file_create_if_not_exists = 0 << 1,
        cutile_file_always_create        = 1 << 0
    } cutile_file_create_mode;

    typedef struct cutile_file
    {
        void* handle;
    } cutile_file;

    CUTILE_C_API b8   cutile_open_file(cutile_file_access_mode access_mode, const char* path, cutile_file* out);
    CUTILE_C_API b8   cutile_create_file(cutile_file_create_mode create_mode, cutile_file_access_mode access_mode, const char* path, cutile_file* out);
    CUTILE_C_API void cutile_close_file(cutile_file* file);

    CUTILE_C_API b8 cutile_get_file_content_from_path(const char* path, cutile_allocator* allocator, u8** out, u64* size_in_bytes);
    CUTILE_C_API b8 cutile_get_file_content(cutile_file* file, cutile_allocator* allocator, u8** out, u64* size_in_bytes);

    CUTILE_C_API void cutile_read_from_file(cutile_file* file, u8* out, u64 nb_bytes_to_read);

    CUTILE_C_API void cutile_write_in_file(cutile_file* file, const u8* buffer, u64 buffer_size_in_bytes);

    CUTILE_C_API u64 cutile_get_file_size(cutile_file* file);
    CUTILE_C_API b8  cutile_get_file_size_from_path(const char* path, u64* out);

    CUTILE_C_API char*         cutile_get_current_executable_path(cutile_allocator* allocator);
    CUTILE_C_API char*         cutile_get_current_executable_dir_path(cutile_allocator* allocator);

    CUTILE_C_API void  cutile_concat_file_paths_into_cstr(const char* lhs, u32 lsize, const char* rhs, u32 rsize, char* out);
    CUTILE_C_API char* cutile_concat_file_paths(const char* lhs, const char* rhs, cutile_allocator* allocator);

    // Returns a pointer to the last element of a path.
    // Elements can be separated by path separators '\' or '/'.
    CUTILE_C_API const char* cutile_get_last_path_element(const char* path);

    // Returns the extension of the filename without the '.' (e.g. "txt", "wav", ...etc).
    // Returns null if filename does not have any.
    // This function does not allocate any memory, it returns a pointer to the starting position of the extension.
    CUTILE_C_API const char* cutile_get_filename_extension(const char* file_path);

    // cutile_string API
    #ifdef CUTILE_FILESYSTEM_STRING_API
        #include "str.h"

        // On Windows and Unix allocation is performed when using those variants because their filesystem API function requires a null-terminated string (cstring):
        CUTILE_C_API b8 cutile_file_exists_str(cutile_string* path, cutile_allocator*);
        CUTILE_C_API b8 cutile_file_exists_str_(cutile_string* path); // Uses default allocation. See memory.h for more information about this.

        // On Windows and Unix allocation is performed when using those variants because their filesystem API function requires a null-terminated string (cstring):
        CUTILE_C_API b8 cutile_directory_exists_str(cutile_string* path, cutile_allocator*);
        CUTILE_C_API b8 cutile_directory_exists_str_(cutile_string* path); // Uses default allocation. See memory.h for more information about this.

        // If the function failed, string.data will be null.
        CUTILE_C_API cutile_string cutile_get_current_executable_path_str(cutile_allocator*);
        CUTILE_C_API cutile_string cutile_get_current_executable_dir_path_str(cutile_allocator*);

        CUTILE_C_API cutile_string cutile_concat_file_paths_str(const cutile_string* lhs, const cutile_string* rhs, cutile_allocator* allocator);
    #endif

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        #define file_exists(...)        cutile_file_exists(__VA_ARGS__)

        #define directory_exists(...)       cutile_directory_exists(__VA_ARGS__)

        #define copy_file(...) cutile_copy_file(__VA_ARGS__)

        typedef cutile_file_access_mode     file_access_mode;
        #define file_access_mode_read       cutile_file_access_mode_read
        #define file_access_mode_write      cutile_file_access_mode_write
        #define file_access_mode_read_write cutile_file_access_mode_read_write

        typedef cutile_file_create_mode     file_create_mode;
        #define file_create_if_not_exists   cutile_file_create_if_not_exists
        #define file_always_create          cutile_file_always_create

        typedef cutile_file file;

        #define open_file(...)   cutile_open_file(__VA_ARGS__)
        #define create_file(...) cutile_create_file(__VA_ARGS__)
        #define close_file(...)  cutile_close_file(__VA_ARGS__)

        #define get_file_content_from_path(...) cutile_get_file_content_from_path(__VA_ARGS__)
        #define get_file_content(...) cutile_get_file_content(__VA_ARGS__)

        #define read_from_file(...) cutile_read_from_file(__VA_ARGS__)
        #define write_in_file(...)  cutile_write_in_file(__VA_ARGS__)

        #define get_file_size(...)              cutile_get_file_size(__VA_ARGS__)
        #define get_file_size_from_path(...)    cutile_get_file_size_from_path(__VA_ARGS__)

        #define get_current_executable_path(...)        cutile_get_current_executable_path(__VA_ARGS__)
        #define get_current_executable_dir_path(...)    cutile_get_current_executable_dir_path(__VA_ARGS__)

        #define concat_file_paths_into_cstr(...)    cutile_concat_file_paths_into_cstr(__VA_ARGS__)
        #define concat_file_paths(...)              cutile_concat_file_paths(__VA_ARGS__)

        #define get_last_path_element(...) cutile_get_last_path_element(__VA_ARGS__)

        #define get_filename_extension(...) cutile_get_filename_extension(__VA_ARGS__)

        #ifdef CUTILE_FILESYSTEM_STRING_API
            #define file_exists_str(...)    cutile_file_exists_str(__VA_ARGS__)
            #define file_exists_str_(...)   cutile_file_exists_str_(__VA_ARGS__)
            #define directory_exists_str(...)   cutile_directory_exists_str(__VA_ARGS__)
            #define directory_exists_str_(...)  cutile_directory_exists_str_(__VA_ARGS__)

            #define get_current_executable_path_str(...) cutile_get_current_executable_path_str(__VA_ARGS__)
            #define get_current_executable_dir_path_str(...) cutile_get_current_executable_dir_path_str(__VA_ARGS__)

            #define concat_file_paths_str(...) cutile_concat_file_paths_str(__VA_ARGS__)
        #endif
    #endif

    #ifdef CUTILE_IMPLEM

        #if WINDOWS
            #include <windows.h>
        #elif UNIX_LIKE
            #include <unistd.h>
            #include <fcntl.h>
            #include <sys/stat.h>
            #include <limits.h>
            #if LINUX // PATH_MAX is defined elsewhere on Linux
                #include <linux/limits.h>
            #endif
        #endif

        b8 cutile_file_exists(const char* path)
        {
            #if WINDOWS
                DWORD dwAttrib = GetFileAttributesA(path);
                return (dwAttrib != INVALID_FILE_ATTRIBUTES);
            #elif UNIX_LIKE
                return access(path, F_OK) != -1;
            #else
                #error "Unsupported platform."
            #endif
        }

        b8 cutile_directory_exists(const char* path)
        {
            #if WINDOWS
                DWORD dwAttrib = GetFileAttributesA(path);
                return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
            #elif UNIX_LIKE
                struct stat info;
                if (stat(path, &info) == -1) return b8_false;
                if (S_ISDIR(info.st_mode)) return b8_true;
                return b8_false;
            #else
                #error "Unsupported platform."
            #endif
        }

        b8 cutile_copy_file(const char* path_of_file_to_copy, const char* path_of_new_file, b8 overwrite)
        {
            #if WINDOWS
                return CopyFile(path_of_file_to_copy, path_of_new_file, !overwrite);
            #endif
            // TODO: Implement for Unix.
            return b8_false;
        }

        #if WINDOWS
            maybe_inline UINT cutile_file_access_mode_to_win32(cutile_file_access_mode mode)
            {
                DWORD flags = 0;
                if (mode & cutile_file_access_mode_read) flags |= GENERIC_READ;
                if (mode & cutile_file_access_mode_write) flags |= GENERIC_WRITE;
                return flags;
            }

            maybe_inline DWORD cutile_file_create_mode_to_win32(cutile_file_create_mode mode)
            {
                if (mode & cutile_file_create_if_not_exists) return CREATE_NEW;
                else return CREATE_ALWAYS;
            }
        #endif

        b8 cutile_open_file(cutile_file_access_mode access_mode, const char* path, cutile_file* out)
        {
            #if WINDOWS
            {
                out->handle = (void*)CreateFileA(path, cutile_file_access_mode_to_win32(access_mode), 0, nullptr, OPEN_EXISTING, 0, nullptr);
                if (out->handle == INVALID_HANDLE_VALUE) return b8_false;
                return b8_true;
            }
            #elif UNIX_LIKE
            {
                int flags = 0;
                switch (access_mode)
                {
                    case cutile_file_access_mode_read: flags = O_RDONLY; break;
                    case cutile_file_access_mode_write: flags = O_WRONLY; break;
                    case cutile_file_access_mode_read_write: flags = O_RDWR; break;
                }
                s64 fd = open(path, flags);
                out->handle = (void*)fd;
                return fd != -1 ? b8_true : b8_false;
            }
            #else
                #error "Unsupported platform."
            #endif
        }

        b8 cutile_create_file(cutile_file_create_mode create_mode, cutile_file_access_mode access_mode, const char* path, cutile_file* out)
        {
            #if WINDOWS
            {
                out->handle = (void*)CreateFileA(path, cutile_file_access_mode_to_win32(access_mode), 0, nullptr, cutile_file_create_mode_to_win32(create_mode), 0, nullptr);
            
                if (out->handle == INVALID_HANDLE_VALUE) return b8_false;
                return b8_true;
            }
            #elif UNIX_LIKE
            {
                int flags = 0;
                switch (access_mode)
                {
                    case cutile_file_access_mode_read: flags = O_RDONLY; break;
                    case cutile_file_access_mode_write: flags = O_WRONLY; break;
                    case cutile_file_access_mode_read_write: flags = O_RDWR; break;
                }
                s64 fd = open(path, flags | O_CREAT);
                if (fd == -1) return b8_false;
                out->handle = (void*)fd;
                return b8_true;
            }
            #else
                #error "Unsupported platform."
            #endif
        }

        void cutile_close_file(cutile_file* file)
        {
            #if WINDOWS
                CloseHandle(file->handle);
            #elif UNIX_LIKE
                close((u64)file->handle);
            #else
                #error "Unsupported platform."
            #endif
        }

        void cutile_write_in_file(cutile_file* file, const u8* buffer, u64 buffer_size_in_bytes)
        {
            #if WINDOWS
                DWORD written = 0;
                WriteFile(file->handle, buffer, buffer_size_in_bytes, &written, nullptr);
            #elif UNIX_LIKE
                write((u64)file->handle, buffer, buffer_size_in_bytes);
            #else
                #error "Unsupported platform."
            #endif
        }
    
        u64 cutile_get_file_size(cutile_file* file)
        {
            u64 result;
            #if WINDOWS
            {
                GetFileSizeEx((HANDLE)file->handle, (PLARGE_INTEGER)&result);
                return result;
            }
            #elif UNIX_LIKE
            {
                off_t curr_pos = lseek((u64)file->handle, 0, SEEK_CUR);
                off_t end_pos = lseek((u64)file->handle, 0, SEEK_END);
                lseek((u64)file->handle, curr_pos, SEEK_SET);
                result = (u64)end_pos;
                return result;
            }
            #else
                #error "Unsupported platform."
            #endif
        }

        b8 get_file_size_from_path(const char* path, u64* out)
        {
            cutile_file f;
            b8 file_opened = cutile_open_file(cutile_file_access_mode_read, path, &f);
            if (!file_opened) return b8_false;
            *out = cutile_get_file_size(&f);
            cutile_close_file(&f);
            return b8_true;
        }

        void cutile_read_from_file(cutile_file* file, u8* out, u64 nb_bytes_to_read)
        {
            #if WINDOWS
                DWORD total_read = 0;
                do
                {
                    DWORD read = 0;
                    if (!ReadFile(file->handle, out + total_read, nb_bytes_to_read - total_read, &read, nullptr)) break;
                    total_read += read;
                } while (total_read < nb_bytes_to_read);
            #elif UNIX_LIKE
                u64 total_read = 0;
                do
                {
                    ssize_t rd = read((u64)file->handle, out + total_read, nb_bytes_to_read - total_read);
                    if (rd == -1) break;
                    total_read += rd;
                } while (total_read < nb_bytes_to_read);
            #else
                #error "read_from_file: Unsupported platform"
            #endif
        }

        b8 cutile_get_file_content_from_path(const char* path, cutile_allocator* allocator, u8** out, u64* size_in_bytes)
        {
            cutile_file file;
            b8 file_opened = cutile_open_file(cutile_file_access_mode_read, path, &file);
            if (!file_opened) return b8_false;
            cutile_get_file_content(&file, allocator, out, size_in_bytes);
            cutile_close_file(&file);
            return b8_true;
        }

        b8 cutile_get_file_content(cutile_file* file, cutile_allocator* allocator, u8** out, u64* size_in_bytes)
        {
            *size_in_bytes = cutile_get_file_size(file);
            *out = (u8*)cutile_allocate_m(allocator, *size_in_bytes);
            cutile_read_from_file(file, *out, *size_in_bytes);
            return b8_true;
        }

        char* cutile_get_current_executable_path(cutile_allocator* allocator)
        {
            #if WINDOWS
                char tmp[MAX_PATH];
                DWORD path_len = GetModuleFileNameA(NULL, tmp, MAX_PATH);
                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER || !path_len) return nullptr;
            #elif UNIX_LIKE
                char tmp[PATH_MAX];
                char cwd[PATH_MAX];
                if (getcwd(cwd, sizeof(cwd)) == nullptr) return nullptr;
                u32 path_len = readlink("/proc/self/exe", tmp, sizeof(tmp));
                if (path_len == -1) return nullptr;
            #else
                #error "Unsupported platform"
            #endif
            char* result = (char*)cutile_allocate_m(allocator, sizeof(char) * path_len + 1);
            cutile_copy_memory_m(result, tmp, path_len);
            result[path_len] = '\0';
            return result;
        }

        char* cutile_get_current_executable_dir_path(cutile_allocator* allocator)
        {
            char* exe_path = cutile_get_current_executable_path(allocator);
            u32 last_sep_index = 0;
            for (u32 i = 0; exe_path[i]; ++i)
            {
                #if WINDOWS
                    if (exe_path[i] == '\\' || exe_path[i] == '/') last_sep_index = i;
                #else
                    if (exe_path[i] == '/') last_sep_index = i;
                #endif
            }
            char* exe_dir = (char*)cutile_allocate_m(allocator, last_sep_index + 1);
            cutile_copy_memory_m(exe_dir, exe_path, last_sep_index);
            exe_dir[last_sep_index] = '\0';
            cutile_deallocate_m(allocator, exe_path);
            return exe_dir;
        }
    
        void cutile_concat_file_paths_into_cstr(const char* lhs, u32 lsize, const char* rhs, u32 rsize, char* out)
        {
            cutile_copy_memory_m(out, lhs, lsize);
            #if WINDOWS
                out[lsize] = '\\';
            #elif UNIX_LIKE
                out[lsize] = '/';
            #else
                #error "concat_file_paths_into_cstr: Unsupported platforn."
            #endif
            copy_memory_m(out + lsize + 1, rhs, rsize);
            out[lsize + rsize + 1] = '\0';
        }

        char* cutile_concat_file_paths(const char* lhs, const char* rhs, cutile_allocator* allocator)
        {
            u32 lsize = 0; while (lhs[lsize]) lsize++;
            u32 rsize = 0; while (rhs[rsize]) rsize++;
            char* result = (char*)cutile_allocate_m(allocator, sizeof(char) * (lsize + rsize + 2));
            cutile_concat_file_paths_into_cstr(lhs, lsize, rhs, rsize, result);
            return result;
        }

        const char* cutile_get_last_path_element(const char* path)
        {
            const char* saved = path;
            while (*path)
            {
                #if WINDOWS
                    if (*path == '\\' || *path == '/') saved = path;
                #elif UNIX_LIKE
                    if (*path == '/') saved = path;
                #endif
                ++path;
            }
            return saved;
        }

       const char* cutile_get_filename_extension(const char* file_path)
       {
           const char* last_path_element = cutile_get_last_path_element(file_path);
           const char* saved = nullptr;
           while (*last_path_element)
           {
               if (*last_path_element == '.' && *(last_path_element + 1)) saved = last_path_element + 1;
               ++last_path_element;
           }
           return saved;
       }

    #endif // CUTILE_IMPLEM

    #ifdef CUTILE_IMPLEM_FILESYSTEM_STRING_API
        #include "str.h"

        b8 cutile_file_exists_str(cutile_string* path, cutile_allocator* allocator)
        {
            char* cpath = cutile_create_cstr_from_str(path, allocator);
            b8 res = cutile_file_exists(cpath);
            cutile_deallocate_m(allocator, cpath);
            return res;
        }

        b8 cutile_file_exists_str_(cutile_string* path)
        {
            char* cpath = (char*)cutile_default_allocate(path->count + 1);
            cutile_copy_memory_m(cpath, path->data, path->count);
            cpath[path->count] = '\0';
            b8 res = cutile_file_exists(cpath);
            cutile_default_deallocate(cpath);
            return res;
        }

        b8 cutile_directory_exists_str(cutile_string* path, cutile_allocator* allocator)
        {
            char* cpath = cutile_create_cstr_from_str(path, allocator);
            b8 res = cutile_directory_exists(cpath);
            cutile_deallocate_m(path->allocator, cpath);
            return res;
        }

        b8 cutile_directory_exists_str_(cutile_string* path)
        {
            char* cpath = (char*)cutile_default_allocate(path->count + 1);
            cutile_copy_memory_m(cpath, path->data, path->count);
            cpath[path->count] = '\0';
            b8 res = cutile_directory_exists(cpath);
            cutile_default_deallocate(cpath);
            return res;
        }

        cutile_string cutile_concat_file_paths_str(const cutile_string* lhs, const cutile_string* rhs, cutile_allocator* allocator)
        {
            string s = cutile_create_sized_empty_str(lhs->count + rhs->count + 1, allocator);
            cutile_str_push_back_str(&s, lhs);
            #if WINDOWS
                cutile_str_push_back(&s, '\\');
            #elif UNIX_LIKE
                cutile_str_push_back(&s, '/');
            #else
                #error "concat_file_paths_str: Unsupported platforn."
            #endif
            cutile_str_push_back_str(&s, rhs);
            return s;
        }

        cutile_string cutile_get_current_executable_path_str(cutile_allocator* allocator)
        {
            cutile_string result = {0};
            #if WINDOWS
                char tmp[MAX_PATH];
                DWORD path_len = GetModuleFileNameA(NULL, tmp, MAX_PATH);
                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER || !path_len) return result;
            #elif UNIX_LIKE
                char tmp[PATH_MAX];
                char cwd[PATH_MAX];
                if (getcwd(cwd, sizeof(cwd)) == nullptr) return result;
                u32 path_len = readlink("/proc/self/exe", tmp, sizeof(tmp));
                if (path_len == -1) return result;
            #else
                #error "Unsupported platform"
            #endif
            result = cutile_create_str_from_buf((u8*)tmp, path_len, allocator);
            return result;

        }

        cutile_string cutile_get_current_executable_dir_path_str(cutile_allocator* allocator)
        {
            cutile_string res = cutile_get_current_executable_path_str(allocator);
            while (res.count)
            {
                #if WINDOWS
                    if (res.data[res.count - 1] == '\\' || res.data[res.count - 1] == '/') break;
                #else
                    if (res.data[res.count - 1] == '/') break;
                #endif
                cutile_str_pop_back(&res);
            }
            return res;
        }

    #endif // CUTILE_IMPLEM_FILESYSTEM_STRING_API

    #define CUTILE_FILESYSTEM_H
#endif
