#ifndef CUTILE_INI_H

    #include "array.h"

    typedef struct cutile_ini_field
    {
        const u8* name_start;       // Where the name starts.
        const u8* name_end;         // Where the name ends.
        const u8* val_start;        // Where the value starts.
        const u8* val_end;          // Where the value ends.
    } cutile_ini_field;

    cutile_generate_array_m(cutile_ini_field);

    typedef struct ini_section
    {
        const u8* decl_start;       // [
        const u8* decl_end;         // ]
        const u8* name;             // Name of the section.
        u64       name_size;        // Size in bytes of the section name.
        const u8* content_start;    // After section declaration.
        const u8* content_end;      // One byte before next section declaration or end of file.

        cutile_ini_field_array fields;
    } cutile_ini_section;

    cutile_generate_array_m(cutile_ini_section);

    typedef struct cutile_ini_error
    {
        const char* msg;            // Null if there is no error.
        const char* filename;       // Null if parse directly from memory and not from filesystem.
        u32         line;           // Line where the error occurred if it comes from the ini data.
    } cutile_ini_error;

    typedef struct
    {
        cutile_ini_error         error;
        cutile_ini_section       global_section;
        cutile_ini_section_array sections;
    } cutile_parse_ini_result;
    CUTILE_C_API cutile_parse_ini_result cutile_parse_ini(const u8* data, u64 data_size, cutile_allocator* allocator);
    CUTILE_C_API void                    cutile_destroy_ini_parsed_data(cutile_parse_ini_result* parsed_data);

    typedef struct
    {
        b8        found;
        const u8* value_start;
        u64       value_size;
    } cutile_ini_entry_value_result;
    CUTILE_C_API cutile_ini_entry_value_result cutile_get_ini_global_entry_value(const char* entry_name, const cutile_parse_ini_result* parsed_data);
    CUTILE_C_API cutile_ini_entry_value_result cutile_get_ini_entry_value(const char* section_name, const char* entry_name, const cutile_parse_ini_result* parsed_data);

    // Fast ini api.
    CUTILE_C_API b8 cutile_get_ini_field(u8* ini_data,
                                         u64 ini_size,
                                         const char* section_name, // NULL if no section (global section).
                                         const char* entry_name,
                                         cutile_ini_field* out);

    #ifndef NO_CUTILE_SHORT_INTERFACE_NAMES
        typedef cutile_ini_field   ini_field;
        typedef cutile_ini_section ini_section;
        typedef cutile_ini_error   ini_error;

        typedef cutile_parse_ini_result      parse_ini_result;
        #define parse_ini(...)               cutile_parse_ini(__VA_ARGS__)
        #define destroy_ini_parsed_data(...) cutile_destroy_ini_parsed_data(__VA_ARGS__)


        typedef cutile_ini_entry_value_result   ini_entry_value_result;
        #define get_ini_global_entry_value(...) cutile_get_ini_global_entry_value(__VA_ARGS__)
        #define get_ini_entry_value(...)        cutile_get_ini_entry_value(__VA_ARGS__)

        #define get_ini_field(...) cutile_get_ini_field(__VA_ARGS__)
    #endif

    #ifdef CUTILE_IMPLEM
        #include "memory.h"
    
        typedef struct cutile_ini_parser_state
        {
            const u8* data;
            u64 data_size;
            u64 index;
            u64 line;
        } cutile_ini_parser_state;
    
        typedef enum cutile_ini_parser_token_kind
        {
            cutile_ini_parser_token_kind_separator,
            cutile_ini_parser_token_kind_op, // operator
            cutile_ini_parser_token_kind_name_or_value,
            cutile_ini_parser_token_kind_end,
            cutile_ini_parser_token_kind_unknown
        } cutile_ini_parser_token_kind;
    
        typedef struct cutile_ini_parser_token
        {
            cutile_ini_parser_token_kind kind;
            const u8* start;
            const u8* end;
            u64 line;
        } cutile_ini_parser_token;
    
        internal cutile_ini_parser_token cutile_get_next_ini_parser_token(cutile_ini_parser_state* state)
        {
            cutile_ini_parser_token tok;
            u8 ch;
    
            // Extracts characters until one is relevant.
            do
            {
                if (state->index >= state->data_size) goto end_of_data;
    
                ch = state->data[state->index];
                
                if (ch == ' ' || ch == '\t' || ch == '\r')
                {
                    ++state->index;
                    continue;
                }
                else if (ch == '\n')
                {
                    ++state->index;
                    ++state->line;
                }
                else break;
            } while (1);
            
            // Comment
            if (ch == ';')
            {
                do
                {
                    if (state->index >= state->data_size) goto end_of_data;
    
                    ch = state->data[state->index++];
    
                    if (ch == '\n') // End of comment.
                    {
                        ++state->line;
                        return cutile_get_next_ini_parser_token(state);
                    }
                } while (1);
            }
    
            tok.line = state->line;
    
            // Section separators.
            if (ch == '[' || ch == ']')
            {
                tok.kind = cutile_ini_parser_token_kind_separator;
                tok.start = state->data + state->index;
                tok.end = tok.start;
                ++state->index;
            }
    
            // Assignment operator.
            else if (ch == '=')
            {
                tok.kind = cutile_ini_parser_token_kind_op;
                tok.start = state->data + state->index;
                tok.end = tok.start;
                ++state->index;
            }
    
            // Section name or entry name or entry value.
            else if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))
            {
                tok.kind = cutile_ini_parser_token_kind_name_or_value;
                tok.start = state->data + state->index;
                tok.end = tok.start;
                ++state->index;
                while (state->index < state->data_size)
                {
                    ch = state->data[state->index];
    
                    // Allowed characters:
                    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch == '_'))
                    {
                        ++tok.end;
                        ++state->index;
                    }
    
                    else break;
                }
            }
    
            // Number value.
            else if (ch >= '0' && ch <= '9')
            {
                tok.kind = cutile_ini_parser_token_kind_name_or_value;
                tok.start = state->data + state->index;
                tok.end = tok.start;
                ++state->index;
                while (state->index < state->data_size)
                {
                    ch = state->data[state->index];
                    if (ch >= '0' && ch <= '9')
                    {
                        ++tok.end;
                        ++state->index;
                    }
                    else break;
                };
            }
    
            // Null terminator (C-strings)
            else if (ch == 0) goto end_of_data;
            
            // Unknown token... Something is wrong!
            else tok.kind = cutile_ini_parser_token_kind_unknown;
            
            return tok;
    
        end_of_data:
            tok.kind = cutile_ini_parser_token_kind_end;
            tok.line = state->line;
            return tok;
        }
    
        internal void cutile_parse_ini_entry(cutile_ini_parser_token* name, cutile_ini_parser_state* state, cutile_ini_section* section, cutile_parse_ini_result* result)
        {
            cutile_ini_parser_token assignment_op_tok = cutile_get_next_ini_parser_token(state);
            if (assignment_op_tok.kind != cutile_ini_parser_token_kind_op)
            {
                result->error.msg = "Assignment operator expected after entry declaration.";
                result->error.line = state->line;
                return;
            }
    
            cutile_ini_parser_token value_tok = cutile_get_next_ini_parser_token(state);
            if (value_tok.kind != cutile_ini_parser_token_kind_name_or_value)
            {
                result->error.msg = "Value expected after assignment operation.";
                result->error.line = state->line;
                return;
            }
    
            cutile_ini_field field;
            field.name_start = name->start;
            field.name_end = name->end;
            field.val_start = value_tok.start;
            field.val_end = value_tok.end;
            
            cutile_cutile_ini_field_array_push(&section->fields, field);
        }
    
        internal void cutile_parse_ini_section(cutile_ini_parser_token* tok, cutile_ini_parser_state* state, cutile_parse_ini_result* result)
        {
            if (*tok->start == ']')
            {
                result->error.msg = "Section declaration should start with '[' but it was ']'.";
                result->error.line = state->line;
                return;
            }
    
            cutile_ini_parser_token section_name_tok = cutile_get_next_ini_parser_token(state);
            if (section_name_tok.kind != cutile_ini_parser_token_kind_name_or_value)
            {
                result->error.msg = "A name for the section was expected.";
                result->error.line = state->line;
                return;
            }
    
            cutile_ini_parser_token section_end_sep_tok = cutile_get_next_ini_parser_token(state);
            if (section_end_sep_tok.kind != cutile_ini_parser_token_kind_separator)
            {
                result->error.msg = "Separator expected at the end of section declaration.";
                result->error.line = state->line;
                return;
            }
            if (*section_end_sep_tok.start == '[')
            {
                result->error.msg = "Section declaration should end with ']' but it was '['.";
                result->error.line = state->line;
                return;
            }
    
            cutile_ini_section section;
            section.decl_start = tok->start;
            section.decl_end = section_end_sep_tok.start;
            section.name = section_name_tok.start;
            section.name_size = section_name_tok.end - section.name + 1;
            section.fields = cutile_create_cutile_ini_field_array(5, 5, result->sections.allocator);
    
            int loop = 1;
            while (loop)
            {
                // An error occurred, just leave the loop to stop processing the ini file.
                // TODO: Handle multi errors maybe instead of exiting at the first error in the data ?
                if (result->error.msg != nullptr) break;
    
                cutile_ini_parser_token next_tok = cutile_get_next_ini_parser_token(state);

                switch (next_tok.kind)
                {
                case cutile_ini_parser_token_kind_name_or_value:
                    if (section.fields.count == 0) section.content_start = next_tok.start; // Represents begin of content if this is the first field.
                    cutile_parse_ini_entry(&next_tok, state, &section, result);
                    break;

                // '[' has been encountered, let's finish with this section and parse a new one.
                case cutile_ini_parser_token_kind_separator:
                    if (section.fields.count == 0) section.content_start = next_tok.start - 1; // Begin of content equals end of content if there is no field.
                    section.content_end = next_tok.start - 1;
                    cutile_parse_ini_section(&next_tok, state, result);
                    loop = 0;
                    break;

                case cutile_ini_parser_token_kind_end:
                    section.content_end = state->data + state->data_size - 1;
                    if (section.fields.count == 0) section.content_start = section.content_end; // Begin of content equals end of content if there is no field.
                    loop = 0;
                    break;

                default:
                    result->error.msg = "Encounter an unknown token!";
                    result->error.line = state->line;
                    break;
                }
            }
            cutile_cutile_ini_section_array_push(&result->sections, section);
        }
    
        internal void cutile_parse_ini_global_section(cutile_ini_parser_state* state, cutile_parse_ini_result* result)
        {
            result->global_section.decl_start = nullptr;
            result->global_section.decl_end = nullptr;
            result->global_section.content_start = state->data;
            result->global_section.content_end = state->data;
            result->global_section.name = nullptr;
            result->global_section.name_size = 0;
            result->global_section.fields = cutile_create_cutile_ini_field_array(5, 5, result->sections.allocator);
            
            int loop = 1;
            while (loop)
            {
                // An error occurred, just leave the loop to stop processing the ini file.
                // TODO: Handle multi errors maybe instead of exiting at the first error in the data ?
                if (result->error.msg != nullptr) break;
                
                cutile_ini_parser_token tok = cutile_get_next_ini_parser_token(state);
    
                switch (tok.kind)
                {
    
                // '[' has been encountered, let's finish with this section and parse a new one.
                // New section. No more in global section.
                case cutile_ini_parser_token_kind_separator:
                    result->global_section.content_end = tok.start - 1;
                    cutile_parse_ini_section(&tok, state, result);
                    return;
    
                case cutile_ini_parser_token_kind_name_or_value:
                    cutile_parse_ini_entry(&tok, state, &result->global_section, result);
                    break;
    
                case cutile_ini_parser_token_kind_end:
                    result->global_section.content_end = state->data + state->data_size - 1;
                    loop = 0;
                    break;
    
                default:
                    result->error.msg = "Encounter an unknown token!";
                    result->error.line = state->line;
                    break;
                }
            }
        }
    
        // TODO: What happens if allocation fails ??????
        cutile_parse_ini_result cutile_parse_ini(const u8* data, u64 data_size, allocator* allocator)
        {
            cutile_parse_ini_result result;
            result.error.msg = nullptr;
            result.sections = cutile_create_cutile_ini_section_array(5, 5, allocator);
    
            cutile_ini_parser_state state;
            state.data = data;
            state.data_size = data_size;
            state.index = 0;
            state.line = 1;
            
            cutile_parse_ini_global_section(&state, &result);
            return result;
        }
    
        #include "str.h"
    
        internal cutile_ini_entry_value_result cutile_get_ini_section_entry_value(const cutile_ini_section* section, const char* entry_name)
        {
            cutile_ini_entry_value_result result;
            result.found = b8_false;
            u32 entry_name_len = 0; while(entry_name[entry_name_len]) entry_name_len++;
            for (u32 i = 0; i < section->fields.count; ++i)
            {
                const cutile_ini_field* field = &section->fields.data[i];

                if (field->name_end - field->name_start + 1 != entry_name_len) continue;
                if (!cutile_memory_equals((const u8*)entry_name, field->name_start, entry_name_len)) continue;

                // FOUND!
                result.found = b8_true;
                result.value_start = field->val_start;
                result.value_size = field->val_end - field->val_start + 1;
                break;
            }
            return result;
        }
    
        cutile_ini_entry_value_result cutile_get_ini_global_entry_value(const char* entry_name, const cutile_parse_ini_result* parsed_data)
        {
            return cutile_get_ini_section_entry_value(&parsed_data->global_section, entry_name);
        }
    
        cutile_ini_entry_value_result cutile_get_ini_entry_value(const char* section_name, const char* entry_name, const cutile_parse_ini_result* parsed_data)
        {
            u32 section_name_len = 0; while(section_name[section_name_len]) section_name_len++;
            for (u32 i = 0; i < parsed_data->sections.count; ++i)
            {
                const cutile_ini_section* section = &parsed_data->sections.data[i];
    
                if (section->name_size != section_name_len) continue;
                if (!cutile_memory_equals((const u8*)section_name, section->name, section_name_len)) continue;
    
                // SECTION FOUND!
                return cutile_get_ini_section_entry_value(section, entry_name);
            }
            cutile_ini_entry_value_result result;
            result.found = b8_false;
            return result;
        }
    
        void cutile_destroy_ini_parsed_data(cutile_parse_ini_result* parsed_data)
        {
            cutile_destroy_cutile_ini_field_array(&parsed_data->global_section.fields);
            for (u32 i = 0; i < parsed_data->sections.count; ++i)
            {
                cutile_destroy_cutile_ini_field_array(&parsed_data->sections.data[i].fields);
            }
            cutile_destroy_cutile_ini_section_array(&parsed_data->sections);
        }
    
        b8 cutile_get_ini_field(u8* ini_data,
                                u64 ini_size,
                                const char* section_name, // NULL if no section (global section).
                                const char* entry_name,
                                cutile_ini_field* out)
        {
            cutile_ini_parser_state state =
            {
                ini_data, ini_size, 0, 1
            };
    
            cutile_ini_parser_token tok;
            if (section_name != nullptr)
            {
                u32 section_name_length = 0; while(section_name[section_name_length]) section_name_length++;
                
                while (b8_true)
                {
                    tok = cutile_get_next_ini_parser_token(&state);
                    if (tok.kind == cutile_ini_parser_token_kind_end ||
                        tok.kind == cutile_ini_parser_token_kind_unknown)
                    {
                        return b8_false;
                    }
                    if (*tok.start == '[')
                    {
                        tok = cutile_get_next_ini_parser_token(&state);
                        if (tok.kind == cutile_ini_parser_token_kind_name_or_value)
                        {
                            // Section name length is different than the given one so this is not the good section.
                            if (section_name_length != tok.end - tok.start + 1)
                            {
                                continue;
                            }
    
                            if (cutile_memory_equals((const u8*)section_name, tok.start, section_name_length))
                            {
                                break;
                            }
                        }
                    }
                }
            }
    
            u32 entry_name_length = 0; while(entry_name[entry_name_length]) entry_name_length;
            while (b8_true)
            {
                tok = cutile_get_next_ini_parser_token(&state);
                if (tok.kind == cutile_ini_parser_token_kind_end ||
                    tok.kind == cutile_ini_parser_token_kind_unknown)
                {
                    return b8_false;
                }
                if (tok.kind == cutile_ini_parser_token_kind_name_or_value)
                {
                    // Entry name size does not match so we already know it's not the good one. 
                    if (entry_name_length != tok.end - tok.start + 1)
                    {
                        continue;
                    }
    
                    if (cutile_memory_equals((const u8*)entry_name, tok.start, entry_name_length))
                    {
                        out->name_start = tok.start;
                        out->name_end = tok.end;
                        tok = cutile_get_next_ini_parser_token(&state);
                        if (tok.kind == cutile_ini_parser_token_kind_op && *tok.start == '=')
                        {
                            tok = cutile_get_next_ini_parser_token(&state);
                            if (tok.kind == cutile_ini_parser_token_kind_name_or_value)
                            {
                                out->val_start = tok.start;
                                out->val_end = tok.end;
                                return b8_true;
                            }
                        }
                    }
                }
                if (section_name &&
                    tok.kind == cutile_ini_parser_token_kind_separator &&
                    *tok.start == '[')
                {
                    return b8_false;
                }
            }
    
            return b8_false;
        }
    #endif // CUTILE_IMPLEM

    #define CUTILE_INI_H
#endif 
