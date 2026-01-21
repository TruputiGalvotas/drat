#include <stdio.h>
#include <sys/errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <sysexits.h>
#include <argp.h>

#include <apfs/object.h>
#include <apfs/nx.h>
#include <apfs/omap.h>
#include <apfs/fs.h>
#include <apfs/j.h>
#include <apfs/dstream.h>
#include <apfs/sibling.h>
#include <apfs/snap.h>

#include <drat/argp.h>
#include <drat/globals.h>
#include <drat/io.h>

#include <drat/func/boolean.h>
#include <drat/func/cksum.h>
#include <drat/func/btree.h>

#include <drat/string/object.h>
#include <drat/string/nx.h>
#include <drat/string/omap.h>
#include <drat/string/btree.h>
#include <drat/string/fs.h>
#include <drat/string/j.h>

typedef struct {
    uint64_t start;
    uint64_t end;
} oid_range_t;

typedef struct {
    int64_t start_addr;
    int64_t end_addr;
    bool require_cksum;
    bool list_all;
    bool scan_omap;
    bool scan_virtual;
    char* export_path;
    FILE* export_stream;
    size_t num_dentry_names;
    char** dentry_names;
    size_t num_dentry_oids;
    uint64_t* dentry_oids;
    size_t num_dentry_oid_ranges;
    oid_range_t* dentry_oid_ranges;
    size_t num_virtual_oids;
    uint64_t* virtual_oids;
    size_t num_omap_oid_ranges;
    oid_range_t* omap_oid_ranges;
} options_t;

#define DRAT_ARG_KEY_START              (DRAT_GLOBAL_ARGS_LAST_KEY - 1)
#define DRAT_ARG_KEY_END                (DRAT_GLOBAL_ARGS_LAST_KEY - 2)
#define DRAT_ARG_KEY_DENTRY_NAME        (DRAT_GLOBAL_ARGS_LAST_KEY - 3)
#define DRAT_ARG_KEY_DENTRY_OID         (DRAT_GLOBAL_ARGS_LAST_KEY - 4)
#define DRAT_ARG_KEY_DENTRY_OID_RANGE   (DRAT_GLOBAL_ARGS_LAST_KEY - 5)
#define DRAT_ARG_KEY_SCAN_OMAP          (DRAT_GLOBAL_ARGS_LAST_KEY - 6)
#define DRAT_ARG_KEY_SCAN_VIRTUAL       (DRAT_GLOBAL_ARGS_LAST_KEY - 7)
#define DRAT_ARG_KEY_NO_CKSUM           (DRAT_GLOBAL_ARGS_LAST_KEY - 8)
#define DRAT_ARG_KEY_VIRTUAL_OID        (DRAT_GLOBAL_ARGS_LAST_KEY - 9)
#define DRAT_ARG_KEY_OMAP_OID_RANGE     (DRAT_GLOBAL_ARGS_LAST_KEY - 10)
#define DRAT_ARG_KEY_MATCHES_ONLY       (DRAT_GLOBAL_ARGS_LAST_KEY - 11)
#define DRAT_ARG_KEY_EXPORT             (DRAT_GLOBAL_ARGS_LAST_KEY - 12)

#define DRAT_ARG_ERR_INVALID_START              (DRAT_GLOBAL_ARGS_LAST_ERR - 1)
#define DRAT_ARG_ERR_INVALID_END                (DRAT_GLOBAL_ARGS_LAST_ERR - 2)
#define DRAT_ARG_ERR_INVALID_DENTRY_NAME        (DRAT_GLOBAL_ARGS_LAST_ERR - 3)
#define DRAT_ARG_ERR_INVALID_DENTRY_OID         (DRAT_GLOBAL_ARGS_LAST_ERR - 4)
#define DRAT_ARG_ERR_INVALID_DENTRY_OID_RANGE   (DRAT_GLOBAL_ARGS_LAST_ERR - 5)
#define DRAT_ARG_ERR_INVALID_VIRTUAL_OID        (DRAT_GLOBAL_ARGS_LAST_ERR - 6)
#define DRAT_ARG_ERR_INVALID_OMAP_OID_RANGE     (DRAT_GLOBAL_ARGS_LAST_ERR - 7)
#define DRAT_ARG_ERR_OUT_OF_MEMORY              (DRAT_GLOBAL_ARGS_LAST_ERR - 8)
#define DRAT_ARG_ERR_INVALID_EXPORT             (DRAT_GLOBAL_ARGS_LAST_ERR - 9)

static const struct argp_option argp_options[] = {
    // char* name,       int key,                    char* arg,            int flags,   char* doc
    { "start",           DRAT_ARG_KEY_START,          "block addr",         0,           "Start block address (inclusive)" },
    { "end",             DRAT_ARG_KEY_END,            "block addr",         0,           "End block address (exclusive)" },
    { "dentry-name",     DRAT_ARG_KEY_DENTRY_NAME,    "name[,name...]",     0,           "Dentry name(s) to match" },
    { "dentry-oid",      DRAT_ARG_KEY_DENTRY_OID,     "oid[,oid...]",       0,           "Dentry file-id(s) to match" },
    { "dentry-oid-range",DRAT_ARG_KEY_DENTRY_OID_RANGE,"start-end",         0,           "Dentry file-id range to match" },
    { "virtual-oid",     DRAT_ARG_KEY_VIRTUAL_OID,    "oid[,oid...]",       0,           "Virtual OID(s) to match" },
    { "omap-oid-range",  DRAT_ARG_KEY_OMAP_OID_RANGE, "start-end",          0,           "Omap OID range to match" },
    { "scan-omap",       DRAT_ARG_KEY_SCAN_OMAP,      0,                    0,           "Scan omap B-tree leaf nodes" },
    { "scan-virtual",    DRAT_ARG_KEY_SCAN_VIRTUAL,   0,                    0,           "Scan virtual objects" },
    { "no-cksum",        DRAT_ARG_KEY_NO_CKSUM,       0,                    0,           "Do not require checksum validation" },
    { "matches-only",    DRAT_ARG_KEY_MATCHES_ONLY,  0,                    0,           "Only print matches (suppress full listing)" },
    { "export",          DRAT_ARG_KEY_EXPORT,         "path",               0,           "Write CSV results to the specified path" },
    {0}
};

static char* dup_string(const char* value) {
    size_t len = strlen(value) + 1;
    char* copy = malloc(len);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, value, len);
    return copy;
}

static bool add_string(char*** list, size_t* count, const char* value) {
    char* copy = dup_string(value);
    if (!copy) {
        return false;
    }
    char** updated = realloc(*list, (*count + 1) * sizeof(**list));
    if (!updated) {
        free(copy);
        return false;
    }
    updated[*count] = copy;
    *list = updated;
    (*count)++;
    return true;
}

static bool add_uint64(uint64_t** list, size_t* count, uint64_t value) {
    uint64_t* updated = realloc(*list, (*count + 1) * sizeof(**list));
    if (!updated) {
        return false;
    }
    updated[*count] = value;
    *list = updated;
    (*count)++;
    return true;
}

static bool add_range(oid_range_t** list, size_t* count, uint64_t start, uint64_t end) {
    oid_range_t* updated = realloc(*list, (*count + 1) * sizeof(**list));
    if (!updated) {
        return false;
    }
    updated[*count].start = start;
    updated[*count].end = end;
    *list = updated;
    (*count)++;
    return true;
}

static bool parse_range(const char* arg, uint64_t* start, uint64_t* end) {
    char* copy = dup_string(arg);
    if (!copy) {
        return false;
    }
    char* sep = strpbrk(copy, ":-");
    if (!sep) {
        free(copy);
        return false;
    }
    *sep = '\0';
    int64_t parsed_start = -1;
    int64_t parsed_end = -1;
    bool ok = parse_number(&parsed_start, copy) && parse_number(&parsed_end, sep + 1);
    if (!ok || parsed_start < 0 || parsed_end < 0 || parsed_start > parsed_end) {
        free(copy);
        return false;
    }
    *start = (uint64_t)parsed_start;
    *end = (uint64_t)parsed_end;
    free(copy);
    return true;
}

static error_t parse_name_list(options_t* options, char* arg) {
    char* option = arg;
    char* const tokens[] = {0};
    char* value = NULL;

    while (*option) {
        switch (getsubopt_posix(&option, tokens, &value)) {
            case -1:
                if (!value || !*value) {
                    return DRAT_ARG_ERR_INVALID_DENTRY_NAME;
                }
                if (!add_string(&options->dentry_names, &options->num_dentry_names, value)) {
                    return DRAT_ARG_ERR_OUT_OF_MEMORY;
                }
                break;
            default:
                assert(false);
                return DRAT_ARG_ERR_INVALID_DENTRY_NAME;
        }
    }
    return 0;
}

static error_t parse_oid_list(uint64_t** list, size_t* count, char* arg, int invalid_err) {
    char* option = arg;
    char* const tokens[] = {0};
    char* value = NULL;

    while (*option) {
        switch (getsubopt_posix(&option, tokens, &value)) {
            case -1: {
                int64_t oid = -1;
                if (!value || !parse_number(&oid, value) || oid < 0) {
                    return invalid_err;
                }
                if (!add_uint64(list, count, (uint64_t)oid)) {
                    return DRAT_ARG_ERR_OUT_OF_MEMORY;
                }
                break;
            }
            default:
                assert(false);
                return invalid_err;
        }
    }
    return 0;
}

static error_t argp_parser(int key, char* arg, struct argp_state* state) {
    options_t* options = state->input;

    switch (key) {
        case DRAT_ARG_KEY_START: {
            int64_t parsed = -1;
            if (!parse_number(&parsed, arg) || parsed < 0) {
                return DRAT_ARG_ERR_INVALID_START;
            }
            options->start_addr = parsed;
            break;
        }
        case DRAT_ARG_KEY_END: {
            int64_t parsed = -1;
            if (!parse_number(&parsed, arg) || parsed < 0) {
                return DRAT_ARG_ERR_INVALID_END;
            }
            options->end_addr = parsed;
            break;
        }
        case DRAT_ARG_KEY_DENTRY_NAME:
            return parse_name_list(options, arg);
        case DRAT_ARG_KEY_DENTRY_OID:
            return parse_oid_list(&options->dentry_oids, &options->num_dentry_oids, arg, DRAT_ARG_ERR_INVALID_DENTRY_OID);
        case DRAT_ARG_KEY_DENTRY_OID_RANGE: {
            uint64_t start = 0;
            uint64_t end = 0;
            if (!parse_range(arg, &start, &end)) {
                return DRAT_ARG_ERR_INVALID_DENTRY_OID_RANGE;
            }
            if (!add_range(&options->dentry_oid_ranges, &options->num_dentry_oid_ranges, start, end)) {
                return DRAT_ARG_ERR_OUT_OF_MEMORY;
            }
            break;
        }
        case DRAT_ARG_KEY_VIRTUAL_OID:
            return parse_oid_list(&options->virtual_oids, &options->num_virtual_oids, arg, DRAT_ARG_ERR_INVALID_VIRTUAL_OID);
        case DRAT_ARG_KEY_OMAP_OID_RANGE: {
            uint64_t start = 0;
            uint64_t end = 0;
            if (!parse_range(arg, &start, &end)) {
                return DRAT_ARG_ERR_INVALID_OMAP_OID_RANGE;
            }
            if (!add_range(&options->omap_oid_ranges, &options->num_omap_oid_ranges, start, end)) {
                return DRAT_ARG_ERR_OUT_OF_MEMORY;
            }
            break;
        }
        case DRAT_ARG_KEY_SCAN_OMAP:
            options->scan_omap = true;
            break;
        case DRAT_ARG_KEY_SCAN_VIRTUAL:
            options->scan_virtual = true;
            break;
        case DRAT_ARG_KEY_NO_CKSUM:
            options->require_cksum = false;
            break;
        case DRAT_ARG_KEY_MATCHES_ONLY:
            options->list_all = false;
            break;
        case DRAT_ARG_KEY_EXPORT:
            if (!arg || !*arg) {
                return DRAT_ARG_ERR_INVALID_EXPORT;
            }
            options->export_path = arg;
            break;
        case ARGP_KEY_END:
            return 0;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

// TODO: Perhaps factor out from all commands
static const struct argp argp = {
    &argp_options,  // struct argp_option* options
    &argp_parser,   // argp_parser_t parser
    0,              // char* args_doc
    0,              // char* doc
    &argp_children  // struct argp_child* children
};

static bool matches_dentry_name(const j_drec_hashed_key_t* key, const char* filter) {
    uint16_t name_len = key->name_len_and_hash & J_DREC_LEN_MASK;
    if (strlen(filter) != name_len) {
        return false;
    }
    return strncasecmp((const char*)key->name, filter, name_len) == 0;
}

static bool matches_any_range(uint64_t value, const oid_range_t* ranges, size_t num_ranges) {
    for (size_t i = 0; i < num_ranges; i++) {
        if (value >= ranges[i].start && value <= ranges[i].end) {
            return true;
        }
    }
    return false;
}

static bool matches_any_oid(uint64_t value, const uint64_t* oids, size_t num_oids) {
    for (size_t i = 0; i < num_oids; i++) {
        if (value == oids[i]) {
            return true;
        }
    }
    return false;
}

static void write_csv_field(FILE* stream, const char* data, size_t len) {
    if (!data || len == 0) {
        return;
    }
    fputc('"', stream);
    for (size_t i = 0; i < len; i++) {
        if (data[i] == '"') {
            fputc('"', stream);
        }
        fputc(data[i], stream);
    }
    fputc('"', stream);
}

static void export_dentry(FILE* stream, uint64_t block_addr, btree_node_phys_t* node, j_drec_hashed_key_t* key, j_drec_val_t* val) {
    uint16_t name_len = key->name_len_and_hash & J_DREC_LEN_MASK;
    fprintf(stream, "DENTRY,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",",
        block_addr,
        node->btn_o.o_oid,
        node->btn_o.o_xid,
        val->file_id
    );
    write_csv_field(stream, (const char*)key->name, name_len);
    fprintf(stream, ",,,\n");
}

static void export_file_extent(FILE* stream, uint64_t block_addr, btree_node_phys_t* node, j_file_extent_key_t* key, j_file_extent_val_t* val) {
    uint64_t length_bytes = val->len_and_flags & J_FILE_EXTENT_LEN_MASK;
    fprintf(stream, "FILE_EXTENT,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",,%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
        block_addr,
        node->btn_o.o_oid,
        node->btn_o.o_xid,
        key->hdr.obj_id_and_type & OBJ_ID_MASK,
        key->logical_addr,
        val->phys_block_num,
        length_bytes
    );
}

/**
 * Print usage info for this program.
 */
static void print_usage(FILE* stream) {
    fprintf(
        stream,
        "Usage:   %1$s %2$s --container <container> [options]\n"
        "Example: %1$s %2$s --container /dev/disk0s2 --matches-only --dentry-name id_rsa\n",
        globals.program_name,
        globals.command_name
    );
}

int cmd_search(int argc, char** argv) {
    if (argc == 2) {
        // Command was specified with no other arguments
        print_usage(stdout);
        return 0;
    }
    
    setbuf(stdout, NULL);

    options_t options = {
        .start_addr = -1,
        .end_addr = -1,
        .require_cksum = true,
        .list_all = true,
        .scan_omap = false,
        .scan_virtual = false,
        .export_path = NULL,
        .export_stream = NULL,
        .num_dentry_names = 0,
        .dentry_names = NULL,
        .num_dentry_oids = 0,
        .dentry_oids = NULL,
        .num_dentry_oid_ranges = 0,
        .dentry_oid_ranges = NULL,
        .num_virtual_oids = 0,
        .virtual_oids = NULL,
        .num_omap_oid_ranges = 0,
        .omap_oid_ranges = NULL,
    };

    // Parse global and command options
    bool usage_error = true;
    error_t parse_result = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &options);
    if (!print_global_args_error(parse_result)) {
        switch (parse_result) {
            case 0:
                usage_error = false;
                break;
            case DRAT_ARG_ERR_INVALID_START:
                fprintf(stderr, "%s: option `--start` has invalid value; must be a non-negative integer.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_END:
                fprintf(stderr, "%s: option `--end` has invalid value; must be a non-negative integer.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_DENTRY_NAME:
                fprintf(stderr, "%s: option `--dentry-name` has invalid value.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_DENTRY_OID:
                fprintf(stderr, "%s: option `--dentry-oid` has invalid value; must be a number.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_DENTRY_OID_RANGE:
                fprintf(stderr, "%s: option `--dentry-oid-range` has invalid value; must be start-end.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_VIRTUAL_OID:
                fprintf(stderr, "%s: option `--virtual-oid` has invalid value; must be a number.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_OMAP_OID_RANGE:
                fprintf(stderr, "%s: option `--omap-oid-range` has invalid value; must be start-end.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_OUT_OF_MEMORY:
                fprintf(stderr, "%s: ran out of memory while parsing options.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_EXPORT:
                fprintf(stderr, "%s: option `--export` has invalid value.\n", globals.program_name);
                break;
            default:
                print_arg_parse_error();
                return EX_SOFTWARE;
        }
    }
    if (usage_error) {
        print_usage(stderr);
        return EX_USAGE;
    }

    if (open_container() != 0) {
        return EX_NOINPUT;
    }

    if (options.export_path) {
        options.export_stream = fopen(options.export_path, "w");
        if (!options.export_stream) {
            fprintf(stderr, "ABORT: Failed to open export file `%s`: %s\n", options.export_path, get_fopen_error_msg());
            close_container();
            return EX_CANTCREAT;
        }
        fprintf(options.export_stream, "type,block_addr,node_oid,node_xid,file_id,name,logical_addr,phys_block,length_bytes\n");
    }

    obj_phys_t* block = malloc(globals.block_size);
    if (!block) {
        fprintf(stderr, "\nABORT: Could not allocate sufficient memory for `block`.\n");
        return -1;
    }

    bool have_block_count = false;
    uint64_t num_blocks = 0;

    printf("Reading block 0x0 to obtain block count ... ");
    if (read_blocks(block, 0x0, 1) == 1) {
        printf("OK.\n");
        if (is_nx_superblock(block) && ((nx_superblock_t*)block)->nx_magic == NX_MAGIC) {
            num_blocks = ((nx_superblock_t*)block)->nx_block_count;
            have_block_count = true;
        } else {
            printf("WARNING: Block 0x0 is not a valid container superblock. Scanning until end-of-container.\n");
        }
    } else {
        printf("FAILED.\n");
        printf("WARNING: Unable to read block 0x0. Scanning until end-of-container.\n");
    }

    if (options.start_addr != -1 && options.end_addr != -1 && options.start_addr >= options.end_addr) {
        fprintf(stderr, "%s: option `--start` must be less than `--end`.\n", globals.program_name);
        print_usage(stderr);
        return EX_USAGE;
    }

    uint64_t start_addr = (options.start_addr != -1) ? (uint64_t)options.start_addr : 0;
    uint64_t end_addr = 0;
    if (options.end_addr != -1) {
        end_addr = (uint64_t)options.end_addr;
    } else if (have_block_count) {
        end_addr = num_blocks;
    } else {
        end_addr = UINT64_MAX;
    }

    if (have_block_count) {
        printf("The specified device has %" PRIu64 " = %#" PRIx64 " blocks. Commencing search:\n\n", num_blocks, num_blocks);
    } else {
        printf("Commencing search without a known block count.\n\n");
    }

    uint64_t num_matches = 0;
    uint64_t addr_range_size = (end_addr == UINT64_MAX) ? 0 : (end_addr - start_addr);

    /** Search over all blocks **/
    const char spinner[] = "|/-\\";
    size_t spinner_index = 0;
    uint64_t progress_interval = 1024;
    if (addr_range_size > 0) {
        progress_interval = addr_range_size / 100;
        if (progress_interval < 1024) {
            progress_interval = 1024;
        }
    }

    for (uint64_t addr = start_addr; addr < end_addr; addr++) {
        if (addr == start_addr || (addr % progress_interval) == 0) {
            if (addr_range_size > 0) {
                double pct = 100.0 * (double)(addr - start_addr) / (double)addr_range_size;
                printf("\r[%c] Reading block %#9" PRIx64 " (%6.2f%%) ... ", spinner[spinner_index++ % 4], addr, pct);
            } else {
                printf("\r[%c] Reading block %#9" PRIx64 " ... ", spinner[spinner_index++ % 4], addr);
            }
        }

        if (read_blocks(block, addr, 1) != 1) {
            if (end_of_container()) {
                printf("Reached end of container; search complete.\n");
                break;
            }

            printf("WARNING: Failed to read block %#"PRIx64".\n", addr);
            continue;
        }

        bool checksum_ok = is_cksum_valid(block);

        if (options.require_cksum && !checksum_ok) {
            continue;
        }

        /** Scan omap leaf nodes **/
        if (options.scan_omap) {
            if (   is_btree_node_phys_non_root(block)
                && is_omap_tree(block)
            ) {
                btree_node_phys_t* node = block;

                if (!(node->btn_flags & BTNODE_FIXED_KV_SIZE)) {
                    continue;
                }
                if (!(node->btn_flags & BTNODE_LEAF)) {
                    continue;
                }

                char* toc_start = (char*)node->btn_data + node->btn_table_space.off;
                char* key_start = toc_start + node->btn_table_space.len;
                kvoff_t* toc_entry = toc_start;

                bool has_range_filter = options.num_omap_oid_ranges > 0;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    omap_key_t* key = key_start + toc_entry->k;
                    bool match = has_range_filter ? matches_any_range(key->ok_oid, options.omap_oid_ranges, options.num_omap_oid_ranges)
                                                  : options.list_all;
                    if (match) {
                        kvoff_t* first_toc_entry = toc_start;
                        omap_key_t* first_key = key_start + first_toc_entry->k;
                        kvoff_t* last_toc_entry = first_toc_entry + node->btn_nkeys - 1;
                        omap_key_t* last_key = key_start + last_toc_entry->k;
                        num_matches++;
                        printf("\rOMAP %#8" PRIx64 " || Node XID = %#9" PRIx64 " || from (OID, XID) = (%#9" PRIx64 ", %#9" PRIx64 ") => (%#9" PRIx64 ", %#9" PRIx64 ")\n",
                            addr,
                            node->btn_o.o_xid,
                            first_key->ok_oid,
                            first_key->ok_xid,
                            last_key->ok_oid,
                            last_key->ok_xid
                        );
                        break;
                    }
                }
            }
        }

        /** Scan virtual objects **/
        if (options.scan_virtual) {
            if ((block->o_type & OBJ_STORAGETYPE_MASK) == OBJ_VIRTUAL) {
                bool has_filter = options.num_virtual_oids > 0;
                bool match = has_filter ? matches_any_oid(block->o_oid, options.virtual_oids, options.num_virtual_oids)
                                        : options.list_all;
                if (match) {
                    num_matches++;
                    printf("\rVIRTUAL %#8" PRIx64 " || OID = %#9" PRIx64 " || XID = %#9" PRIx64 "\n", addr, block->o_oid, block->o_xid);
                }
            }
        }

        /** Scan FS B-tree dentries **/
        if (   is_btree_node_phys(block)
            && is_fs_tree(block)
        ) {
            btree_node_phys_t* node = block;

            if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
                continue;
            }

            if (!(node->btn_flags & BTNODE_LEAF)) {
                continue;
            }

            char* toc_start = (char*)node->btn_data + node->btn_table_space.off;
            char* key_start = toc_start + node->btn_table_space.len;
            char* val_end   = (char*)node + globals.block_size;
            if (node->btn_flags & BTNODE_ROOT) {
                val_end -= sizeof(btree_info_t);
            }

            bool has_name_filter = options.num_dentry_names > 0;
            bool has_oid_filter = options.num_dentry_oids > 0 || options.num_dentry_oid_ranges > 0;

            kvloc_t* toc_entry = toc_start;
            for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                j_key_t* hdr = key_start + toc_entry->k.off;
                uint8_t record_type = (hdr->obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
                if (record_type == APFS_TYPE_DIR_REC) {
                    j_drec_hashed_key_t* key = hdr;
                    j_drec_val_t* val = val_end - toc_entry->v.off;

                    bool name_ok = !has_name_filter;
                    if (has_name_filter) {
                        for (size_t j = 0; j < options.num_dentry_names; j++) {
                            if (matches_dentry_name(key, options.dentry_names[j])) {
                                name_ok = true;
                                break;
                            }
                        }
                    }

                    bool oid_ok = !has_oid_filter;
                    if (has_oid_filter) {
                        oid_ok = matches_any_oid(val->file_id, options.dentry_oids, options.num_dentry_oids)
                            || matches_any_range(val->file_id, options.dentry_oid_ranges, options.num_dentry_oid_ranges);
                    }

                    if (name_ok && oid_ok && (options.list_all || has_name_filter || has_oid_filter)) {
                        uint16_t name_len = key->name_len_and_hash & J_DREC_LEN_MASK;
                        num_matches++;
                        printf("\rDENTRY %#8" PRIx64 " || Node OID = %#9" PRIx64 " || XID = %#9" PRIx64 " || FileID = %#9" PRIx64 " || Name = %.*s\n",
                            addr,
                            node->btn_o.o_oid,
                            node->btn_o.o_xid,
                            val->file_id,
                            name_len,
                            key->name
                        );
                    }
                    if (options.export_stream && (options.list_all || has_name_filter || has_oid_filter)) {
                        export_dentry(options.export_stream, addr, node, key, val);
                    }
                } else if (record_type == APFS_TYPE_FILE_EXTENT) {
                    j_file_extent_key_t* key = hdr;
                    j_file_extent_val_t* val = val_end - toc_entry->v.off;
                    if (options.export_stream) {
                        export_file_extent(options.export_stream, addr, node, key, val);
                    }
                }
            }
        }
    }

    printf("\n\nFinished search; found %" PRIu64 " results.\n\n", num_matches);
    if (options.export_stream) {
        fclose(options.export_stream);
    }
    for (size_t i = 0; i < options.num_dentry_names; i++) {
        free(options.dentry_names[i]);
    }
    free(options.dentry_names);
    free(options.dentry_oids);
    free(options.dentry_oid_ranges);
    free(options.virtual_oids);
    free(options.omap_oid_ranges);
    
    return 0;
}
