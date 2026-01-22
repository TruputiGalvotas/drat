#include <stdio.h>
#include <sys/errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sysexits.h>

#include <apfs/object.h>
#include <apfs/nx.h>
#include <apfs/omap.h>
#include <apfs/fs.h>
#include <apfs/j.h>
#include <apfs/dstream.h>
#include <apfs/sibling.h>
#include <apfs/snap.h>

#include <drat/globals.h>
#include <drat/argp.h>
#include <drat/strings.h>
#include <drat/io.h>
#include <drat/print-fs-records.h>

#include <drat/func/boolean.h>
#include <drat/func/cksum.h>
#include <drat/func/btree.h>

#include <drat/string/object.h>
#include <drat/string/nx.h>
#include <drat/string/omap.h>
#include <drat/string/btree.h>
#include <drat/string/fs.h>
#include <drat/string/j.h>

typedef struct options_t {
    int64_t fsoid;  // Needs to be `int64_t to work with `parse_number()`
    char* path;
    bool require_cksum;
    int64_t snapshot_xid;
    char* snapshot_name;
    bool all_snapshots;
} options_t;

static bool name_equals(const uint8_t* name, uint16_t name_len, const char* query) {
    size_t query_len = strlen(query);
    return query_len == name_len && strncmp((const char*)name, query, name_len) == 0;
}

typedef struct {
    xid_t xid;
    char* name;
} snapshot_info_t;

static bool add_snapshot_info(snapshot_info_t** list, size_t* count, xid_t xid, const uint8_t* name, uint16_t name_len) {
    for (size_t i = 0; i < *count; i++) {
        if ((*list)[i].xid == xid && strncmp((*list)[i].name, (const char*)name, name_len) == 0 && (*list)[i].name[name_len] == '\0') {
            return true;
        }
    }
    char* copy = malloc(name_len + 1);
    if (!copy) {
        return false;
    }
    memcpy(copy, name, name_len);
    copy[name_len] = '\0';
    snapshot_info_t* updated = realloc(*list, (*count + 1) * sizeof(**list));
    if (!updated) {
        free(copy);
        return false;
    }
    updated[*count].xid = xid;
    updated[*count].name = copy;
    *list = updated;
    (*count)++;
    return true;
}

static snapshot_info_t* list_snapshots(btree_node_phys_t* fs_omap_btree, apfs_superblock_t* apsb, size_t* out_count) {
    *out_count = 0;
    if (!apsb->apfs_snap_meta_tree_oid) {
        return NULL;
    }

    omap_entry_t* snap_tree_entry = get_btree_phys_omap_entry(fs_omap_btree, apsb->apfs_snap_meta_tree_oid, apsb->apfs_o.o_xid);
    if (!snap_tree_entry) {
        return NULL;
    }

    size_t stack_cap = 64;
    size_t stack_len = 0;
    paddr_t* stack = malloc(stack_cap * sizeof(*stack));
    if (!stack) {
        free(snap_tree_entry);
        return NULL;
    }
    stack[stack_len++] = snap_tree_entry->val.ov_paddr;
    free(snap_tree_entry);

    snapshot_info_t* snapshots = NULL;

    btree_node_phys_t* node = malloc(globals.block_size);
    if (!node) {
        free(stack);
        return NULL;
    }

    while (stack_len > 0) {
        paddr_t addr = stack[--stack_len];
        if (read_blocks(node, addr, 1) != 1) {
            continue;
        }
        if (globals.require_cksum && !is_cksum_valid(node)) {
            continue;
        }

        char* toc_start = (char*)node->btn_data + node->btn_table_space.off;
        char* key_start = toc_start + node->btn_table_space.len;
        char* val_end   = (char*)node + globals.block_size;
        if (node->btn_flags & BTNODE_ROOT) {
            val_end -= sizeof(btree_info_t);
        }

        if (node->btn_flags & BTNODE_LEAF) {
            if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
                kvoff_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    j_key_t* hdr = key_start + toc_entry->k;
                    uint8_t record_type = (hdr->obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
                    if (record_type != APFS_TYPE_SNAP_NAME) {
                        continue;
                    }
                    j_snap_name_key_t* key = (j_snap_name_key_t*)hdr;
                    j_snap_name_val_t* val = val_end - toc_entry->v;
                    if (!add_snapshot_info(&snapshots, out_count, val->snap_xid, key->name, key->name_len)) {
                        free(node);
                        free(stack);
                        return snapshots;
                    }
                }
            } else {
                kvloc_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    j_key_t* hdr = key_start + toc_entry->k.off;
                    uint8_t record_type = (hdr->obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
                    if (record_type != APFS_TYPE_SNAP_NAME) {
                        continue;
                    }
                    j_snap_name_key_t* key = (j_snap_name_key_t*)hdr;
                    j_snap_name_val_t* val = val_end - toc_entry->v.off;
                    if (!add_snapshot_info(&snapshots, out_count, val->snap_xid, key->name, key->name_len)) {
                        free(node);
                        free(stack);
                        return snapshots;
                    }
                }
            }
        } else {
            if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
                kvoff_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    oid_t* child_oid = val_end - toc_entry->v;
                    omap_entry_t* child_entry = get_btree_phys_omap_entry(fs_omap_btree, *child_oid, apsb->apfs_o.o_xid);
                    if (!child_entry) {
                        continue;
                    }
                    if (stack_len == stack_cap) {
                        stack_cap *= 2;
                        paddr_t* updated = realloc(stack, stack_cap * sizeof(*stack));
                        if (!updated) {
                            free(child_entry);
                            continue;
                        }
                        stack = updated;
                    }
                    stack[stack_len++] = child_entry->val.ov_paddr;
                    free(child_entry);
                }
            } else {
                kvloc_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    oid_t* child_oid = val_end - toc_entry->v.off;
                    omap_entry_t* child_entry = get_btree_phys_omap_entry(fs_omap_btree, *child_oid, apsb->apfs_o.o_xid);
                    if (!child_entry) {
                        continue;
                    }
                    if (stack_len == stack_cap) {
                        stack_cap *= 2;
                        paddr_t* updated = realloc(stack, stack_cap * sizeof(*stack));
                        if (!updated) {
                            free(child_entry);
                            continue;
                        }
                        stack = updated;
                    }
                    stack[stack_len++] = child_entry->val.ov_paddr;
                    free(child_entry);
                }
            }
        }
    }

    free(node);
    free(stack);
    return snapshots;
}

static int list_entrypoint(btree_node_phys_t* fs_omap_btree, btree_node_phys_t* fs_root_btree, const options_t* options) {
    j_rec_t** fs_records = NULL;
    int64_t target_fsoid = options->fsoid;

    if (options->path) {
        printf("Navigating to path `%s` ... ", options->path);

        oid_t fsoid = ROOT_DIR_INO_NUM;
        fs_records = get_fs_records(fs_omap_btree, fs_root_btree, fsoid, globals.max_xid);
        if (!fs_records) {
            printf("END: No records found for the filesystem root, `/`.\n");
            return 0;
        }

        char* path = malloc(strlen(options->path) + 1);
        if (!path) {
            fprintf(stderr, "ABORT: Not enough memory for `path`.\n");
            return EX_OSERR;
        }
        memcpy(path, options->path, strlen(options->path) + 1);

        char* path_element;
        while ( (path_element = strsep(&path, "/")) != NULL ) {
            // If path element is empty string, skip it
            if (*path_element == '\0') {
                continue;
            }
            
            signed int matching_record_index = -1;
            for (j_rec_t** fs_rec_cursor = fs_records; *fs_rec_cursor; fs_rec_cursor++) {
                j_rec_t* fs_rec = *fs_rec_cursor;
                j_key_t* hdr = fs_rec->data;
                if ( ((hdr->obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT)  ==  APFS_TYPE_DIR_REC ) {
                    j_drec_hashed_key_t* key = fs_rec->data;   
                    if (strcmp((char*)key->name, path_element) == 0) {
                        matching_record_index = fs_rec_cursor - fs_records;
                        break;
                    }
                }
            }

            if (matching_record_index == -1) {
                // No match
                printf("END: No dentry found for path `%s`.\n", options->path);
                free_j_rec_array(fs_records);
                return 0;
            }

            // Get the file ID of the matching record's target
            j_rec_t* fs_rec = fs_records[matching_record_index];
            j_drec_val_t* val = fs_rec->data + fs_rec->key_len;

            // Get the records for the target
            fsoid = val->file_id;
            free_j_rec_array(fs_records);
            fs_records = get_fs_records(fs_omap_btree, fs_root_btree, fsoid, globals.max_xid);
        }

        target_fsoid = fsoid;
        printf("its FSOID is %#"PRIx64".\n", (uint64_t)target_fsoid);
    }

    if (target_fsoid == -1) {
        return 0;
    }

    printf("Finding records for FSOID %#"PRIx64" ... ", (uint64_t)target_fsoid);
    if (!fs_records) {
        fs_records = get_fs_records(fs_omap_btree, fs_root_btree, (oid_t)target_fsoid, globals.max_xid);
    }
    printf("OK.\n");

    size_t num_records = 0;
    for (j_rec_t** cursor = fs_records; *cursor; cursor++) {
        num_records++;
    }
    printf("Filesystem object has %zu records, as follows:\n", num_records);
    print_fs_records(stdout, fs_records);

    free_j_rec_array(fs_records);
    return 0;
}
static xid_t find_snapshot_xid(btree_node_phys_t* fs_omap_btree, apfs_superblock_t* apsb, const char* snapshot_name) {
    if (!apsb->apfs_snap_meta_tree_oid) {
        return 0;
    }

    omap_entry_t* snap_tree_entry = get_btree_phys_omap_entry(fs_omap_btree, apsb->apfs_snap_meta_tree_oid, apsb->apfs_o.o_xid);
    if (!snap_tree_entry) {
        return 0;
    }

    size_t stack_cap = 64;
    size_t stack_len = 0;
    paddr_t* stack = malloc(stack_cap * sizeof(*stack));
    if (!stack) {
        free(snap_tree_entry);
        return 0;
    }
    stack[stack_len++] = snap_tree_entry->val.ov_paddr;
    free(snap_tree_entry);

    btree_node_phys_t* node = malloc(globals.block_size);
    if (!node) {
        free(stack);
        return 0;
    }

    while (stack_len > 0) {
        paddr_t addr = stack[--stack_len];
        if (read_blocks(node, addr, 1) != 1) {
            continue;
        }
        if (globals.require_cksum && !is_cksum_valid(node)) {
            continue;
        }

        char* toc_start = (char*)node->btn_data + node->btn_table_space.off;
        char* key_start = toc_start + node->btn_table_space.len;
        char* val_end   = (char*)node + globals.block_size;
        if (node->btn_flags & BTNODE_ROOT) {
            val_end -= sizeof(btree_info_t);
        }

        if (node->btn_flags & BTNODE_LEAF) {
            if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
                kvoff_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    j_key_t* hdr = key_start + toc_entry->k;
                    uint8_t record_type = (hdr->obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
                    if (record_type != APFS_TYPE_SNAP_NAME) {
                        continue;
                    }
                    j_snap_name_key_t* key = (j_snap_name_key_t*)hdr;
                    j_snap_name_val_t* val = val_end - toc_entry->v;
                    if (name_equals(key->name, key->name_len, snapshot_name)) {
                        xid_t xid = val->snap_xid;
                        free(node);
                        free(stack);
                        return xid;
                    }
                }
            } else {
                kvloc_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    j_key_t* hdr = key_start + toc_entry->k.off;
                    uint8_t record_type = (hdr->obj_id_and_type & OBJ_TYPE_MASK) >> OBJ_TYPE_SHIFT;
                    if (record_type != APFS_TYPE_SNAP_NAME) {
                        continue;
                    }
                    j_snap_name_key_t* key = (j_snap_name_key_t*)hdr;
                    j_snap_name_val_t* val = val_end - toc_entry->v.off;
                    if (name_equals(key->name, key->name_len, snapshot_name)) {
                        xid_t xid = val->snap_xid;
                        free(node);
                        free(stack);
                        return xid;
                    }
                }
            }
        } else {
            if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
                kvoff_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    oid_t* child_oid = val_end - toc_entry->v;
                    omap_entry_t* child_entry = get_btree_phys_omap_entry(fs_omap_btree, *child_oid, apsb->apfs_o.o_xid);
                    if (!child_entry) {
                        continue;
                    }
                    if (stack_len == stack_cap) {
                        stack_cap *= 2;
                        paddr_t* updated = realloc(stack, stack_cap * sizeof(*stack));
                        if (!updated) {
                            free(child_entry);
                            continue;
                        }
                        stack = updated;
                    }
                    stack[stack_len++] = child_entry->val.ov_paddr;
                    free(child_entry);
                }
            } else {
                kvloc_t* toc_entry = toc_start;
                for (uint32_t i = 0; i < node->btn_nkeys; i++, toc_entry++) {
                    oid_t* child_oid = val_end - toc_entry->v.off;
                    omap_entry_t* child_entry = get_btree_phys_omap_entry(fs_omap_btree, *child_oid, apsb->apfs_o.o_xid);
                    if (!child_entry) {
                        continue;
                    }
                    if (stack_len == stack_cap) {
                        stack_cap *= 2;
                        paddr_t* updated = realloc(stack, stack_cap * sizeof(*stack));
                        if (!updated) {
                            free(child_entry);
                            continue;
                        }
                        stack = updated;
                    }
                    stack[stack_len++] = child_entry->val.ov_paddr;
                    free(child_entry);
                }
            }
        }
    }

    free(node);
    free(stack);
    return 0;
}

#define DRAT_ARG_KEY_FSOID  (DRAT_GLOBAL_ARGS_LAST_KEY - 1)
#define DRAT_ARG_KEY_PATH   (DRAT_GLOBAL_ARGS_LAST_KEY - 2)
#define DRAT_ARG_KEY_NO_CKSUM (DRAT_GLOBAL_ARGS_LAST_KEY - 3)
#define DRAT_ARG_KEY_SNAPSHOT_XID (DRAT_GLOBAL_ARGS_LAST_KEY - 4)
#define DRAT_ARG_KEY_SNAPSHOT_NAME (DRAT_GLOBAL_ARGS_LAST_KEY - 5)
#define DRAT_ARG_KEY_ALL_SNAPSHOTS (DRAT_GLOBAL_ARGS_LAST_KEY - 6)

#define DRAT_ARG_ERR_INVALID_FSOID  (DRAT_GLOBAL_ARGS_LAST_ERR - 1)
#define DRAT_ARG_ERR_INVALID_PATH   (DRAT_GLOBAL_ARGS_LAST_ERR - 2)
#define DRAT_ARG_ERR_NO_VOLUME      (DRAT_GLOBAL_ARGS_LAST_ERR - 3)
#define DRAT_ARG_ERR_NO_ENTRYPOINT  (DRAT_GLOBAL_ARGS_LAST_ERR - 4)
#define DRAT_ARG_ERR_INVALID_SNAPSHOT_XID (DRAT_GLOBAL_ARGS_LAST_ERR - 5)
#define DRAT_ARG_ERR_INVALID_SNAPSHOT_NAME (DRAT_GLOBAL_ARGS_LAST_ERR - 6)
#define DRAT_ARG_ERR_SNAPSHOT_CONFLICT (DRAT_GLOBAL_ARGS_LAST_ERR - 7)
#define DRAT_ARG_ERR_ALL_SNAPSHOTS_CONFLICT (DRAT_GLOBAL_ARGS_LAST_ERR - 8)

static const struct argp_option argp_options[] = {
    // char* name,  int key,            char* arg,  int flags,  char* doc
    { "fsoid",      DRAT_ARG_KEY_FSOID, "fsoid",    0,          "Filesystem object ID" },
    { "path",       DRAT_ARG_KEY_PATH,  "path",     0,          "File/directory path" },
    { "no-cksum",   DRAT_ARG_KEY_NO_CKSUM, 0,       0,          "Do not require checksum validation" },
    { "snapshot-xid",  DRAT_ARG_KEY_SNAPSHOT_XID, "xid", 0,     "Use snapshot at the given XID" },
    { "snapshot-name", DRAT_ARG_KEY_SNAPSHOT_NAME, "name", 0,   "Use snapshot with the given name" },
    { "all-snapshots", DRAT_ARG_KEY_ALL_SNAPSHOTS, 0,     0,    "List the entrypoint across all snapshots" },
    {0}
};

static error_t argp_parser(int key, char* arg, struct argp_state* state) {
    options_t* options = state->input;

    switch (key) {
        case DRAT_ARG_KEY_FSOID:
            if (!parse_number(&options->fsoid, arg)) {
                return DRAT_ARG_ERR_INVALID_FSOID;
            }
            break;
        case DRAT_ARG_KEY_PATH:
            if (arg[0] != '/') {
                return DRAT_ARG_ERR_INVALID_PATH;
            }
            options->path = arg;
            break;
        case DRAT_ARG_KEY_NO_CKSUM:
            options->require_cksum = false;
            break;
        case DRAT_ARG_KEY_SNAPSHOT_XID:
            if (!parse_number(&options->snapshot_xid, arg) || options->snapshot_xid < 0) {
                return DRAT_ARG_ERR_INVALID_SNAPSHOT_XID;
            }
            break;
        case DRAT_ARG_KEY_SNAPSHOT_NAME:
            if (!arg || !*arg) {
                return DRAT_ARG_ERR_INVALID_SNAPSHOT_NAME;
            }
            options->snapshot_name = arg;
            break;
        case DRAT_ARG_KEY_ALL_SNAPSHOTS:
            options->all_snapshots = true;
            break;
        case ARGP_KEY_END:
            if (options->snapshot_xid != -1 && options->snapshot_name) {
                return DRAT_ARG_ERR_SNAPSHOT_CONFLICT;
            }
            if (options->all_snapshots && (options->snapshot_xid != -1 || options->snapshot_name)) {
                return DRAT_ARG_ERR_ALL_SNAPSHOTS_CONFLICT;
            }
            if (globals.volume == -1) {
                return DRAT_ARG_ERR_NO_VOLUME;
            }
            if (options->fsoid == -1 && !options->path) {
                return DRAT_ARG_ERR_NO_ENTRYPOINT;
            }
            // fall through
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

static void print_usage(FILE* stream) {
    // TODO: Add all possible syntaxes.
    fprintf(
        stream,
        "Usage:\n"
        "  %1$s %2$s --container <container> --volume <volume index> --fsoid <filesystem object ID> [--no-cksum] [--snapshot-xid <xid> | --snapshot-name <name>]\n"
        "  %1$s %2$s --container <container> --volume <volume index> --path <file/directory path> [--no-cksum] [--snapshot-xid <xid> | --snapshot-name <name>]\n"
        "Examples:\n"
        "  %1$s %2$s --container /dev/disk0s2 --volume 1 0xd02a4 --fsoid 0x3af2\n"
        "  %1$s %2$s --container /dev/disk0s2 --volume 1 0xd02a4 --path /Users/john/Documents\n",
        globals.program_name,
        globals.command_name
    );
}

int cmd_list(int argc, char** argv) {
    if (argc == 2) {
        // Command was specified with no other arguments
        print_usage(stdout);
        return 0;
    }
    
    // Set placeholder values so that the parser can identify whether the user
    // has set mandatory options or not
    globals.volume = -1;
    options_t options = {-1, NULL, true, -1, NULL, false};

    bool usage_error = true;
    error_t parse_result = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &options);
    if (!print_global_args_error(parse_result)) {
        switch (parse_result) {
            case 0:
                usage_error = false;
                break;
            case DRAT_ARG_ERR_INVALID_FSOID:
                fprintf(stderr, "%s: option `--fsoid`" INVALID_HEX_STRING, globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_PATH:
                fprintf(stderr, "%s: option `--path` has invalid value; must be an absolute path, i.e. start with `/`.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_NO_VOLUME:
                fprintf(stderr, "%s: option `--volume` is mandatory.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_NO_ENTRYPOINT:
                fprintf(stderr, "%s: entrypoint is mandatory; use either `--fsoid` or `--path`.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_SNAPSHOT_XID:
                fprintf(stderr, "%s: option `--snapshot-xid` has invalid value.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_INVALID_SNAPSHOT_NAME:
                fprintf(stderr, "%s: option `--snapshot-name` has invalid value.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_SNAPSHOT_CONFLICT:
                fprintf(stderr, "%s: use either `--snapshot-xid` or `--snapshot-name`, not both.\n", globals.program_name);
                break;
            case DRAT_ARG_ERR_ALL_SNAPSHOTS_CONFLICT:
                fprintf(stderr, "%s: `--all-snapshots` cannot be used with `--snapshot-xid` or `--snapshot-name`.\n", globals.program_name);
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

    globals.require_cksum = options.require_cksum;

    // TODO: Perhaps handle other return values and factor out
    if (open_container() != 0) {
        return EX_NOINPUT;
    }
    printf("\n");

    setbuf(stdout, NULL);
    
    printf("Finding most recent container superblock:\n");

    printf("- Reading block 0x0 ... ");
    nx_superblock_t* nxsb = malloc(globals.block_size);
    if (!nxsb) {
        fprintf(stderr, "ABORT: Not enough memory to create `nxsb`.\n");
        return EX_OSERR;
    }
    if (read_blocks(nxsb, 0, 1) != 1) {
        fprintf(stderr, "ABORT: Failed to read block 0.\n");
        return EX_IOERR;
    }
    printf("validating ... ");
    if (!is_cksum_valid(nxsb)) {
        printf("FAILED.\n");
        printf("WARNING: Block 0 did not validate.\n");
    } else {
        printf("OK.\n");
    }

    if (!is_nx_superblock(nxsb)) {
        printf("WARNING: Block 0 should be a container superblock, but has the wrong object type.\n\n");
    }
    if (nxsb->nx_magic != NX_MAGIC) {
        printf(
            "WARNING: Block 0 %s a container superblock but doesn't have the correct magic number.\n",
            is_nx_superblock(nxsb) ? "is" : "should be"
        );
    }

    printf("- Loading checkpoint descriptor area ... ");
    
    uint32_t xp_desc_blocks = nxsb->nx_xp_desc_blocks & ~(1 << 31);
    char (*xp_desc)[globals.block_size] = malloc(xp_desc_blocks * globals.block_size);
    if (!xp_desc) {
        fprintf(stderr, "ABORT: Not enough memory for %"PRIu32" blocks.\n", xp_desc_blocks);
        return EX_OSERR;
    }

    if (nxsb->nx_xp_desc_blocks >> 31) {
        // TODO: implement case when xp_desc area is not contiguous
        printf("END: Checkpoint descriptor area is a B-tree, but we haven't implemented handling of this case yet.\n\n");
        return 0;
    } else {
        size_t blocks_read = read_blocks(xp_desc, nxsb->nx_xp_desc_base, xp_desc_blocks);
        if (blocks_read != xp_desc_blocks) {
            printf("FAILED.\n");
            fprintf(stderr, "\nABORT: Failed to read all blocks in the checkpoint descriptor area; only successfully read %zu blocks.\n", blocks_read);
            return EX_IOERR;
        } else {
            printf("OK.\n");
        }
    }

    printf("- Searching checkpoint descriptor area ... ");
    
    uint32_t i_latest_nx = 0;
    xid_t xid_latest_nx = 0;

    for (uint32_t i = 0; i < xp_desc_blocks; i++) {
        if (!is_cksum_valid(xp_desc[i])) {
            printf("WARNING: Checkpoint descriptor block %"PRIu32" failed validation.\n", i);
            continue;
        }
        
        if (is_nx_superblock(xp_desc[i])) {
            if ( ((nx_superblock_t*)xp_desc[i])->nx_magic  !=  NX_MAGIC ) {
                printf("WARNING: Checkpoint descriptor block %"PRIu32" is a container superblock but doesn't have the correct magic number.\n", i);
                continue;
            }

            xid_t nxsb_xid = ((nx_superblock_t*)xp_desc[i])->nx_o.o_xid;

            if ( (nxsb_xid > xid_latest_nx) && (nxsb_xid <= (xid_t)(globals.max_xid)) ) {
                i_latest_nx = i;
                xid_latest_nx = nxsb_xid;
            }
        } else if (!is_checkpoint_map_phys(xp_desc[i])) {
            printf("WARNING: Checkpoint descriptor block %"PRIu32" is neither a container superblock nor a checkpoint map.\n", i);
            continue;
        }
    }

    if (xid_latest_nx == 0) {
        printf("END: Didn't find any container superblock with maximum XID %#"PRIx64".\n", globals.max_xid);
        return 0;
    }
    
    // Don't need block 0 anymore; overwrite `nxsb` with the latest container superblock.
    memcpy(nxsb, xp_desc[i_latest_nx], sizeof(nx_superblock_t));
    // Don't need the checkpoint descriptor anymore
    free(xp_desc);
    
    printf("found most recent container superblock at index %"PRIu32", its XID is %#"PRIx64".\n", i_latest_nx, nxsb->nx_o.o_xid);

    printf("Finding container's omap tree:\n");
    
    printf("- Container's omap has Physical OID %#"PRIx64".\n", nxsb->nx_omap_oid);

    printf("- Reading block %#"PRIx64" ... ", nxsb->nx_omap_oid);
    omap_phys_t* nx_omap = malloc(globals.block_size);
    if (read_blocks(nx_omap, nxsb->nx_omap_oid, 1) != 1) {
        fprintf(stderr, "ABORT: Not enough memory for `nx_omap`.\n");
        return EX_OSERR;
    }
    printf("validating ... ");
    printf(is_cksum_valid(nx_omap) ? "OK.\n" : "FAILED.\n");
    
    if ((nx_omap->om_tree_type & OBJ_STORAGETYPE_MASK) != OBJ_PHYSICAL) {
        printf("  - END: Container omap B-tree is not a Physical object, and thus cannot be located.\n");
        return 0;
    }
    printf("- Container's omap tree has Physical OID %#"PRIx64".\n", nx_omap->om_tree_oid);

    printf("- Reading block %#"PRIx64" ... ", nx_omap->om_tree_oid);
    btree_node_phys_t* nx_omap_btree = malloc(globals.block_size);
    if (!nx_omap_btree) {
        fprintf(stderr, "ABORT: Not enough memory for `nx_omap_btree`.\n");
        return EX_OSERR;
    }
    if (read_blocks(nx_omap_btree, nx_omap->om_tree_oid, 1) != 1) {
        fprintf(stderr, "ABORT: Failed to read block %#"PRIx64".\n", nx_omap->om_tree_oid);
        return EX_IOERR;
    }
    printf("validating ...");
    printf(is_cksum_valid(nx_omap_btree) ? "OK.\n" : "FAILED.\n");

    printf("\n");

    // TODO: Handle `--volume-name` as well as `--volume` here.
    printf("Finding volume %"PRId64"'s superblock:\n", globals.volume);
    oid_t apsb_oid = nxsb->nx_fs_oid[globals.volume - 1];
    if (apsb_oid == 0) {
        printf("  - END: Volume %"PRId64" does not exist (apparent Virtual OID is 0).\n", globals.volume);
        return 0;
    }
    printf("- Volume %"PRId64" has Virtual OID %#"PRIx64" ... ", globals.volume, apsb_oid);

    // Get the block address
    omap_entry_t* fs_entry = get_btree_phys_omap_entry(nx_omap_btree, apsb_oid, nxsb->nx_o.o_xid);
    if (!fs_entry) {
        // TODO: Need better handling of this case; look at the previous transaction.
        printf("END: No objects with Virtual OID %#"PRIx64" and maximum XID %#"PRIx64" exist in `nx_omap_btree`.\n", apsb_oid, nxsb->nx_o.o_xid);
        return 0;
    }
    
    printf("maps to block %#"PRIx64" with XID %#"PRIx64".\n", fs_entry->val.ov_paddr, fs_entry->key.ok_xid);

    // Read the block
    printf("- Reading block %#"PRIx64" ... ", fs_entry->val.ov_paddr);
    apfs_superblock_t* apsb = malloc(globals.block_size);
    if (!apsb) {
        fprintf(stderr, "ABORT: Not enough memory for `apsb`.\n");
        return EX_OSERR;
    }
    if (read_blocks(apsb, fs_entry->val.ov_paddr, 1) != 1) {
        fprintf(stderr, "ABORT: Failed to read block %#"PRIx64".\n", fs_entry->val.ov_paddr);
        return EX_IOERR;
    }
    printf("validating ... ");
    printf(is_cksum_valid(apsb) ? "OK.\n" : "FAILED.\n");
    printf("- Volume name: %s\n", apsb->apfs_volname);

    printf("Finding volume's omap tree:\n");

    printf("- Volume's omap has Physical OID %#"PRIx64".\n", apsb->apfs_omap_oid);

    printf("- Reading block %#"PRIx64" ... ", apsb->apfs_omap_oid);
    omap_phys_t* fs_omap = malloc(globals.block_size);
    if (!fs_omap) {
        fprintf(stderr, "ABORT: Not enough memory for `fs_omap`.\n");
        return EX_OSERR;
    }
    if (read_blocks(fs_omap, apsb->apfs_omap_oid, 1) != 1) {
        fprintf(stderr, "ABORT: Failed to read block %#"PRIx64".\n", apsb->apfs_omap_oid);
        return EX_IOERR;
    }
    printf("validating ... ");
    printf(is_cksum_valid(fs_omap) ? "OK.\n" : "FAILED.\n");

    if ((fs_omap->om_tree_type & OBJ_STORAGETYPE_MASK) != OBJ_PHYSICAL) {
        printf("- END: Volume's omap tree is not a Physical object, and thus cannot be located.\n");
        return 0;
    }
    printf("- Volume's omap tree has Physical OID %#"PRIx64".\n", fs_omap->om_tree_oid);

    printf("- Reading block %#"PRIx64" ... ", fs_omap->om_tree_oid);
    btree_node_phys_t* fs_omap_btree = malloc(globals.block_size);
    if (!fs_omap_btree) {
        fprintf(stderr, "ABORT: Not enough memory for `fs_omap_btree`.\n");
        return EX_OSERR;
    }
    if (read_blocks(fs_omap_btree, fs_omap->om_tree_oid, 1) != 1) {
        fprintf(stderr, "ABORT: Failed to read block %#"PRIx64".\n", fs_omap->om_tree_oid);
        return EX_IOERR;
    }
    printf("validating ... ");
    printf(is_cksum_valid(fs_omap_btree) ? "OK.\n" : "FAILED.\n");

    printf("\n");

    if (options.snapshot_name || options.snapshot_xid != -1) {
        xid_t snapshot_xid = 0;
        if (options.snapshot_xid != -1) {
            snapshot_xid = (xid_t)options.snapshot_xid;
        } else {
            printf("Resolving snapshot name `%s` ... ", options.snapshot_name);
            snapshot_xid = find_snapshot_xid(fs_omap_btree, apsb, options.snapshot_name);
            if (snapshot_xid == 0) {
                printf("FAILED.\nEND: Snapshot name not found.\n");
                return 0;
            }
            printf("OK (XID = %#" PRIx64 ").\n", snapshot_xid);
        }
        globals.max_xid = snapshot_xid;
        printf("Using snapshot XID %#" PRIx64 " for traversal.\n\n", (uint64_t)globals.max_xid);
    }

    printf("Finding volume's filesystem tree:\n");
    printf("- Filesystem tree has Virtual OID %#"PRIx64" ... ", apsb->apfs_root_tree_oid);
    
    omap_entry_t* fs_root_entry = get_btree_phys_omap_entry(fs_omap_btree, apsb->apfs_root_tree_oid, apsb->apfs_o.o_xid);    
    if (!fs_root_entry) {
        // TODO: Need better handling of this case; look at the previous transaction.
        printf("END: No objects with Virtual OID %#"PRIx64" and maximum XID %#"PRIx64" exist in `fs_omap_btree`.\n", apsb->apfs_root_tree_oid, apsb->apfs_o.o_xid);
        return 0;
    }
    printf("maps to block %#"PRIx64".\n", fs_root_entry->val.ov_paddr);

    printf("- Reading block %#"PRIx64" ... ", fs_root_entry->val.ov_paddr);
    btree_node_phys_t* fs_root_btree = malloc(globals.block_size);
    if (!fs_root_btree) {
        fprintf(stderr, "ABORT: Not enough memory for `fs_root_btree`.\n");
        return EX_OSERR;
    }
    if (read_blocks(fs_root_btree, fs_root_entry->val.ov_paddr, 1) != 1) {
        fprintf(stderr, "ABORT: Failed to read block %#"PRIx64".\n", fs_root_entry->val.ov_paddr);
        return EX_IOERR;
    }
    
    // No longer need the block address of the file-system root.
    free(fs_root_entry);

    printf("validating ... ");
    if (globals.require_cksum) {
        printf(is_cksum_valid(fs_root_btree) ? "OK.\n" : "FAILED.\n");
    } else {
        printf("SKIPPED (ignoring checksum).\n");
    }

    printf("\n");

    if (options.all_snapshots) {
        size_t snapshot_count = 0;
        snapshot_info_t* snapshots = list_snapshots(fs_omap_btree, apsb, &snapshot_count);
        if (!snapshots || snapshot_count == 0) {
            printf("END: No snapshots found.\n");
            return 0;
        }
        for (size_t i = 0; i < snapshot_count; i++) {
            globals.max_xid = snapshots[i].xid;
            printf("Snapshot %zu/%zu: XID = %#" PRIx64 " | name = %s\n", i + 1, snapshot_count, (uint64_t)snapshots[i].xid, snapshots[i].name);
            int result = list_entrypoint(fs_omap_btree, fs_root_btree, &options);
            if (result != 0) {
                for (size_t j = 0; j < snapshot_count; j++) {
                    free(snapshots[j].name);
                }
                free(snapshots);
                return result;
            }
            printf("\n");
        }
        for (size_t i = 0; i < snapshot_count; i++) {
            free(snapshots[i].name);
        }
        free(snapshots);
    } else {
        int result = list_entrypoint(fs_omap_btree, fs_root_btree, &options);
        if (result != 0) {
            return result;
        }
    }
    free(fs_omap_btree);
    free(fs_omap);
    free(apsb);
    free(nx_omap_btree);
    free(nx_omap);
    free(nxsb);
    close_container();
    return 0;
}
