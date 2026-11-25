/*
 * OpenRAR - Clean-Room RAR 5.0 Command-Line Interface (CLI)
 * Replicates the official WinRAR CLI (Rar.exe) and unrar-free CLI interface
 * without any proprietary code or registration/activation mechanism.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_CLI_H
#define OPENRAR_CLI_H

#include "rar_archive.h"
#include <cstdint>
#include <string>
#include <vector>

namespace openrar {

struct CliConfig {
    // Primary command ("a", "x", "e", "l", "lt", "lta", "lb", "v", "vt", "vta", "vb",
    // "t", "p", "d", "rn", "c", "cw", "k", "r", "rc", "rr", "rv", "s", "s-", "u", "f",
    // "m", "mf", "ch", "i")
    std::string command;
    std::string find_str;           // For i[par]=<str>
    std::string find_params;        // Modifiers for i[par]=<str> (c, i, h, t)

    // Archive options
    RarArchiveOptions arch_opts;

    // Switches
    bool show_help = false;         // -?, -h, --help
    bool show_version = false;      // -iver, --version, -V
    bool recurse = false;           // -r
    bool recurse_wildcard = false;  // -r0
    bool disable_recurse = false;   // -r-
    bool assume_yes = false;        // -y
    int  overwrite_mode = 0;        // 0 = prompt, 1 = overwrite (-o+), -1 = skip (-o-)
    bool auto_rename = false;       // -or
    bool delete_after = false;      // -df, -dr, -dw, or command m/mf
    bool move_files_only = false;   // command mf
    bool test_after_archive = false;// -t
    bool keep_broken = false;       // -kb
    bool clear_archive_attr = false;// -ac
    bool ignore_attributes = false; // -ai
    bool no_empty_dirs = false;     // -ed
    bool disable_sort = false;      // -ds
    bool sync_archive = false;      // -as
    bool keep_archive_time = false; // -tk
    bool latest_archive_time = false;// -tl
    bool disable_comments = false;  // -c-
    int  case_convert = 0;          // 0 = none, 1 = lower (-cl), 2 = upper (-cu)
    int  ep_mode = 1;               // 0 = -ep (no paths), 1 = -ep1 (default strip base), 2 = -ep2 (full), 3 = -ep3
    std::string ep4_prefix;         // -ep4<path>
    std::string ap_prefix;          // -ap<path>
    std::string op_path;            // -op<path>
    std::string work_dir;           // -w<path>
    int  append_arch_dir = 0;       // -ad (1 = subdir, 2 = direct)
    bool create_sfx = false;        // -sfx[name]
    std::string sfx_stub_name;
    std::string comment_file;       // -z[file]
    std::string log_file;           // -ilog[name], -log[=name]
    bool read_from_stdin = false;   // -si[name]
    std::string stdin_name;         // name for -si
    std::string ag_format;          // -ag[format]
    bool version_control = false;   // -ver[n]
    int  max_versions = 0;          // n in -ver[n]
    bool disable_lists = false;     // -@
    bool freshen_switch = false;    // -f
    bool update_switch = false;     // -u
    bool wipe_after = false;        // -dw
    bool recycle_after = false;     // -dr
    bool save_symlinks = false;     // -ol
    bool save_hardlinks = false;    // -oh
    bool save_owner = false;        // -ow
    bool archive_attr_only = false; // -ao
    bool open_shared = false;       // -dh
    bool allow_incompatible = false;// -oni
    bool ntfs_compress = false;     // -oc
    bool pause_volumes = false;     // -vp
    bool beep_when_done = false;    // -isnd
    int  power_off = 0;             // -ioff[n], 0 = do not
    std::string email_to;           // -ieml[addr]
    int  threads = 0;               // -mt, 0 = hardware default
    int  priority = -1;             // -ri
    int  sleep_ms = 0;
    int  solid_files = 0;           // -s<N>, 0 = one solid group
    bool solid_by_extension = false;// -se
    bool independent_volumes = false;// -sv
    bool extract_newer = false;     // --extract-newer
    bool prompt_password = false;   // bare -p / -hp
    char charset = 0;               // -sc: 0, 'u', 'a', 'o'
    std::string charset_objects;
    bool method_explicit = false;
    bool solid_explicit = false;
    int  recovery_volumes = 0;      // -rv / rv command
    int  format_version = 5;        // -ma4 / -ma5

    // File filtering switches
    uint64_t size_less = 0;         // -sl<size> (0 = disabled)
    uint64_t size_more = 0;         // -sm<size> (0 = disabled)
    uint64_t time_after = 0;        // -ta<d> (winft, 0 = disabled)
    uint64_t time_before = 0;       // -tb<d> (winft, 0 = disabled)
    uint64_t time_newer_sec = 0;    // -tn<t>
    uint64_t time_older_sec = 0;    // -to<t>
    std::vector<std::string> include_masks; // -n<mask>
    std::vector<std::string> exclude_masks; // -x<mask>
    std::vector<std::string> store_exts;    // -ms[ext;ext]

    // Message suppression (-id[c,d,n,p,q], -inul, -ierr)
    bool quiet_copyright = false;   // -idc
    bool quiet_done = false;        // -idd
    bool quiet_names = false;       // -idn
    bool quiet_percent = false;     // -idp
    bool quiet_all = false;         // -inul
    bool quiet_mode = false;        // -idq
    bool msg_to_stderr = false;     // -ierr

    // Positional arguments
    std::string archive_path;
    std::vector<std::string> file_args;
    std::string dest_dir;
};

class CliRunner {
public:
    static int run(int argc, const std::vector<std::string>& args);
};

} // namespace openrar

#endif // OPENRAR_CLI_H
