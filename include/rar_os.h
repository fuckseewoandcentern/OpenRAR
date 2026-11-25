/*
 * OpenRAR - Small OS helpers for Windows, Linux, macOS and BSD.
 * Archive bytes stay platform-neutral; this file only touches the host.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_OS_H
#define OPENRAR_OS_H

#include <cstdint>
#include <string>
#include <vector>

namespace openrar {

struct OsFileInfo {
    uint64_t mtime_winft = 0;
    uint64_t ctime_winft = 0;
    uint64_t atime_winft = 0;
    uint64_t attributes = 0;     // Windows file attributes, or Unix st_mode
    uint64_t host_os = 0;        // HOST5_WINDOWS or HOST5_UNIX
    bool is_dir = false;
    bool is_symlink = false;
    std::string link_target;
    bool has_owner = false;
    uint32_t uid = 0;
    uint32_t gid = 0;
    std::string user;
    std::string group;
    uint64_t nlink = 1;
    uint64_t inode = 0;
    uint64_t dev = 0;
    bool archive_bit = true;     // Windows FILE_ATTRIBUTE_ARCHIVE; always true elsewhere
};

// Absolute path of the running executable, or empty if it cannot be resolved.
std::string executable_path();

std::string path_dirname(const std::string& path);
std::string path_join(const std::string& dir, const std::string& name);

// Configuration files, lowest priority first (later files override earlier ones).
std::vector<std::string> config_file_candidates(const std::string& exe_path);

bool read_file_bytes(const std::string& utf8_path, std::vector<uint8_t>& out, bool shared);
bool get_file_info(const std::string& utf8_path, OsFileInfo& info);

// Restore mtime/atime, permissions, and optionally owner. Missing privileges are not fatal.
bool apply_file_info(const std::string& utf8_path, const OsFileInfo& info,
                     bool restore_attr, bool restore_owner, bool clear_archive_bit,
                     bool ntfs_compress);

bool create_symlink_utf8(const std::string& target, const std::string& link_path, bool directory);
bool create_hardlink_utf8(const std::string& existing, const std::string& link_path);

bool move_to_trash(const std::string& utf8_path);
bool wipe_file(const std::string& utf8_path);
bool make_executable(const std::string& utf8_path);
void clear_archive_attribute(const std::string& utf8_path);

void set_binary_stdio(bool stdin_bin, bool stdout_bin);
bool stdin_is_tty();
std::string prompt_line(const std::string& prompt, bool hidden);

void set_process_priority(int level_0_to_15);
void beep();
// 1 power off, 2 hibernate, 3 sleep, 4 reboot. Returns false if the OS refuses.
bool request_power_action(int kind);

// Open a mail composer. Does not talk to a network server itself.
bool open_mail_composer(const std::string& address, const std::string& attachment);

// charset: 'u' UTF-8, 'a' ANSI/locale, 'o' OEM. Other values are returned unchanged.
std::string decode_text(const std::string& bytes, char charset);

std::string getenv_utf8(const char* name);

} // namespace openrar

#endif
