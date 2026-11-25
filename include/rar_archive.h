/*
 * OpenRAR - Clean-Room RAR 5.0 Archive Container Reader, Writer & Modifier
 * Supports RAR 5.0 headers, extra areas (Encryption, BLAKE2sp, High-Precision Time,
 * Version, Redirection), Solid archives, Multi-volume archives, SFX, Comments,
 * Quick Open, and Recovery Records.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_ARCHIVE_H
#define OPENRAR_ARCHIVE_H

#include "rar_defs.h"
#include "rar_crypto.h"
#include "rar_codec.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace openrar {

struct RarFileEntry {
    std::string name;             // UTF-8 path using '/' separator internally
    bool        is_dir = false;
    uint64_t    unpacked_size = 0;
    uint64_t    packed_size = 0;
    uint64_t    attributes = 0x20; // Windows FILE_ATTRIBUTE_ARCHIVE default
    uint64_t    host_os = HOST5_WINDOWS;

    // Timestamps (Windows FILETIME: 100ns intervals since 1601-01-01 UTC)
    uint64_t    mtime_winft = 0;
    uint64_t    ctime_winft = 0;
    uint64_t    atime_winft = 0;
    uint32_t    mtime_unix = 0;
    bool        has_unix_mtime = false;

    // Checksums
    bool        has_crc32 = true;
    uint32_t    crc32 = 0;        // Plain or tweaked CRC32 stored in header
    bool        has_blake2sp = false;
    uint8_t     blake2sp[32] = {0};

    // Compression info
    int         comp_version = 0; // 0 = v50
    int         comp_method = 3;  // 0..5
    int         dict_bits = 0;    // 0 = 128KB, 1 = 256KB, ...
    bool        solid = false;

    // Encryption info (per-file EX_CRYPT)
    bool        encrypted = false;
    uint64_t    crypt_flags = CFL5_PSWCHECK | CFL5_TWEAKED;
    uint8_t     kdf_count = 15;
    uint8_t     salt[16] = {0};
    uint8_t     iv[16] = {0};
    uint8_t     check_value[12] = {0};

    // Versioning (EX_VERSION)
    bool        has_version = false;
    uint64_t    version_num = 0;

    // Redirection (EX_REDIR)
    uint64_t    redir_type = REDIR5_NONE;
    uint64_t    redir_flags = 0;
    std::string redir_target;

    // Unix owner (EX_UOWNER, 0x06). Names are UTF-8.
    bool        has_owner = false;
    std::string owner_user;
    std::string owner_group;
    uint32_t    owner_uid = 0;
    uint32_t    owner_gid = 0;

    // Raw packed (and possibly encrypted) payload bytes
    std::vector<uint8_t> packed_data;
};

struct RarArchiveOptions {
    int         method = 3;               // -m0..5
    int         dict_bits = 0;            // -md (0 = 128KB default)
    bool        solid = false;            // -s
    bool        use_blake2sp = false;     // -htb
    bool        lock_archive = false;     // -k
    bool        quick_open = false;       // -qo+
    int         recovery_percent = 0;     // -rr[N]
    uint64_t    volume_size = 0;          // -v<size>
    std::string password;                 // -p[pwd] or -hp[pwd]
    bool        encrypt_headers = false;  // -hp[pwd]
    bool        save_ctime = false;       // -tsc
    bool        save_atime = false;       // -tsa
    bool        omit_endarc = false;      // -en (final volume only)
    bool        old_volume_names = false; // -vn
};

// Optional metadata supplied when a file is added from memory.
struct RarEntryExtra {
    bool        host_os_set = false;
    uint64_t    host_os = HOST5_WINDOWS;
    uint64_t    redir_type = REDIR5_NONE;
    std::string redir_target;
    bool        has_owner = false;
    std::string owner_user;
    std::string owner_group;
    uint32_t    owner_uid = 0;
    uint32_t    owner_gid = 0;
};

class RarArchive {
public:
    std::vector<uint8_t>      sfx_stub;
    bool                      is_solid = false;
    bool                      is_locked = false;
    bool                      is_volume = false;
    bool                      has_recovery = false;
    bool                      headers_encrypted = false;
    uint8_t                   hdr_kdf_count = 15;
    uint8_t                   hdr_salt[16] = {0};
    uint8_t                   hdr_check[12] = {0};
    std::string               comment;
    std::vector<RarFileEntry> entries;
    std::vector<uint8_t>      recovery_data;

    // Return false to abort before a volume file is written (-vp).
    std::function<bool(const std::string& volume_path)> before_volume;

    // Load a RAR 5.0 archive from disk (automatically resolves multi-volume sets)
    RarExitCode load(const std::string& path, const std::string& password = "", std::string* err_msg = nullptr);

    // Save the RAR 5.0 archive to disk (supports single-file and multi-volume output)
    RarExitCode save(const std::string& path, const RarArchiveOptions& opts,
                     std::vector<std::string>* created_volumes = nullptr,
                     std::string* err_msg = nullptr);

    // Compress and add/replace a file or directory entry in memory
    bool add_entry_from_memory(const std::string& internal_name,
                               const uint8_t* raw_data, size_t raw_len,
                               bool is_dir, uint64_t attributes,
                               uint64_t mtime_winft, uint64_t ctime_winft, uint64_t atime_winft,
                               const RarArchiveOptions& opts,
                               Rar5Compressor& compressor,
                               bool solid_continuation,
                               const RarEntryExtra* extra = nullptr);

    // Compress one file without inserting it. Safe to call on separate archives/compressors in parallel.
    RarFileEntry build_entry_from_memory(const std::string& internal_name,
                                         const uint8_t* raw_data, size_t raw_len,
                                         bool is_dir, uint64_t attributes,
                                         uint64_t mtime_winft, uint64_t ctime_winft, uint64_t atime_winft,
                                         const RarArchiveOptions& opts,
                                         Rar5Compressor& compressor,
                                         bool solid_continuation,
                                         const RarEntryExtra* extra = nullptr) const;

    bool commit_entry(RarFileEntry entry);

    // Extract & verify a single entry (`entries[index]`) using `decompressor`
    RarExitCode extract_entry(size_t index, const std::string& password,
                              Rar5Decompressor& decompressor,
                              std::vector<uint8_t>& out_data,
                              std::string* err_msg = nullptr) const;

    // Repair a potentially damaged archive by scanning for valid RAR5 blocks/headers
    // and applying recovery parity if present.
    static RarExitCode repair_archive(const std::string& src_path, const std::string& dst_path,
                                      const std::string& password,
                                      std::vector<std::string>& found_names,
                                      bool& used_recovery_record);

    // Create an SFX stub from this executable (or a caller-supplied stub file).
    static std::vector<uint8_t> create_default_sfx_stub(const std::string& self_exe_path);
};

// Volume names. index is 1-based. old_style uses name.rar, name.r00, name.r01, ...
std::string make_volume_name(const std::string& base_path, size_t index_1based, bool old_style);

// If `any_path` is a later volume and the first volume exists, return the first volume.
std::string locate_first_volume(const std::string& any_path);

// Reed-Solomon recovery volumes (.rev) over the raw volume files.
bool write_recovery_volumes(const std::vector<std::string>& data_volumes, int parity_count,
                            bool old_style, std::vector<std::string>& created, std::string* err);
bool reconstruct_missing_volumes(const std::string& any_path,
                                 std::vector<std::string>& restored, std::string* err);

// Time conversion helpers between Unix time_t / std::filesystem and Windows FILETIME
uint64_t unix_to_win_filetime(int64_t unix_sec, uint32_t nsec = 0);
void win_filetime_to_unix(uint64_t winft, int64_t& unix_sec, uint32_t& nsec);
uint64_t current_win_filetime();

} // namespace openrar

#endif // OPENRAR_ARCHIVE_H
