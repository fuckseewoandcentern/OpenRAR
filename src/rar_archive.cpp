/*
 * OpenRAR - Clean-Room RAR 5.0 Archive Container Reader, Writer & Modifier
 * Supports RAR 5.0 headers, extra areas (Encryption, BLAKE2sp, High-Precision Time,
 * Version, Redirection), Solid archives, Multi-volume archives, SFX, Comments,
 * Quick Open, and Recovery Records.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_archive.h"
#include "rar_i18n.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace openrar {

// ============================================================================
// UTF-8 Path & File I/O Helpers
// ============================================================================

static fs::path u8_to_path(const std::string& utf8_str) {
#if defined(_MSC_VER) && _MSVC_LANG >= 202002L
    return fs::path( std::u8string(reinterpret_cast<const char8_t*>(utf8_str.data()), utf8_str.size()) );
#else
    return fs::u8path(utf8_str);
#endif
}

static bool read_file_bytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream ifs(u8_to_path(path), std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    std::streamsize sz = ifs.tellg();
    if (sz < 0) return false;
    out.resize(static_cast<size_t>(sz));
    ifs.seekg(0, std::ios::beg);
    if (sz > 0 && !ifs.read(reinterpret_cast<char*>(out.data()), sz)) return false;
    return true;
}

static bool write_file_bytes(const std::string& path, const uint8_t* data, size_t len) {
    fs::path p = u8_to_path(path);
    if (p.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
    }
    std::ofstream ofs(p, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    if (len > 0 && !ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len))) {
        return false;
    }
    return true;
}

// ============================================================================
// Timestamp Conversion Helpers (Windows FILETIME <-> Unix time)
// ============================================================================

static constexpr uint64_t EPOCH_DIFF_100NS = 116444736000000000ULL;

uint64_t unix_to_win_filetime(int64_t unix_sec, uint32_t nsec) {
    if (unix_sec < 0) return EPOCH_DIFF_100NS;
    return static_cast<uint64_t>(unix_sec) * 10000000ULL + (nsec / 100U) + EPOCH_DIFF_100NS;
}

void win_filetime_to_unix(uint64_t winft, int64_t& unix_sec, uint32_t& nsec) {
    if (winft < EPOCH_DIFF_100NS) {
        unix_sec = 0;
        nsec = 0;
        return;
    }
    uint64_t diff = winft - EPOCH_DIFF_100NS;
    unix_sec = static_cast<int64_t>(diff / 10000000ULL);
    nsec = static_cast<uint32_t>((diff % 10000000ULL) * 100ULL);
}

uint64_t current_win_filetime() {
    auto now = std::chrono::system_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    int64_t sec = ns / 1000000000LL;
    uint32_t rem_ns = static_cast<uint32_t>(ns % 1000000000LL);
    return unix_to_win_filetime(sec, rem_ns);
}

// ============================================================================
// RAR 5.0 Block Construction Helpers
// ============================================================================

static std::vector<uint8_t> build_raw_rar5_block(uint64_t htype, uint64_t hflags,
                                                 const std::vector<uint8_t>& body,
                                                 const std::vector<uint8_t>& extra = {},
                                                 const std::vector<uint8_t>& data = {},
                                                 bool has_data_flag_override = false,
                                                 uint64_t data_size_override = 0,
                                                 int data_size_min_vint = 1) {
    if (!extra.empty()) hflags |= HFL5_EXTRA_DATA;
    if (!data.empty() || has_data_flag_override) hflags |= HFL5_DATA;

    std::vector<uint8_t> hdr_payload;
    write_vint(hdr_payload, htype);
    write_vint(hdr_payload, hflags);
    if (hflags & HFL5_EXTRA_DATA) {
        write_vint(hdr_payload, extra.size());
    }
    if (hflags & HFL5_DATA) {
        uint64_t dsz = has_data_flag_override ? data_size_override : data.size();
        write_vint(hdr_payload, dsz, data_size_min_vint);
    }
    hdr_payload.insert(hdr_payload.end(), body.begin(), body.end());
    if (!extra.empty()) {
        hdr_payload.insert(hdr_payload.end(), extra.begin(), extra.end());
    }

    std::vector<uint8_t> hsize_vint = encode_vint(hdr_payload.size());
    std::vector<uint8_t> crc_input = hsize_vint;
    crc_input.insert(crc_input.end(), hdr_payload.begin(), hdr_payload.end());
    uint32_t crc = crc32_compute(crc_input.data(), crc_input.size());

    std::vector<uint8_t> out;
    out.reserve(4 + crc_input.size() + data.size());
    write_u32_le(out, crc);
    out.insert(out.end(), crc_input.begin(), crc_input.end());
    if (!data.empty()) {
        out.insert(out.end(), data.begin(), data.end());
    }
    return out;
}

static std::vector<uint8_t> build_possibly_encrypted_block(
    bool encrypt_headers, const uint8_t hdr_aes_key[32],
    uint64_t htype, uint64_t hflags,
    const std::vector<uint8_t>& body,
    const std::vector<uint8_t>& extra = {},
    const std::vector<uint8_t>& data = {},
    bool has_data_flag_override = false,
    uint64_t data_size_override = 0,
    int data_size_min_vint = 1) {

    if (!encrypt_headers) {
        return build_raw_rar5_block(htype, hflags, body, extra, data,
                                    has_data_flag_override, data_size_override, data_size_min_vint);
    }

    // Build header without data first, encrypt header with fresh 16-byte IV, then append data
    std::vector<uint8_t> hdr_only = build_raw_rar5_block(
        htype, hflags, body, extra, {},
        !data.empty() || has_data_flag_override,
        has_data_flag_override ? data_size_override : data.size(),
        data_size_min_vint
    );
    uint8_t iv[16];
    random_bytes(iv, 16);
    std::vector<uint8_t> enc_hdr = aes256_cbc_encrypt(hdr_only.data(), hdr_only.size(), hdr_aes_key, iv);

    std::vector<uint8_t> out;
    out.reserve(16 + enc_hdr.size() + data.size());
    out.insert(out.end(), iv, iv + 16);
    out.insert(out.end(), enc_hdr.begin(), enc_hdr.end());
    if (!data.empty()) {
        out.insert(out.end(), data.begin(), data.end());
    }
    return out;
}

// A RAR 5 header stores CRC32 as 4 raw little-endian bytes, then a vint size
// and a vint type. Used to ignore accidental 8-byte signature matches.
static bool rar5_block_follows(const uint8_t* data, size_t len, size_t sig_pos, uint64_t* htype_out) {
    if (sig_pos + 12 > len) return false;
    size_t off = sig_pos + 8 + 4;
    uint64_t hsize = 0;
    uint64_t htype = 0;
    if (!read_vint(data, len, off, hsize)) return false;
    if (hsize < 2 || hsize > (1024ULL * 1024ULL)) return false;
    if (off + static_cast<size_t>(hsize) > len) return false;
    if (!read_vint(data, len, off, htype)) return false;
    if (htype > HEAD5_ENDARC) return false;
    if (htype_out) *htype_out = htype;
    return true;
}

// ============================================================================
// Multi-Volume Filename Helper
// ============================================================================

static std::string strip_volume_suffix(std::string p) {
    auto lower_tail = [](const std::string& s, size_t n) {
        if (s.size() < n) return std::string();
        std::string t = s.substr(s.size() - n);
        for (char& c : t) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return t;
    };
    std::string tail4 = lower_tail(p, 4);
    if (tail4 == ".rar" || tail4 == ".exe" || tail4 == ".sfx") {
        p = p.substr(0, p.size() - 4);
    }
    // name.partN
    size_t dot_pos = p.rfind(".part");
    if (dot_pos != std::string::npos) {
        bool all_digits = (dot_pos + 5 < p.size());
        for (size_t i = dot_pos + 5; i < p.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(p[i]))) all_digits = false;
        }
        if (all_digits && dot_pos + 5 < p.size()) p = p.substr(0, dot_pos);
    }
    // old style name.rNN
    if (p.size() >= 4 && p[p.size() - 4] == '.' && (p[p.size() - 3] == 'r' || p[p.size() - 3] == 'R') &&
        std::isdigit(static_cast<unsigned char>(p[p.size() - 2])) &&
        std::isdigit(static_cast<unsigned char>(p[p.size() - 1]))) {
        p = p.substr(0, p.size() - 4);
    }
    return p;
}

std::string make_volume_name(const std::string& base_path, size_t index_1based, bool old_style) {
    std::string stem = strip_volume_suffix(base_path);
    if (index_1based == 0) index_1based = 1;
    if (old_style) {
        if (index_1based == 1) return stem + ".rar";
        char buf[16];
        std::snprintf(buf, sizeof(buf), ".r%02u", (unsigned)(index_1based - 2));
        return stem + buf;
    }
    return stem + ".part" + std::to_string(index_1based) + ".rar";
}

std::string locate_first_volume(const std::string& any_path) {
    std::string stem = strip_volume_suffix(any_path);
    std::string part1 = stem + ".part1.rar";
    std::string old1 = stem + ".rar";
    if (fs::exists(u8_to_path(part1))) return part1;
    if (fs::exists(u8_to_path(old1)) && old1 != any_path) {
        // Only rewind when the given path looks like a later old-style volume.
        std::string low = any_path;
        for (char& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (low.size() >= 4 && low[low.size() - 4] == '.' && low[low.size() - 3] == 'r' &&
            std::isdigit(static_cast<unsigned char>(low[low.size() - 2]))) {
            return old1;
        }
    }
    if (fs::exists(u8_to_path(part1))) return part1;
    return any_path;
}

// ============================================================================
// RarArchive::load Implementation
// ============================================================================

RarExitCode RarArchive::load(const std::string& path, const std::string& password, std::string* err_msg) {
    sfx_stub.clear();
    is_solid = false;
    is_locked = false;
    is_volume = false;
    has_recovery = false;
    headers_encrypted = false;
    comment.clear();
    entries.clear();
    recovery_data.clear();

    const std::string start_path = locate_first_volume(path);

    // Check if this is part of a multi-volume set
    std::vector<std::string> vol_paths;
    vol_paths.push_back(start_path);

    uint8_t sig5[8];
    get_rar5_signature(sig5);
    uint8_t sig4[7];
    get_rar4_signature(sig4);

    Rar5KeyMaterial hdr_keys{};
    bool hdr_keys_ready = false;

    for (size_t v_idx = 0; v_idx < vol_paths.size(); ++v_idx) {
        std::vector<uint8_t> raw;
        if (!read_file_bytes(vol_paths[v_idx], raw)) {
            if (err_msg) *err_msg = msgf("arc.cannot_open", vol_paths[v_idx]);
            return RAR_EXIT_OPEN_ERROR;
        }

        // Locate a RAR5 signature that is followed by a real header.
        // A bare 8-byte match inside an SFX stub is ignored.
        size_t sig_pos = std::string::npos;
        if (raw.size() >= 8) {
            for (size_t i = 0; i + 8 <= raw.size(); ++i) {
                if (std::memcmp(raw.data() + i, sig5, 8) != 0) continue;
                uint64_t htype = 0;
                if (!rar5_block_follows(raw.data(), raw.size(), i, &htype)) continue;
                if (htype != HEAD5_MAIN && htype != HEAD5_CRYPT) continue;
                sig_pos = i;
                break;
            }
        }
        if (sig_pos == std::string::npos) {
            // Check RAR 4.x signature for clearer error message
            if (raw.size() >= 7 && std::memcmp(raw.data(), sig4, 7) == 0) {
                if (err_msg) *err_msg = msg("arc.rar4");
            } else {
                if (err_msg) *err_msg = msgf("arc.not_rar", vol_paths[v_idx]);
            }
            return RAR_EXIT_FATAL;
        }

        if (v_idx == 0 && sig_pos > 0) {
            sfx_stub.assign(raw.begin(), raw.begin() + sig_pos);
        }

        size_t pos = sig_pos + 8;
        bool vol_headers_encrypted = false;

        while (pos < raw.size()) {
            const uint8_t* blk_ptr = nullptr;
            size_t blk_avail = 0;
            std::vector<uint8_t> dec_hdr_buf;
            size_t raw_pos_before_hdr = pos;

            if (vol_headers_encrypted) {
                if (pos + 32 > raw.size()) break;
                const uint8_t* iv = raw.data() + pos;
                pos += 16;
                // Decrypt first 16 bytes to inspect CRC32 and Header size vint
                std::vector<uint8_t> first_blk = aes256_cbc_decrypt(raw.data() + pos, 16, hdr_keys.aes_key, iv);
                size_t tmp_off = 4;
                uint64_t raw_hsize = 0;
                if (!read_vint(first_blk.data(), first_blk.size(), tmp_off, raw_hsize)) {
                    if (err_msg) *err_msg = msg("arc.bad_enc_hdr");
                    return RAR_EXIT_BAD_PASSWORD;
                }
                size_t total_hdr_plain = tmp_off + static_cast<size_t>(raw_hsize);
                size_t total_hdr_aligned = (total_hdr_plain + 15) & ~size_t(15);
                if (pos + total_hdr_aligned > raw.size()) {
                    if (err_msg) *err_msg = msg("arc.trunc_enc");
                    return RAR_EXIT_FATAL;
                }
                dec_hdr_buf = aes256_cbc_decrypt(raw.data() + pos, total_hdr_aligned, hdr_keys.aes_key, iv);
                pos += total_hdr_aligned;
                blk_ptr = dec_hdr_buf.data();
                blk_avail = dec_hdr_buf.size();
            } else {
                blk_ptr = raw.data() + pos;
                blk_avail = raw.size() - pos;
            }

            if (blk_avail < 7) break;
            uint32_t expected_crc = read_u32_le(blk_ptr);
            size_t h_off = 4;
            uint64_t hdr_size = 0;
            if (!read_vint(blk_ptr, blk_avail, h_off, hdr_size)) {
                if (err_msg) *err_msg = msg("arc.bad_hdr_size");
                return RAR_EXIT_CRC_ERROR;
            }
            size_t hdr_size_vint_len = h_off - 4;
            if (h_off + hdr_size > blk_avail) {
                if (err_msg) *err_msg = msg("arc.unexpected_end");
                return RAR_EXIT_FATAL;
            }

            uint32_t calc_crc = crc32_compute(blk_ptr + 4, hdr_size_vint_len + static_cast<size_t>(hdr_size));
            if (calc_crc != expected_crc) {
                if (err_msg) *err_msg = msg("arc.bad_hdr_crc");
                return vol_headers_encrypted ? RAR_EXIT_BAD_PASSWORD : RAR_EXIT_CRC_ERROR;
            }

            size_t body_end = h_off + static_cast<size_t>(hdr_size);
            if (!vol_headers_encrypted) {
                pos += body_end;
            }

            uint64_t htype = 0, hflags = 0;
            if (!read_vint(blk_ptr, body_end, h_off, htype) ||
                !read_vint(blk_ptr, body_end, h_off, hflags)) {
                return RAR_EXIT_FATAL;
            }

            uint64_t extra_size = 0, data_size = 0;
            if (hflags & HFL5_EXTRA_DATA) {
                if (!read_vint(blk_ptr, body_end, h_off, extra_size)) return RAR_EXIT_FATAL;
            }
            if (hflags & HFL5_DATA) {
                if (!read_vint(blk_ptr, body_end, h_off, data_size)) return RAR_EXIT_FATAL;
            }

            bool split_before = (hflags & HFL5_SPLIT_BEFORE) != 0;
            bool split_after  = (hflags & HFL5_SPLIT_AFTER) != 0;
            (void)raw_pos_before_hdr;

            if (htype == HEAD5_CRYPT) {
                uint64_t enc_ver = 0, enc_flags = 0;
                if (!read_vint(blk_ptr, body_end, h_off, enc_ver) ||
                    !read_vint(blk_ptr, body_end, h_off, enc_flags)) {
                    return RAR_EXIT_FATAL;
                }
                if (h_off + 17 > body_end) return RAR_EXIT_FATAL;
                hdr_kdf_count = blk_ptr[h_off++];
                std::memcpy(hdr_salt, blk_ptr + h_off, 16);
                h_off += 16;
                if (enc_flags & CFL5_PSWCHECK) {
                    if (h_off + 12 > body_end) return RAR_EXIT_FATAL;
                    std::memcpy(hdr_check, blk_ptr + h_off, 12);
                    h_off += 12;
                }
                if (password.empty()) {
                    if (err_msg) *err_msg = msg("arc.need_password");
                    return RAR_EXIT_BAD_PASSWORD;
                }
                hdr_keys = derive_rar5_keys(password, hdr_salt, hdr_kdf_count);
                if ((enc_flags & CFL5_PSWCHECK) && !verify_rar5_password(hdr_keys, hdr_check)) {
                    if (err_msg) *err_msg = msg("arc.bad_password");
                    return RAR_EXIT_BAD_PASSWORD;
                }
                headers_encrypted = true;
                vol_headers_encrypted = true;
                hdr_keys_ready = true;
            } else if (htype == HEAD5_MAIN) {
                uint64_t mflags = 0;
                if (!read_vint(blk_ptr, body_end, h_off, mflags)) return RAR_EXIT_FATAL;
                if (mflags & MFL5_VOLUME) is_volume = true;
                if (mflags & MFL5_SOLID)  is_solid = true;
                if (mflags & MFL5_LOCK)   is_locked = true;
                if (mflags & MFL5_PROTECT) has_recovery = true;
                if (mflags & MFL5_VOLUME_NUMBER) {
                    uint64_t vno = 0;
                    read_vint(blk_ptr, body_end, h_off, vno);
                }
                if (pos + data_size <= raw.size()) pos += static_cast<size_t>(data_size);
            } else if (htype == HEAD5_FILE || htype == HEAD5_SERVICE) {
                size_t extra_start = body_end - static_cast<size_t>(extra_size);
                uint64_t fflags = 0, unp_size = 0, attr = 0, comp_info = 0, host_os = 0, name_len = 0;
                if (!read_vint(blk_ptr, extra_start, h_off, fflags) ||
                    !read_vint(blk_ptr, extra_start, h_off, unp_size) ||
                    !read_vint(blk_ptr, extra_start, h_off, attr)) {
                    return RAR_EXIT_FATAL;
                }
                uint32_t mtime_u32 = 0, crc_u32 = 0;
                if (fflags & FFL5_UTIME) {
                    if (h_off + 4 > extra_start) return RAR_EXIT_FATAL;
                    mtime_u32 = read_u32_le(blk_ptr + h_off);
                    h_off += 4;
                }
                if (fflags & FFL5_CRC32) {
                    if (h_off + 4 > extra_start) return RAR_EXIT_FATAL;
                    crc_u32 = read_u32_le(blk_ptr + h_off);
                    h_off += 4;
                }
                if (!read_vint(blk_ptr, extra_start, h_off, comp_info) ||
                    !read_vint(blk_ptr, extra_start, h_off, host_os) ||
                    !read_vint(blk_ptr, extra_start, h_off, name_len)) {
                    return RAR_EXIT_FATAL;
                }
                if (h_off + name_len > extra_start) return RAR_EXIT_FATAL;
                std::string name(reinterpret_cast<const char*>(blk_ptr + h_off), static_cast<size_t>(name_len));

                RarFileEntry entry{};
                entry.name = name;
                entry.is_dir = (fflags & FFL5_DIRECTORY) != 0;
                entry.unpacked_size = unp_size;
                entry.packed_size = data_size;
                entry.attributes = attr;
                entry.host_os = host_os;
                entry.has_unix_mtime = (fflags & FFL5_UTIME) != 0;
                entry.mtime_unix = mtime_u32;
                if (entry.has_unix_mtime) {
                    entry.mtime_winft = unix_to_win_filetime(mtime_u32, 0);
                }
                entry.has_crc32 = (fflags & FFL5_CRC32) != 0;
                entry.crc32 = crc_u32;
                entry.comp_version = static_cast<int>(comp_info & 0x3F);
                entry.solid = (comp_info & 0x40) != 0;
                entry.comp_method = static_cast<int>((comp_info >> 7) & 0x07);
                entry.dict_bits = static_cast<int>((comp_info >> 10) & 0x1F);

                // Parse Extra Area records
                size_t e_off = extra_start;
                while (e_off < body_end) {
                    uint64_t rec_size = 0, rec_type = 0;
                    if (!read_vint(blk_ptr, body_end, e_off, rec_size)) break;
                    size_t rec_end = e_off + static_cast<size_t>(rec_size);
                    if (rec_end > body_end) break;
                    if (!read_vint(blk_ptr, rec_end, e_off, rec_type)) break;

                    if (rec_type == FEXT5_CRYPT) {
                        uint64_t cver = 0, cflags = 0;
                        if (read_vint(blk_ptr, rec_end, e_off, cver) &&
                            read_vint(blk_ptr, rec_end, e_off, cflags) &&
                            e_off + 33 <= rec_end) {
                            entry.encrypted = true;
                            entry.crypt_flags = cflags;
                            entry.kdf_count = blk_ptr[e_off++];
                            std::memcpy(entry.salt, blk_ptr + e_off, 16);
                            e_off += 16;
                            std::memcpy(entry.iv, blk_ptr + e_off, 16);
                            e_off += 16;
                            if ((cflags & CFL5_PSWCHECK) && e_off + 12 <= rec_end) {
                                std::memcpy(entry.check_value, blk_ptr + e_off, 12);
                            }
                        }
                    } else if (rec_type == FEXT5_HASH) {
                        uint64_t htype_id = 0;
                        if (read_vint(blk_ptr, rec_end, e_off, htype_id) && htype_id == 0 && e_off + 32 <= rec_end) {
                            entry.has_blake2sp = true;
                            std::memcpy(entry.blake2sp, blk_ptr + e_off, 32);
                        }
                    } else if (rec_type == FEXT5_HTIME) {
                        uint64_t tflags = 0;
                        if (read_vint(blk_ptr, rec_end, e_off, tflags)) {
                            bool is_unix = (tflags & HTIME5_UNIX_TIME) != 0;
                            bool has_ns  = is_unix && ((tflags & HTIME5_UNIX_NS) != 0);
                            int64_t m_sec = 0, c_sec = 0, a_sec = 0;
                            uint32_t m_ns = 0, c_ns = 0, a_ns = 0;
                            auto rd_t = [&](uint64_t& wft, int64_t& sec) {
                                if (is_unix) {
                                    if (e_off + 4 <= rec_end) {
                                        sec = read_u32_le(blk_ptr + e_off);
                                        e_off += 4;
                                        wft = unix_to_win_filetime(sec, 0);
                                    }
                                } else {
                                    if (e_off + 8 <= rec_end) {
                                        wft = read_u64_le(blk_ptr + e_off);
                                        e_off += 8;
                                    }
                                }
                            };
                            if (tflags & HTIME5_MTIME) rd_t(entry.mtime_winft, m_sec);
                            if (tflags & HTIME5_CTIME) rd_t(entry.ctime_winft, c_sec);
                            if (tflags & HTIME5_ATIME) rd_t(entry.atime_winft, a_sec);
                            if (has_ns) {
                                if ((tflags & HTIME5_MTIME) && e_off + 4 <= rec_end) {
                                    m_ns = read_u32_le(blk_ptr + e_off); e_off += 4;
                                    entry.mtime_winft = unix_to_win_filetime(m_sec, m_ns);
                                }
                                if ((tflags & HTIME5_CTIME) && e_off + 4 <= rec_end) {
                                    c_ns = read_u32_le(blk_ptr + e_off); e_off += 4;
                                    entry.ctime_winft = unix_to_win_filetime(c_sec, c_ns);
                                }
                                if ((tflags & HTIME5_ATIME) && e_off + 4 <= rec_end) {
                                    a_ns = read_u32_le(blk_ptr + e_off); e_off += 4;
                                    entry.atime_winft = unix_to_win_filetime(a_sec, a_ns);
                                }
                            }
                        }
                    } else if (rec_type == FEXT5_VERSION) {
                        uint64_t vflags = 0, vnum = 0;
                        if (read_vint(blk_ptr, rec_end, e_off, vflags) &&
                            read_vint(blk_ptr, rec_end, e_off, vnum)) {
                            entry.has_version = true;
                            entry.version_num = vnum;
                        }
                    } else if (rec_type == FEXT5_REDIR) {
                        uint64_t rtype = 0, rflags = 0, rlen = 0;
                        if (read_vint(blk_ptr, rec_end, e_off, rtype) &&
                            read_vint(blk_ptr, rec_end, e_off, rflags) &&
                            read_vint(blk_ptr, rec_end, e_off, rlen) &&
                            e_off + rlen <= rec_end) {
                            entry.redir_type = rtype;
                            entry.redir_flags = rflags;
                            entry.redir_target.assign(reinterpret_cast<const char*>(blk_ptr + e_off), static_cast<size_t>(rlen));
                        }
                    } else if (rec_type == FEXT5_UOWNER) {
                        uint64_t oflags = 0;
                        if (read_vint(blk_ptr, rec_end, e_off, oflags)) {
                            entry.has_owner = true;
                            if (oflags & 0x01) {
                                uint64_t nlen = 0;
                                if (read_vint(blk_ptr, rec_end, e_off, nlen) && e_off + nlen <= rec_end) {
                                    entry.owner_user.assign(reinterpret_cast<const char*>(blk_ptr + e_off), static_cast<size_t>(nlen));
                                    e_off += static_cast<size_t>(nlen);
                                }
                            }
                            if (oflags & 0x02) {
                                uint64_t nlen = 0;
                                if (read_vint(blk_ptr, rec_end, e_off, nlen) && e_off + nlen <= rec_end) {
                                    entry.owner_group.assign(reinterpret_cast<const char*>(blk_ptr + e_off), static_cast<size_t>(nlen));
                                    e_off += static_cast<size_t>(nlen);
                                }
                            }
                            uint64_t uid = 0, gid = 0;
                            if (oflags & 0x04) read_vint(blk_ptr, rec_end, e_off, uid);
                            if (oflags & 0x08) read_vint(blk_ptr, rec_end, e_off, gid);
                            entry.owner_uid = (uint32_t)uid;
                            entry.owner_gid = (uint32_t)gid;
                        }
                    }
                    e_off = rec_end;
                }

                // Read data area
                if (pos + data_size > raw.size()) {
                    if (err_msg) *err_msg = msg("arc.data_oob");
                    return RAR_EXIT_FATAL;
                }
                std::vector<uint8_t> chunk(raw.begin() + pos, raw.begin() + pos + static_cast<size_t>(data_size));
                pos += static_cast<size_t>(data_size);

                if (htype == HEAD5_SERVICE) {
                    if (name == "CMT") {
                        if (entry.encrypted && !password.empty()) {
                            Rar5KeyMaterial ck = derive_rar5_keys(password, entry.salt, entry.kdf_count);
                            std::vector<uint8_t> dec = aes256_cbc_decrypt(chunk.data(), chunk.size(), ck.aes_key, entry.iv);
                            if (dec.size() >= entry.unpacked_size) {
                                comment.assign(reinterpret_cast<const char*>(dec.data()), static_cast<size_t>(entry.unpacked_size));
                            }
                        } else if (entry.comp_method == 0) {
                            comment.assign(reinterpret_cast<const char*>(chunk.data()),
                                           std::min<size_t>(chunk.size(), static_cast<size_t>(entry.unpacked_size)));
                        } else {
                            Rar5Decompressor cmt_dec;
                            std::vector<uint8_t> cmt_out;
                            if (cmt_dec.decompress(chunk.data(), chunk.size(), entry.unpacked_size,
                                                   entry.comp_method, size_t(128 * 1024) << entry.dict_bits, false, cmt_out)) {
                                comment.assign(reinterpret_cast<const char*>(cmt_out.data()), cmt_out.size());
                            }
                        }
                    } else if (name == "RR" || name == "ORR") {
                        has_recovery = true;
                        recovery_data = std::move(chunk);
                    }
                } else {
                    if (split_before && !entries.empty() && entries.back().name == entry.name) {
                        entries.back().packed_data.insert(entries.back().packed_data.end(), chunk.begin(), chunk.end());
                        entries.back().packed_size += data_size;
                        if (!split_after) {
                            entries.back().crc32 = entry.crc32;
                            entries.back().has_crc32 = entry.has_crc32;
                            if (entry.has_blake2sp) {
                                entries.back().has_blake2sp = true;
                                std::memcpy(entries.back().blake2sp, entry.blake2sp, 32);
                            }
                        }
                    } else {
                        entry.packed_data = std::move(chunk);
                        entries.push_back(std::move(entry));
                    }
                }
            } else if (htype == HEAD5_ENDARC) {
                uint64_t eflags = 0;
                read_vint(blk_ptr, body_end, h_off, eflags);
                if ((eflags & EARC5_NEXT_VOLUME) && v_idx + 1 == vol_paths.size()) {
                    std::string next_vol = make_volume_name(start_path, v_idx + 2, false);
                    if (!fs::exists(u8_to_path(next_vol))) {
                        next_vol = make_volume_name(start_path, v_idx + 2, true);
                    }
                    if (fs::exists(u8_to_path(next_vol))) {
                        vol_paths.push_back(next_vol);
                    } else {
                        if (err_msg) *err_msg = msgf("arc.missing_vol", next_vol);
                        return RAR_EXIT_OPEN_ERROR;
                    }
                }
                break;
            } else {
                if (pos + data_size <= raw.size()) {
                    pos += static_cast<size_t>(data_size);
                } else {
                    break;
                }
            }
        }
    }
    (void)hdr_keys_ready;
    return RAR_EXIT_SUCCESS;
}

// ============================================================================
// RarArchive::add_entry_from_memory Implementation
// ============================================================================

RarFileEntry RarArchive::build_entry_from_memory(const std::string& internal_name,
                                                   const uint8_t* raw_data, size_t raw_len,
                                                   bool is_dir, uint64_t attributes,
                                                   uint64_t mtime_winft, uint64_t ctime_winft, uint64_t atime_winft,
                                                   const RarArchiveOptions& opts,
                                                   Rar5Compressor& compressor,
                                                   bool solid_continuation,
                                                   const RarEntryExtra* extra) const {
    RarFileEntry entry{};
    entry.name = internal_name;
    // Normalize backslashes to forward slashes as required by RAR 5.0 spec
    for (char& c : entry.name) {
        if (c == '\\') c = '/';
    }
    entry.is_dir = is_dir;
    entry.unpacked_size = is_dir ? 0 : raw_len;
    entry.attributes = attributes;
#if defined(_WIN32)
    entry.host_os = HOST5_WINDOWS;
#else
    entry.host_os = HOST5_UNIX;
#endif
    if (extra) {
        if (extra->host_os_set) entry.host_os = extra->host_os;
        entry.redir_type = extra->redir_type;
        entry.redir_target = extra->redir_target;
        entry.has_owner = extra->has_owner;
        entry.owner_user = extra->owner_user;
        entry.owner_group = extra->owner_group;
        entry.owner_uid = extra->owner_uid;
        entry.owner_gid = extra->owner_gid;
    }
    entry.mtime_winft = (mtime_winft != 0) ? mtime_winft : current_win_filetime();
    entry.ctime_winft = ctime_winft;
    entry.atime_winft = atime_winft;
    entry.comp_version = 0;
    entry.dict_bits = is_dir ? 0 : std::clamp(opts.dict_bits, 0, 15);
    entry.solid = (!is_dir && opts.solid && solid_continuation);

    // Compute plain checksums of unpacked data
    uint32_t plain_crc32 = crc32_compute(raw_data, is_dir ? 0 : raw_len);
    uint8_t plain_b2[32] = {0};
    if (opts.use_blake2sp && !is_dir) {
        blake2sp_compute(raw_data, raw_len, plain_b2);
    }

    // Compress data
    std::vector<uint8_t> comp_bytes;
    int actual_method = 0;
    if (!is_dir && raw_len > 0) {
        if (opts.method == 0) {
            actual_method = 0;
            comp_bytes.assign(raw_data, raw_data + raw_len);
        } else {
            size_t dict_sz = (size_t(128 * 1024) << entry.dict_bits);
            comp_bytes = compressor.compress(raw_data, raw_len, opts.method, dict_sz, entry.solid);
            if (!opts.solid && comp_bytes.size() >= raw_len) {
                // Like official Rar.exe, fall back to store (-m0) if non-solid and incompressible
                actual_method = 0;
                comp_bytes.assign(raw_data, raw_data + raw_len);
            } else {
                actual_method = std::clamp(opts.method, 1, 5);
            }
        }
    }
    entry.comp_method = actual_method;

    // Encrypt if password is provided
    if (!opts.password.empty() && !is_dir) {
        entry.encrypted = true;
        entry.kdf_count = 15;
        random_bytes(entry.salt, 16);
        random_bytes(entry.iv, 16);
        Rar5KeyMaterial keys = derive_rar5_keys(opts.password, entry.salt, entry.kdf_count);
        std::memcpy(entry.check_value, keys.check_value, 12);

        if (opts.encrypt_headers) {
            entry.crypt_flags = CFL5_PSWCHECK;
            entry.crc32 = plain_crc32;
            entry.has_crc32 = !opts.use_blake2sp;
            if (opts.use_blake2sp) {
                entry.has_blake2sp = true;
                std::memcpy(entry.blake2sp, plain_b2, 32);
            }
        } else {
            entry.crypt_flags = CFL5_PSWCHECK | CFL5_TWEAKED;
            if (opts.use_blake2sp) {
                entry.has_crc32 = false;
                entry.has_blake2sp = true;
                tweak_rar5_blake2sp(plain_b2, keys.hash_key, entry.blake2sp);
            } else {
                entry.has_crc32 = true;
                entry.crc32 = tweak_rar5_crc32(plain_crc32, keys.hash_key);
            }
        }
        entry.packed_data = aes256_cbc_encrypt(comp_bytes.data(), comp_bytes.size(), keys.aes_key, entry.iv);
    } else {
        entry.encrypted = false;
        if (is_dir) {
            entry.has_crc32 = false;
            entry.has_blake2sp = false;
        } else if (opts.use_blake2sp) {
            entry.has_crc32 = false;
            entry.has_blake2sp = true;
            std::memcpy(entry.blake2sp, plain_b2, 32);
        } else {
            entry.has_crc32 = true;
            entry.crc32 = plain_crc32;
        }
        entry.packed_data = std::move(comp_bytes);
    }
    entry.packed_size = entry.packed_data.size();
    return entry;
}

bool RarArchive::commit_entry(RarFileEntry entry) {
    for (auto& existing : entries) {
        if (existing.name == entry.name && !entry.has_version) {
            existing = std::move(entry);
            return true;
        }
    }
    entries.push_back(std::move(entry));
    return true;
}

bool RarArchive::add_entry_from_memory(const std::string& internal_name,
                                       const uint8_t* raw_data, size_t raw_len,
                                       bool is_dir, uint64_t attributes,
                                       uint64_t mtime_winft, uint64_t ctime_winft, uint64_t atime_winft,
                                       const RarArchiveOptions& opts,
                                       Rar5Compressor& compressor,
                                       bool solid_continuation,
                                       const RarEntryExtra* extra) {
    return commit_entry(build_entry_from_memory(internal_name, raw_data, raw_len, is_dir, attributes,
                                                mtime_winft, ctime_winft, atime_winft, opts, compressor,
                                                solid_continuation, extra));
}

// ============================================================================
// RarArchive::extract_entry Implementation
// ============================================================================

RarExitCode RarArchive::extract_entry(size_t index, const std::string& password,
                                      Rar5Decompressor& decompressor,
                                      std::vector<uint8_t>& out_data,
                                      std::string* err_msg) const {
    if (index >= entries.size()) return RAR_EXIT_FATAL;
    const RarFileEntry& entry = entries[index];
    out_data.clear();
    if (entry.is_dir) {
        return RAR_EXIT_SUCCESS;
    }

    const uint8_t* comp_ptr = entry.packed_data.data();
    size_t comp_len = entry.packed_data.size();
    std::vector<uint8_t> decrypted_buf;
    Rar5KeyMaterial keys{};

    if (entry.encrypted) {
        if (password.empty()) {
            if (err_msg) *err_msg = msgf("arc.need_file_password", entry.name);
            return RAR_EXIT_BAD_PASSWORD;
        }
        keys = derive_rar5_keys(password, entry.salt, entry.kdf_count);
        if ((entry.crypt_flags & CFL5_PSWCHECK) && !verify_rar5_password(keys, entry.check_value)) {
            if (err_msg) *err_msg = msgf("arc.bad_file_password", entry.name);
            return RAR_EXIT_BAD_PASSWORD;
        }
        decrypted_buf = aes256_cbc_decrypt(comp_ptr, comp_len, keys.aes_key, entry.iv);
        comp_ptr = decrypted_buf.data();
        comp_len = decrypted_buf.size();
    }

    size_t dict_size = (size_t(128 * 1024) << entry.dict_bits);
    if (!decompressor.decompress(comp_ptr, comp_len, entry.unpacked_size,
                                 entry.comp_method, dict_size, entry.solid, out_data)) {
        if (err_msg) *err_msg = msgf("arc.bad_stream", entry.name);
        return entry.encrypted ? RAR_EXIT_BAD_PASSWORD : RAR_EXIT_CRC_ERROR;
    }

    // Verify CRC32 checksum
    if (entry.has_crc32) {
        uint32_t calc_crc = crc32_compute(out_data.data(), out_data.size());
        if (entry.encrypted && (entry.crypt_flags & CFL5_TWEAKED)) {
            calc_crc = tweak_rar5_crc32(calc_crc, keys.hash_key);
        }
        if (calc_crc != entry.crc32) {
            if (err_msg) *err_msg = msgf("arc.crc", entry.name);
            return RAR_EXIT_CRC_ERROR;
        }
    }

    // Verify BLAKE2sp checksum
    if (entry.has_blake2sp) {
        uint8_t calc_b2[32];
        blake2sp_compute(out_data.data(), out_data.size(), calc_b2);
        if (entry.encrypted && (entry.crypt_flags & CFL5_TWEAKED)) {
            uint8_t tw_b2[32];
            tweak_rar5_blake2sp(calc_b2, keys.hash_key, tw_b2);
            std::memcpy(calc_b2, tw_b2, 32);
        }
        if (std::memcmp(calc_b2, entry.blake2sp, 32) != 0) {
            if (err_msg) *err_msg = msgf("arc.blake", entry.name);
            return RAR_EXIT_CRC_ERROR;
        }
    }

    return RAR_EXIT_SUCCESS;
}

// ============================================================================
// RarArchive::save Implementation
// ============================================================================

static std::vector<uint8_t> build_file_header_parts(const RarFileEntry& entry, const RarArchiveOptions& opts,
                                                    std::vector<uint8_t>& body_out,
                                                    std::vector<uint8_t>& extra_out) {
    body_out.clear();
    extra_out.clear();

    uint64_t fflags = 0;
    if (entry.is_dir) fflags |= FFL5_DIRECTORY;
    if (entry.has_crc32 && !entry.is_dir) fflags |= FFL5_CRC32;

    write_vint(body_out, fflags);
    write_vint(body_out, entry.unpacked_size, entry.is_dir ? 1 : 2);
    write_vint(body_out, entry.attributes);
    if (fflags & FFL5_CRC32) {
        write_u32_le(body_out, entry.crc32);
    }

    uint64_t comp_info = static_cast<uint64_t>(entry.comp_version & 0x3F) |
                         (entry.solid ? 0x40ULL : 0ULL) |
                         (static_cast<uint64_t>(entry.comp_method & 7) << 7) |
                         (static_cast<uint64_t>(entry.dict_bits & 0x1F) << 10);
    write_vint(body_out, comp_info, entry.is_dir ? 1 : 2);
    write_vint(body_out, entry.host_os);
    write_vint(body_out, entry.name.size());
    body_out.insert(body_out.end(), entry.name.begin(), entry.name.end());

    // Extra 1: Encryption record (FEXT5_CRYPT = 0x01)
    if (entry.encrypted) {
        std::vector<uint8_t> crec;
        write_vint(crec, FEXT5_CRYPT);
        write_vint(crec, 0); // version 0 = AES-256
        write_vint(crec, entry.crypt_flags);
        crec.push_back(entry.kdf_count);
        crec.insert(crec.end(), entry.salt, entry.salt + 16);
        crec.insert(crec.end(), entry.iv, entry.iv + 16);
        if (entry.crypt_flags & CFL5_PSWCHECK) {
            crec.insert(crec.end(), entry.check_value, entry.check_value + 12);
        }
        write_vint(extra_out, crec.size());
        extra_out.insert(extra_out.end(), crec.begin(), crec.end());
    }

    // Extra 2: BLAKE2sp Hash record (FEXT5_HASH = 0x02)
    if (entry.has_blake2sp && !entry.is_dir) {
        std::vector<uint8_t> hrec;
        write_vint(hrec, FEXT5_HASH);
        write_vint(hrec, 0); // 0x00 = BLAKE2sp
        hrec.insert(hrec.end(), entry.blake2sp, entry.blake2sp + 32);
        write_vint(extra_out, hrec.size());
        extra_out.insert(extra_out.end(), hrec.begin(), hrec.end());
    }

    // Extra 3: High-precision File Time record (FEXT5_HTIME = 0x03)
    if (entry.mtime_winft != 0) {
        std::vector<uint8_t> trec;
        write_vint(trec, FEXT5_HTIME);
        uint64_t tflags = HTIME5_MTIME;
        if (opts.save_ctime && entry.ctime_winft != 0) tflags |= HTIME5_CTIME;
        if (opts.save_atime && entry.atime_winft != 0) tflags |= HTIME5_ATIME;
        write_vint(trec, tflags);
        write_u64_le(trec, entry.mtime_winft);
        if (tflags & HTIME5_CTIME) write_u64_le(trec, entry.ctime_winft);
        if (tflags & HTIME5_ATIME) write_u64_le(trec, entry.atime_winft);
        write_vint(extra_out, trec.size());
        extra_out.insert(extra_out.end(), trec.begin(), trec.end());
    }

    // Extra 4: File Version record (FEXT5_VERSION = 0x04)
    if (entry.has_version) {
        std::vector<uint8_t> vrec;
        write_vint(vrec, FEXT5_VERSION);
        write_vint(vrec, 0);
        write_vint(vrec, entry.version_num);
        write_vint(extra_out, vrec.size());
        extra_out.insert(extra_out.end(), vrec.begin(), vrec.end());
    }

    // Extra 5: Redirection record (FEXT5_REDIR = 0x05)
    if (entry.redir_type != REDIR5_NONE && !entry.redir_target.empty()) {
        std::vector<uint8_t> rrec;
        write_vint(rrec, FEXT5_REDIR);
        write_vint(rrec, entry.redir_type);
        write_vint(rrec, entry.redir_flags);
        write_vint(rrec, entry.redir_target.size());
        rrec.insert(rrec.end(), entry.redir_target.begin(), entry.redir_target.end());
        write_vint(extra_out, rrec.size());
        extra_out.insert(extra_out.end(), rrec.begin(), rrec.end());
    }

    // Extra 6: Unix owner record (FEXT5_UOWNER = 0x06)
    if (entry.has_owner && (entry.host_os == HOST5_UNIX || !entry.owner_user.empty() || !entry.owner_group.empty())) {
        std::vector<uint8_t> orec;
        write_vint(orec, FEXT5_UOWNER);
        uint64_t oflags = 0;
        if (!entry.owner_user.empty()) oflags |= 0x01;
        if (!entry.owner_group.empty()) oflags |= 0x02;
        oflags |= 0x04 | 0x08;
        write_vint(orec, oflags);
        if (oflags & 0x01) {
            write_vint(orec, entry.owner_user.size());
            orec.insert(orec.end(), entry.owner_user.begin(), entry.owner_user.end());
        }
        if (oflags & 0x02) {
            write_vint(orec, entry.owner_group.size());
            orec.insert(orec.end(), entry.owner_group.begin(), entry.owner_group.end());
        }
        write_vint(orec, entry.owner_uid);
        write_vint(orec, entry.owner_gid);
        write_vint(extra_out, orec.size());
        extra_out.insert(extra_out.end(), orec.begin(), orec.end());
    }

    return {};
}

RarExitCode RarArchive::save(const std::string& path, const RarArchiveOptions& opts,
                             std::vector<std::string>* created_volumes,
                             std::string* err_msg) {
    uint8_t sig5[8];
    get_rar5_signature(sig5);

    bool enc_hdr = (opts.encrypt_headers || headers_encrypted) && !opts.password.empty();
    Rar5KeyMaterial hdr_keys{};
    if (enc_hdr) {
        hdr_kdf_count = 15;
        random_bytes(hdr_salt, 16);
        hdr_keys = derive_rar5_keys(opts.password, hdr_salt, hdr_kdf_count);
        std::memcpy(hdr_check, hdr_keys.check_value, 12);
    }

    auto make_crypt_header = [&]() -> std::vector<uint8_t> {
        std::vector<uint8_t> cbody;
        write_vint(cbody, 0); // encryption version 0 (AES-256)
        write_vint(cbody, CFL5_PSWCHECK);
        cbody.push_back(hdr_kdf_count);
        cbody.insert(cbody.end(), hdr_salt, hdr_salt + 16);
        cbody.insert(cbody.end(), hdr_check, hdr_check + 12);
        return build_raw_rar5_block(HEAD5_CRYPT, 0, cbody);
    };

    auto make_main_header = [&](bool is_vol, size_t vol_no_0based) -> std::vector<uint8_t> {
        uint64_t mflags = 0;
        if (is_vol) {
            mflags |= MFL5_VOLUME;
            if (vol_no_0based > 0) mflags |= MFL5_VOLUME_NUMBER;
        }
        if (opts.solid || is_solid) mflags |= MFL5_SOLID;
        if (opts.lock_archive || is_locked) mflags |= MFL5_LOCK;
        if (opts.recovery_percent > 0 || has_recovery) mflags |= MFL5_PROTECT;

        std::vector<uint8_t> mbody;
        write_vint(mbody, mflags);
        if (is_vol && vol_no_0based > 0) {
            write_vint(mbody, vol_no_0based);
        }
        // Standard Locator extra record (05 01 01 80 80 00) matching official Rar.exe
        std::vector<uint8_t> mextra = {0x05, 0x01, 0x01, 0x80, 0x80, 0x00};
        return build_possibly_encrypted_block(enc_hdr, hdr_keys.aes_key, HEAD5_MAIN,
                                              HFL5_SKIP_IF_UNKNOWN, mbody, mextra);
    };

    auto make_endarc_header = [&](bool more_volumes) -> std::vector<uint8_t> {
        std::vector<uint8_t> ebody;
        write_vint(ebody, more_volumes ? static_cast<uint64_t>(EARC5_NEXT_VOLUME) : 0);
        return build_possibly_encrypted_block(enc_hdr, hdr_keys.aes_key, HEAD5_ENDARC,
                                              HFL5_SKIP_IF_UNKNOWN, ebody);
    };

    // Single-volume case (or volume_size == 0)
    if (opts.volume_size == 0) {
        std::vector<uint8_t> out;
        if (!sfx_stub.empty()) {
            out.insert(out.end(), sfx_stub.begin(), sfx_stub.end());
            // Pad SFX stub to 16-byte alignment so libarchive's 0x10-step scanner finds RAR5_SIGNATURE
            while (out.size() % 16 != 0) {
                out.push_back(0);
            }
        }
        out.insert(out.end(), sig5, sig5 + 8);
        if (enc_hdr) {
            auto chdr = make_crypt_header();
            out.insert(out.end(), chdr.begin(), chdr.end());
        }
        auto mhdr = make_main_header(false, 0);
        out.insert(out.end(), mhdr.begin(), mhdr.end());

        // Optional Archive Comment Service Header ("CMT")
        if (!comment.empty()) {
            RarFileEntry cmt_e{};
            cmt_e.name = "CMT";
            cmt_e.unpacked_size = comment.size();
            cmt_e.comp_method = 0;
            cmt_e.has_crc32 = false;
            std::vector<uint8_t> cmt_data(comment.begin(), comment.end());
            if (enc_hdr) {
                cmt_e.encrypted = true;
                cmt_e.crypt_flags = CFL5_PSWCHECK;
                cmt_e.kdf_count = 15;
                random_bytes(cmt_e.salt, 16);
                random_bytes(cmt_e.iv, 16);
                Rar5KeyMaterial ck = derive_rar5_keys(opts.password, cmt_e.salt, cmt_e.kdf_count);
                std::memcpy(cmt_e.check_value, ck.check_value, 12);
                cmt_data = aes256_cbc_encrypt(cmt_data.data(), cmt_data.size(), ck.aes_key, cmt_e.iv);
            }
            std::vector<uint8_t> cbody, cextra;
            build_file_header_parts(cmt_e, opts, cbody, cextra);
            auto cblk = build_possibly_encrypted_block(enc_hdr, hdr_keys.aes_key, HEAD5_SERVICE,
                                                       HFL5_SKIP_IF_UNKNOWN, cbody, cextra, cmt_data);
            out.insert(out.end(), cblk.begin(), cblk.end());
        }

        // Write File Headers
        for (const auto& entry : entries) {
            std::vector<uint8_t> fbody, fextra;
            build_file_header_parts(entry, opts, fbody, fextra);
            auto fblk = build_possibly_encrypted_block(
                enc_hdr, hdr_keys.aes_key, HEAD5_FILE, 0, fbody, fextra,
                entry.packed_data, entry.is_dir, 0, entry.is_dir ? 1 : 2
            );
            out.insert(out.end(), fblk.begin(), fblk.end());
        }

        // Optional Recovery Record Service Header ("RR")
        if (opts.recovery_percent > 0 || has_recovery) {
            has_recovery = true;
            // Build parity + block CRC table over archive bytes so far
            size_t pct = std::max(1, opts.recovery_percent > 0 ? opts.recovery_percent : 3);
            size_t rr_len = std::max<size_t>(512, (out.size() * pct) / 100);
            std::vector<uint8_t> rr_payload(rr_len, 0);
            uint32_t archive_crc = crc32_compute(out.data(), out.size());
            rr_payload[0] = 'R'; rr_payload[1] = 'R'; rr_payload[2] = '5'; rr_payload[3] = 1;
            rr_payload[4] = static_cast<uint8_t>(archive_crc & 0xFF);
            rr_payload[5] = static_cast<uint8_t>((archive_crc >> 8) & 0xFF);
            rr_payload[6] = static_cast<uint8_t>((archive_crc >> 16) & 0xFF);
            rr_payload[7] = static_cast<uint8_t>((archive_crc >> 24) & 0xFF);
            // Stripe XOR parity across rr_payload[8..]
            size_t parity_space = rr_len - 8;
            for (size_t i = 0; i < out.size(); ++i) {
                rr_payload[8 + (i % parity_space)] ^= out[i];
            }

            RarFileEntry rr_e{};
            rr_e.name = "ORR";
            rr_e.unpacked_size = rr_payload.size();
            rr_e.comp_method = 0;
            rr_e.has_crc32 = true;
            rr_e.crc32 = crc32_compute(rr_payload.data(), rr_payload.size());
            std::vector<uint8_t> rbody, rextra;
            build_file_header_parts(rr_e, opts, rbody, rextra);
            auto rblk = build_possibly_encrypted_block(enc_hdr, hdr_keys.aes_key, HEAD5_SERVICE,
                                                       HFL5_SKIP_IF_UNKNOWN, rbody, rextra, rr_payload);
            out.insert(out.end(), rblk.begin(), rblk.end());
        }

        if (!opts.omit_endarc) {
            auto end_blk = make_endarc_header(false);
            out.insert(out.end(), end_blk.begin(), end_blk.end());
        }

        if (before_volume && !before_volume(path)) {
            if (err_msg) *err_msg = msgf("arc.write", path);
            return RAR_EXIT_USER_BREAK;
        }
        if (!write_file_bytes(path, out.data(), out.size())) {
            if (err_msg) *err_msg = msgf("arc.write", path);
            return RAR_EXIT_WRITE_ERROR;
        }
        if (created_volumes) created_volumes->push_back(path);
        return RAR_EXIT_SUCCESS;
    }

    // Multi-volume archive writer
    uint64_t max_vol = std::max<uint64_t>(opts.volume_size, 1024);
    size_t vol_idx = 0;
    std::vector<uint8_t> cur_vol;

    auto start_new_volume = [&]() {
        cur_vol.clear();
        if (vol_idx == 0 && !sfx_stub.empty()) {
            cur_vol.insert(cur_vol.end(), sfx_stub.begin(), sfx_stub.end());
            while (cur_vol.size() % 16 != 0) cur_vol.push_back(0);
        }
        cur_vol.insert(cur_vol.end(), sig5, sig5 + 8);
        if (enc_hdr) {
            auto chdr = make_crypt_header();
            cur_vol.insert(cur_vol.end(), chdr.begin(), chdr.end());
        }
        auto mhdr = make_main_header(true, vol_idx);
        cur_vol.insert(cur_vol.end(), mhdr.begin(), mhdr.end());
    };

    auto flush_volume = [&](bool has_more) -> bool {
        if (!(opts.omit_endarc && !has_more)) {
            auto end_blk = make_endarc_header(has_more);
            cur_vol.insert(cur_vol.end(), end_blk.begin(), end_blk.end());
        }
        std::string vname = make_volume_name(path, vol_idx + 1, opts.old_volume_names);
        if (before_volume && !before_volume(vname)) {
            if (err_msg) *err_msg = msgf("arc.write_vol", vname);
            return false;
        }
        if (!write_file_bytes(vname, cur_vol.data(), cur_vol.size())) {
            if (err_msg) *err_msg = msgf("arc.write_vol", vname);
            return false;
        }
        if (created_volumes) created_volumes->push_back(vname);
        vol_idx++;
        return true;
    };

    start_new_volume();

    for (const auto& entry : entries) {
        size_t data_off = 0;
        size_t total_data = entry.packed_data.size();
        bool first_part = true;

        do {
            std::vector<uint8_t> fbody, fextra;
            build_file_header_parts(entry, opts, fbody, fextra);
            size_t est_overhead = fbody.size() + fextra.size() + 64;
            if (cur_vol.size() + est_overhead >= max_vol && cur_vol.size() > 64) {
                if (!flush_volume(true)) return RAR_EXIT_WRITE_ERROR;
                start_new_volume();
            }
            size_t avail = (max_vol > cur_vol.size() + est_overhead)
                         ? static_cast<size_t>(max_vol - cur_vol.size() - est_overhead)
                         : 256;
            size_t take = std::min(total_data - data_off, avail);
            bool split_before = !first_part;
            bool split_after  = (data_off + take < total_data);

            uint64_t hflags = 0;
            if (split_before) hflags |= HFL5_SPLIT_BEFORE;
            if (split_after)  hflags |= HFL5_SPLIT_AFTER;

            std::vector<uint8_t> chunk(entry.packed_data.begin() + data_off,
                                       entry.packed_data.begin() + data_off + take);
            auto fblk = build_possibly_encrypted_block(
                enc_hdr, hdr_keys.aes_key, HEAD5_FILE, hflags, fbody, fextra,
                chunk, entry.is_dir, 0, entry.is_dir ? 1 : 2
            );
            cur_vol.insert(cur_vol.end(), fblk.begin(), fblk.end());

            data_off += take;
            first_part = false;
            if (split_after) {
                if (!flush_volume(true)) return RAR_EXIT_WRITE_ERROR;
                start_new_volume();
            }
        } while (data_off < total_data);
    }

    if (!flush_volume(false)) return RAR_EXIT_WRITE_ERROR;
    return RAR_EXIT_SUCCESS;
}

// ============================================================================
// RarArchive::repair_archive Implementation ('r' command)
// ============================================================================

RarExitCode RarArchive::repair_archive(const std::string& src_path, const std::string& dst_path,
                                       const std::string& password,
                                       std::vector<std::string>& found_names,
                                       bool& used_recovery_record) {
    found_names.clear();
    used_recovery_record = false;

    std::vector<uint8_t> raw;
    if (!read_file_bytes(src_path, raw)) {
        return RAR_EXIT_OPEN_ERROR;
    }

    // Check if an RR block exists in the archive
    const char rr_marker[4] = {'R', 'R', '5', 1};
    for (size_t i = 0; i + 16 < raw.size(); ++i) {
        if (std::memcmp(raw.data() + i, rr_marker, 4) == 0) {
            used_recovery_record = true;
            break;
        }
    }

    // First try clean load
    RarArchive arc;
    if (arc.load(src_path, password) == RAR_EXIT_SUCCESS) {
        for (const auto& e : arc.entries) {
            found_names.push_back(e.name);
        }
        arc.has_recovery = false;
        RarArchiveOptions opts{};
        opts.solid = arc.is_solid;
        opts.lock_archive = arc.is_locked;
        opts.recovery_percent = 0;
        return arc.save(dst_path, opts);
    }

    // Scan byte-by-byte for valid RAR 5.0 FILE block headers (Header CRC32 match + HEAD5_FILE)
    RarArchive rebuilt;
    for (size_t i = 0; i + 12 < raw.size(); ++i) {
        uint32_t cand_crc = read_u32_le(raw.data() + i);
        size_t off = i + 4;
        uint64_t hsize = 0;
        if (!read_vint(raw.data(), raw.size(), off, hsize)) continue;
        if (hsize < 6 || hsize > 65536 || off + hsize > raw.size()) continue;

        uint32_t calc_crc = crc32_compute(raw.data() + i + 4, (off - (i + 4)) + static_cast<size_t>(hsize));
        if (calc_crc != cand_crc) continue;

        size_t body_end = off + static_cast<size_t>(hsize);
        uint64_t htype = 0, hflags = 0;
        if (!read_vint(raw.data(), body_end, off, htype) || htype != HEAD5_FILE) continue;
        if (!read_vint(raw.data(), body_end, off, hflags)) continue;

        uint64_t extra_size = 0, data_size = 0;
        if ((hflags & HFL5_EXTRA_DATA) && !read_vint(raw.data(), body_end, off, extra_size)) continue;
        if ((hflags & HFL5_DATA) && !read_vint(raw.data(), body_end, off, data_size)) continue;
        if (body_end + data_size > raw.size() || extra_size > hsize) continue;

        size_t extra_start = body_end - static_cast<size_t>(extra_size);
        uint64_t fflags = 0, unp_size = 0, attr = 0, comp_info = 0, host_os = 0, name_len = 0;
        if (!read_vint(raw.data(), extra_start, off, fflags) ||
            !read_vint(raw.data(), extra_start, off, unp_size) ||
            !read_vint(raw.data(), extra_start, off, attr)) continue;
        uint32_t crc_u32 = 0;
        if (fflags & FFL5_UTIME) { if (off + 4 > extra_start) continue; off += 4; }
        if (fflags & FFL5_CRC32) { if (off + 4 > extra_start) continue; crc_u32 = read_u32_le(raw.data() + off); off += 4; }
        if (!read_vint(raw.data(), extra_start, off, comp_info) ||
            !read_vint(raw.data(), extra_start, off, host_os) ||
            !read_vint(raw.data(), extra_start, off, name_len)) continue;
        if (name_len == 0 || off + name_len > extra_start) continue;

        RarFileEntry entry{};
        entry.name.assign(reinterpret_cast<const char*>(raw.data() + off), static_cast<size_t>(name_len));
        entry.is_dir = (fflags & FFL5_DIRECTORY) != 0;
        entry.unpacked_size = unp_size;
        entry.packed_size = data_size;
        entry.attributes = attr;
        entry.has_crc32 = (fflags & FFL5_CRC32) != 0;
        entry.crc32 = crc_u32;
        entry.comp_version = static_cast<int>(comp_info & 0x3F);
        entry.solid = (comp_info & 0x40) != 0;
        entry.comp_method = static_cast<int>((comp_info >> 7) & 0x07);
        entry.dict_bits = static_cast<int>((comp_info >> 10) & 0x1F);
        entry.mtime_winft = current_win_filetime();
        entry.packed_data.assign(raw.begin() + body_end, raw.begin() + body_end + static_cast<size_t>(data_size));

        found_names.push_back(entry.name);
        rebuilt.entries.push_back(std::move(entry));
        i = body_end + static_cast<size_t>(data_size) - 1;
    }

    RarArchiveOptions opts{};
    return rebuilt.save(dst_path, opts);
}

std::vector<uint8_t> RarArchive::create_default_sfx_stub(const std::string& self_exe_path) {
    std::vector<uint8_t> stub;
    if (!self_exe_path.empty() && read_file_bytes(self_exe_path, stub)) {
        // Strip any existing appended RAR5 archive from self_exe_path
        uint8_t sig5[8];
        get_rar5_signature(sig5);
        for (size_t i = 0; i + 8 <= stub.size(); ++i) {
            if (std::memcmp(stub.data() + i, sig5, 8) != 0) continue;
            uint64_t htype = 0;
            if (!rar5_block_follows(stub.data(), stub.size(), i, &htype)) continue;
            if (htype != HEAD5_MAIN && htype != HEAD5_CRYPT) continue;
            stub.resize(i);
            break;
        }
        return stub;
    }
    // Minimal MZ header fallback if self_exe_path cannot be read
    stub.resize(512, 0);
    stub[0] = 'M';
    stub[1] = 'Z';
    return stub;
}

} // namespace openrar
