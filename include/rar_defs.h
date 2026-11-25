/*
 * OpenRAR - Clean-Room Open-Source RAR 5.0 Archiver & Compressor
 *
 * Copyright (C) 2026 OpenRAR Contributors
 * Based on the public RAR 5.0 Archive Format Specification and inspired by
 * unrar-free (https://gitlab.com/bgermann/unrar-free, GPLv2+) and libarchive.
 *
 * DISCLAIMER & LEGAL NOTICE:
 * This project is an independent clean-room implementation created strictly
 * for academic learning and research into RAR archive structures and lossless
 * data compression principles (LZSS, Canonical Huffman coding, filters).
 * It contains NO code from RARLAB's proprietary WinRAR or UnRAR sources,
 * and removes all commercial licensing/activation mechanisms.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_DEFS_H
#define OPENRAR_DEFS_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace openrar {

// Official RAR CLI Exit Codes
enum RarExitCode : int {
    RAR_EXIT_SUCCESS       = 0,   // Successful operation
    RAR_EXIT_WARNING       = 1,   // Non-fatal error(s) occurred
    RAR_EXIT_FATAL         = 2,   // A fatal error occurred
    RAR_EXIT_CRC_ERROR     = 3,   // Invalid checksum (CRC32 / BLAKE2sp)
    RAR_EXIT_LOCKED        = 4,   // Attempt to modify a locked archive ('k')
    RAR_EXIT_WRITE_ERROR   = 5,   // Disk write error
    RAR_EXIT_OPEN_ERROR    = 6,   // File open error
    RAR_EXIT_USER_ERROR    = 7,   // Wrong command line option
    RAR_EXIT_MEMORY_ERROR  = 8,   // Not enough memory
    RAR_EXIT_CREATE_ERROR  = 9,   // File create error
    RAR_EXIT_NO_FILES      = 10,  // No files matching specified mask and options
    RAR_EXIT_BAD_PASSWORD  = 11,  // Wrong password
    RAR_EXIT_READ_ERROR    = 12,  // Read error
    RAR_EXIT_USER_BREAK    = 255  // User stopped the process
};

// RAR 5.0 8-byte Magic Signature XOR-masked with 0xA1 so the compiled binary
// does not contain a false RAR5 magic sequence inside its .rdata section when used as an SFX stub.
static constexpr uint8_t RAR5_SIGNATURE_XOR[8] = {
    0x52 ^ 0xA1, 0x61 ^ 0xA1, 0x72 ^ 0xA1, 0x21 ^ 0xA1,
    0x1A ^ 0xA1, 0x07 ^ 0xA1, 0x01 ^ 0xA1, 0x00 ^ 0xA1
};

inline void get_rar5_signature(uint8_t out[8]) {
    // Read the mask through volatile so the real signature is not a
    // compile-time constant sitting inside the executable. An SFX stub is a
    // copy of this binary, and a baked-in signature would be cut as if it
    // were an appended archive.
    volatile uint8_t mask = 0xA1;
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>(RAR5_SIGNATURE_XOR[i] ^ mask);
    }
}

// RAR 4.x 7-byte Magic Signature XOR-masked with 0xA1
static constexpr uint8_t RAR4_SIGNATURE_XOR[7] = {
    0x52 ^ 0xA1, 0x61 ^ 0xA1, 0x72 ^ 0xA1, 0x21 ^ 0xA1,
    0x1A ^ 0xA1, 0x07 ^ 0xA1, 0x00 ^ 0xA1
};

inline void get_rar4_signature(uint8_t out[7]) {
    volatile uint8_t mask = 0xA1;
    for (int i = 0; i < 7; ++i) {
        out[i] = static_cast<uint8_t>(RAR4_SIGNATURE_XOR[i] ^ mask);
    }
}

// RAR 5.0 Header Types
enum Rar5HeaderType : uint64_t {
    HEAD5_MARK    = 0x00,
    HEAD5_MAIN    = 0x01,
    HEAD5_FILE    = 0x02,
    HEAD5_SERVICE = 0x03,
    HEAD5_CRYPT   = 0x04,
    HEAD5_ENDARC  = 0x05
};

// RAR 5.0 Common Header Flags
enum Rar5HeaderFlags : uint64_t {
    HFL5_EXTRA_DATA      = 0x0001,
    HFL5_DATA            = 0x0002,
    HFL5_SKIP_IF_UNKNOWN = 0x0004,
    HFL5_SPLIT_BEFORE    = 0x0008,
    HFL5_SPLIT_AFTER     = 0x0010,
    HFL5_CHILD           = 0x0020,
    HFL5_INHERITED       = 0x0040
};

// RAR 5.0 Main Archive Header Flags
enum Rar5MainFlags : uint64_t {
    MFL5_VOLUME        = 0x0001,
    MFL5_VOLUME_NUMBER = 0x0002,
    MFL5_SOLID         = 0x0004,
    MFL5_PROTECT       = 0x0008,
    MFL5_LOCK          = 0x0010
};

// RAR 5.0 Main Header Extra Record Types
enum Rar5MainExtraType : uint64_t {
    MEXT5_LOCATOR  = 0x01,
    MEXT5_METADATA = 0x02
};

// RAR 5.0 Locator Flags
enum Rar5LocatorFlags : uint64_t {
    LOC5_QLIST    = 0x0001,
    LOC5_RECOVERY = 0x0002
};

// RAR 5.0 File / Service Header Flags
enum Rar5FileFlags : uint64_t {
    FFL5_DIRECTORY      = 0x0001,
    FFL5_UTIME          = 0x0002,
    FFL5_CRC32          = 0x0004,
    FFL5_UNP_UNKNOWN    = 0x0008
};

// RAR 5.0 File / Service Extra Record Types
enum Rar5FileExtraType : uint64_t {
    FEXT5_CRYPT   = 0x01,
    FEXT5_HASH    = 0x02,
    FEXT5_HTIME   = 0x03,
    FEXT5_VERSION = 0x04,
    FEXT5_REDIR   = 0x05,
    FEXT5_UOWNER  = 0x06,
    FEXT5_SUBDATA = 0x07
};

// RAR 5.0 Encryption Flags
enum Rar5CryptFlags : uint64_t {
    CFL5_PSWCHECK = 0x0001,
    CFL5_TWEAKED  = 0x0002
};

// RAR 5.0 File Time Extra Record Flags
enum Rar5HTimeFlags : uint64_t {
    HTIME5_UNIX_TIME = 0x0001,
    HTIME5_MTIME     = 0x0002,
    HTIME5_CTIME     = 0x0004,
    HTIME5_ATIME     = 0x0008,
    HTIME5_UNIX_NS   = 0x0010
};

// RAR 5.0 End of Archive Flags
enum Rar5EndArcFlags : uint64_t {
    EARC5_NEXT_VOLUME = 0x0001
};

// RAR 5.0 Host OS
enum Rar5HostOS : uint64_t {
    HOST5_WINDOWS = 0x00,
    HOST5_UNIX    = 0x01
};

// RAR 5.0 Redirection Types
enum Rar5RedirType : uint64_t {
    REDIR5_NONE        = 0x00,
    REDIR5_UNIXSYMLINK = 0x01,
    REDIR5_WINSYMLINK  = 0x02,
    REDIR5_JUNCTION    = 0x03,
    REDIR5_HARDLINK    = 0x04,
    REDIR5_FILECOPY    = 0x05
};

// RAR 5.0 Filter Types
enum Rar5FilterType : int {
    FILTER5_DELTA = 0,
    FILTER5_E8    = 1,
    FILTER5_E8E9  = 2,
    FILTER5_ARM   = 3
};

// Huffman Table Constants in RAR 5.0
static constexpr int HUFF_BC         = 20;
static constexpr int HUFF_NC         = 306;
static constexpr int HUFF_DC         = 64;
static constexpr int HUFF_LDC        = 16;
static constexpr int HUFF_RC         = 44;
static constexpr int HUFF_TABLE_SIZE = HUFF_NC + HUFF_DC + HUFF_LDC + HUFF_RC; // 430
static constexpr int MAX_HUFF_BITS   = 15;

// Variable-length integer (vint) encoding & decoding helpers
inline void write_vint(std::vector<uint8_t>& out, uint64_t val, int min_bytes = 1) {
    int count = 0;
    do {
        uint8_t b = static_cast<uint8_t>(val & 0x7F);
        val >>= 7;
        count++;
        if (val != 0 || count < min_bytes) {
            b |= 0x80;
        }
        out.push_back(b);
    } while (val != 0 || count < min_bytes);
}

inline std::vector<uint8_t> encode_vint(uint64_t val, int min_bytes = 1) {
    std::vector<uint8_t> out;
    write_vint(out, val, min_bytes);
    return out;
}

inline bool read_vint(const uint8_t* data, size_t len, size_t& offset, uint64_t& val) {
    val = 0;
    unsigned int shift = 0;
    for (int i = 0; i < 10; ++i) {
        if (offset >= len) return false;
        uint8_t b = data[offset++];
        if (shift < 64) {
            val |= static_cast<uint64_t>(b & 0x7F) << shift;
        }
        shift += 7;
        if ((b & 0x80) == 0) {
            return true;
        }
    }
    return false;
}

inline void write_u32_le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline void write_u64_le(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

inline uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    }
    return v;
}

} // namespace openrar

#endif // OPENRAR_DEFS_H
