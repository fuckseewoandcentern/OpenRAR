/*
 * OpenRAR - Recovery volumes.
 * Parity is systematic Reed-Solomon over GF(256), independent of RARLAB's
 * proprietary .rev layout. `rv` writes these volumes and `rc` uses them to
 * rebuild missing volumes created by this program.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_archive.h"
#include "rar_i18n.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace openrar {

namespace {

fs::path u8p(const std::string& s) {
    return fs::u8path(s);
}

bool read_all(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream in(u8p(path), std::ios::binary | std::ios::ate);
    if (!in) return false;
    std::streamsize sz = in.tellg();
    if (sz < 0) return false;
    out.resize(static_cast<size_t>(sz));
    in.seekg(0);
    return sz == 0 || (bool)in.read(reinterpret_cast<char*>(out.data()), sz);
}

bool write_all(const std::string& path, const uint8_t* data, size_t len) {
    fs::path p = u8p(path);
    if (p.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
    }
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (len && !out.write(reinterpret_cast<const char*>(data), (std::streamsize)len)) return false;
    return true;
}

std::string stem_of(std::string p) {
    auto lower = [](std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    };
    std::string low = lower(p);
    if (low.size() >= 4 && (low.substr(low.size() - 4) == ".rar" || low.substr(low.size() - 4) == ".exe" ||
                            low.substr(low.size() - 4) == ".sfx" || low.substr(low.size() - 4) == ".rev")) {
        p = p.substr(0, p.size() - 4);
        low = lower(p);
    }
    auto cut_part = [&](std::string& s) {
        std::string l = lower(s);
        size_t pos = l.rfind(".part");
        if (pos == std::string::npos || pos + 5 >= s.size()) return;
        for (size_t i = pos + 5; i < s.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[i]))) return;
        }
        s = s.substr(0, pos);
    };
    cut_part(p);
    if (p.size() >= 4 && (p[p.size() - 3] == 'r' || p[p.size() - 3] == 'R') && p[p.size() - 4] == '.' &&
        std::isdigit(static_cast<unsigned char>(p[p.size() - 2])) &&
        std::isdigit(static_cast<unsigned char>(p[p.size() - 1]))) {
        p = p.substr(0, p.size() - 4);
    }
    return p;
}

std::string rev_name(const std::string& sample, int parity_index_0, bool old_style) {
    std::string stem = stem_of(sample);
    if (old_style && parity_index_0 == 0) return stem + ".rev";
    return stem + ".part" + std::to_string(parity_index_0 + 1) + ".rev";
}

struct Gf {
    uint8_t exp[512]{};
    uint8_t log[256]{};
    Gf() {
        unsigned x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[i] = (uint8_t)x;
            log[x] = (uint8_t)i;
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
        for (int i = 255; i < 512; ++i) exp[i] = exp[i - 255];
    }
    uint8_t mul(uint8_t a, uint8_t b) const {
        if (!a || !b) return 0;
        return exp[log[a] + log[b]];
    }
    uint8_t inv(uint8_t a) const {
        if (!a) return 0;
        return exp[255 - log[a]];
    }
    uint8_t coeff(int parity, int data) const {
        int e = ((parity + 1) * (data + 1)) % 255;
        return exp[e];
    }
};

const Gf& gf() {
    static const Gf g;
    return g;
}

bool invert(std::vector<std::vector<uint8_t>> a, std::vector<std::vector<uint8_t>>& inv) {
    const Gf& g = gf();
    int n = (int)a.size();
    inv.assign(n, std::vector<uint8_t>(n, 0));
    for (int i = 0; i < n; ++i) inv[i][i] = 1;
    for (int col = 0; col < n; ++col) {
        int piv = col;
        while (piv < n && a[piv][col] == 0) ++piv;
        if (piv == n) return false;
        if (piv != col) {
            std::swap(a[piv], a[col]);
            std::swap(inv[piv], inv[col]);
        }
        uint8_t scale = g.inv(a[col][col]);
        for (int j = 0; j < n; ++j) {
            a[col][j] = g.mul(a[col][j], scale);
            inv[col][j] = g.mul(inv[col][j], scale);
        }
        for (int r = 0; r < n; ++r) {
            if (r == col || a[r][col] == 0) continue;
            uint8_t f = a[r][col];
            for (int j = 0; j < n; ++j) {
                a[r][j] ^= g.mul(f, a[col][j]);
                inv[r][j] ^= g.mul(f, inv[col][j]);
            }
        }
    }
    return true;
}

static const char kMagic[8] = {'O', 'R', 'R', 'E', 'V', '1', 0, 1};

struct RevFile {
    std::string path;
    uint32_t volume_count = 0;
    uint32_t parity_index = 0;
    std::vector<std::string> names;
    std::vector<uint64_t> sizes;
    std::vector<uint8_t> payload;
};

void append_u32(std::vector<uint8_t>& o, uint32_t v) {
    for (int i = 0; i < 4; ++i) o.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
}
void append_u64(std::vector<uint8_t>& o, uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back((uint8_t)((v >> (8 * i)) & 0xFF));
}
uint32_t ru32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
uint64_t ru64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

bool parse_rev(const std::string& path, RevFile& rev) {
    std::vector<uint8_t> raw;
    if (!read_all(path, raw) || raw.size() < 16) return false;
    if (std::memcmp(raw.data(), kMagic, 8) != 0) return false;
    uint32_t count = ru32(raw.data() + 8);
    uint32_t index = ru32(raw.data() + 12);
    uint32_t name_bytes = ru32(raw.data() + 16);
    if (count == 0 || count > 100000) return false;
    size_t off = 20;
    if (off + name_bytes + count * 8 > raw.size()) return false;
    std::string joined(reinterpret_cast<const char*>(raw.data() + off), name_bytes);
    off += name_bytes;
    rev.names.clear();
    std::stringstream ss(joined);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) rev.names.push_back(line);
    }
    if (rev.names.size() != count) return false;
    rev.sizes.resize(count);
    for (uint32_t i = 0; i < count; ++i) {
        rev.sizes[i] = ru64(raw.data() + off);
        off += 8;
    }
    rev.payload.assign(raw.begin() + off, raw.end());
    rev.volume_count = count;
    rev.parity_index = index;
    rev.path = path;
    return true;
}

std::string basename_of(const std::string& path) {
    fs::path p = u8p(path);
    std::string base = p.filename().u8string();
    return base;
}

std::string parent_of(const std::string& path) {
    fs::path p = u8p(path);
    if (!p.has_parent_path()) return std::string();
    return p.parent_path().u8string();
}

} // namespace

bool write_recovery_volumes(const std::vector<std::string>& data_volumes, int parity_count,
                            bool old_style, std::vector<std::string>& created, std::string* err) {
    created.clear();
    if (data_volumes.empty() || parity_count <= 0) {
        if (err) *err = msg("err.rev_write");
        return false;
    }
    if (parity_count > 64) parity_count = 64;
    std::vector<std::vector<uint8_t>> data(data_volumes.size());
    size_t max_len = 0;
    std::string joined;
    std::vector<uint64_t> sizes;
    for (size_t i = 0; i < data_volumes.size(); ++i) {
        if (!read_all(data_volumes[i], data[i])) {
            if (err) *err = msgf("arc.cannot_open", data_volumes[i]);
            return false;
        }
        max_len = std::max(max_len, data[i].size());
        sizes.push_back(data[i].size());
        if (i) joined.push_back('\n');
        joined += basename_of(data_volumes[i]);
    }
    for (auto& d : data) d.resize(max_len, 0);
    const Gf& g = gf();
    int D = (int)data.size();
    for (int p = 0; p < parity_count; ++p) {
        std::vector<uint8_t> payload(max_len, 0);
        for (size_t i = 0; i < max_len; ++i) {
            uint8_t acc = 0;
            for (int j = 0; j < D; ++j) {
                acc ^= g.mul(g.coeff(p, j), data[j][i]);
            }
            payload[i] = acc;
        }
        std::vector<uint8_t> file;
        file.insert(file.end(), kMagic, kMagic + 8);
        append_u32(file, (uint32_t)D);
        append_u32(file, (uint32_t)p);
        append_u32(file, (uint32_t)joined.size());
        file.insert(file.end(), joined.begin(), joined.end());
        for (uint64_t sz : sizes) append_u64(file, sz);
        file.insert(file.end(), payload.begin(), payload.end());
        std::string out = rev_name(data_volumes.front(), p, old_style);
        if (!write_all(out, file.data(), file.size())) {
            if (err) *err = msgf("arc.write", out);
            return false;
        }
        created.push_back(out);
    }
    return true;
}

bool reconstruct_missing_volumes(const std::string& any_path,
                                 std::vector<std::string>& restored, std::string* err) {
    restored.clear();
    std::string dir = parent_of(any_path);
    fs::path dirp = dir.empty() ? fs::path(".") : u8p(dir);
    std::vector<RevFile> revs;
    std::error_code ec;
    for (auto it = fs::directory_iterator(dirp, ec); !ec && it != fs::directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        std::string p = it->path().u8string();
        std::string low = p;
        for (char& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (low.size() < 4 || low.substr(low.size() - 4) != ".rev") continue;
        RevFile rev;
        if (parse_rev(p, rev)) revs.push_back(std::move(rev));
    }
    if (revs.empty()) {
        if (err) *err = msg("err.rev");
        return false;
    }
    RevFile spec = revs.front();
    int D = (int)spec.volume_count;
    std::vector<std::vector<uint8_t>> data(D);
    std::vector<char> present(D, 0);
    for (int j = 0; j < D; ++j) {
        std::string full = dir.empty() ? spec.names[j] : (u8p(dir) / u8p(spec.names[j])).u8string();
        if (read_all(full, data[j])) {
            present[j] = 1;
            if (data[j].size() < spec.payload.size() && !revs.empty()) {
                // padded later to the parity length
            }
        }
    }
    std::vector<int> missing;
    for (int j = 0; j < D; ++j) if (!present[j]) missing.push_back(j);
    if (missing.empty()) return true;

    std::sort(revs.begin(), revs.end(), [](const RevFile& a, const RevFile& b) {
        return a.parity_index < b.parity_index;
    });
    // Keep rev files that describe the same set.
    std::vector<RevFile> usable;
    for (auto& r : revs) {
        if (r.volume_count == spec.volume_count && r.names == spec.names) usable.push_back(std::move(r));
    }
    if ((int)usable.size() < (int)missing.size()) {
        if (err) *err = msg("err.rev");
        return false;
    }
    usable.resize(missing.size());
    size_t max_len = 0;
    for (const auto& r : usable) max_len = std::max(max_len, r.payload.size());
    for (int j = 0; j < D; ++j) if (present[j]) max_len = std::max(max_len, data[j].size());
    for (int j = 0; j < D; ++j) if (present[j]) data[j].resize(max_len, 0);
    for (auto& r : usable) r.payload.resize(max_len, 0);

    const Gf& g = gf();
    int m = (int)missing.size();
    std::vector<std::vector<uint8_t>> mat(m, std::vector<uint8_t>(m, 0));
    for (int r = 0; r < m; ++r) {
        for (int c = 0; c < m; ++c) {
            mat[r][c] = g.coeff((int)usable[r].parity_index, missing[c]);
        }
    }
    std::vector<std::vector<uint8_t>> inv;
    if (!invert(mat, inv)) {
        if (err) *err = msg("err.rev");
        return false;
    }

    std::vector<std::vector<uint8_t>> recovered(m, std::vector<uint8_t>(max_len, 0));
    for (size_t i = 0; i < max_len; ++i) {
        std::vector<uint8_t> rhs(m, 0);
        for (int r = 0; r < m; ++r) {
            uint8_t v = usable[r].payload[i];
            for (int j = 0; j < D; ++j) {
                if (!present[j]) continue;
                v ^= g.mul(g.coeff((int)usable[r].parity_index, j), data[j][i]);
            }
            rhs[r] = v;
        }
        for (int c = 0; c < m; ++c) {
            uint8_t acc = 0;
            for (int r = 0; r < m; ++r) acc ^= g.mul(inv[c][r], rhs[r]);
            recovered[c][i] = acc;
        }
    }
    for (int c = 0; c < m; ++c) {
        int j = missing[c];
        uint64_t sz = spec.sizes[j];
        if (sz > recovered[c].size()) sz = recovered[c].size();
        std::string full = dir.empty() ? spec.names[j] : (u8p(dir) / u8p(spec.names[j])).u8string();
        if (!write_all(full, recovered[c].data(), (size_t)sz)) {
            if (err) *err = msgf("arc.write", full);
            return false;
        }
        restored.push_back(full);
    }
    return true;
}

} // namespace openrar
