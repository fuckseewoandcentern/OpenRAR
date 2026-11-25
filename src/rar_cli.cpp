/*
 * OpenRAR - Clean-Room RAR 5.0 Command-Line Interface (CLI) Implementation
 * Replicates the official WinRAR CLI (Rar.exe) and unrar-free CLI behavior
 * without any proprietary code or registration/activation mechanism.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_cli.h"
#include "rar_i18n.h"
#include "rar_os.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

namespace fs = std::filesystem;

namespace openrar {

namespace {

// UTF-8 <-> UTF-16 helpers for Windows filesystem and console
#ifdef _WIN32
std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (len <= 0) return std::wstring();
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &ws[0], len);
    return ws;
}

std::string wide_to_utf8(const std::wstring& ws) {
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

fs::path make_fspath(const std::string& utf8_path) {
    return fs::path(utf8_to_wide(utf8_path));
}

std::string fspath_to_utf8(const fs::path& p) {
    return wide_to_utf8(p.wstring());
}
#else
fs::path make_fspath(const std::string& utf8_path) {
    return fs::path(utf8_path);
}

std::string fspath_to_utf8(const fs::path& p) {
    return p.string();
}
#endif

// Console-aware text output (uses WriteConsoleW on Windows interactive consoles to prevent GBK/UTF-8 garbling)
void print_stream(FILE* stream, const std::string& text) {
    if (text.empty()) return;
#ifdef _WIN32
    int fd = _fileno(stream);
    if (fd >= 0) {
        HANDLE h = (HANDLE)_get_osfhandle(fd);
        DWORD mode = 0;
        if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
            std::wstring ws = utf8_to_wide(text);
            DWORD written = 0;
            WriteConsoleW(h, ws.data(), (DWORD)ws.size(), &written, nullptr);
            return;
        }
    }
#endif
    fwrite(text.data(), 1, text.size(), stream);
    fflush(stream);
}

void out_print(const CliConfig& cfg, const std::string& text) {
    if (cfg.quiet_all || cfg.quiet_mode) return;
    FILE* target = cfg.msg_to_stderr ? stderr : stdout;
    print_stream(target, text);
}

void out_println(const CliConfig& cfg, const std::string& text = "") {
    out_print(cfg, text + "\n");
}

void err_println(const CliConfig& cfg, const std::string& text) {
    if (!cfg.log_file.empty()) {
        std::ofstream lf(make_fspath(cfg.log_file), std::ios::app);
        if (lf) lf << text << "\n";
    }
    if (cfg.quiet_all) return;
    print_stream(stderr, text + "\n");
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string to_upper_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    return s;
}

std::string normalize_internal_slashes(std::string s) {
    for (char& c : s) {
        if (c == '\\') c = '/';
    }
    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    return s;
}

std::string to_native_slashes(std::string s) {
#ifdef _WIN32
    for (char& c : s) {
        if (c == '/') c = '\\';
    }
#endif
    return s;
}

// Wildcard matching (* and ?), case-insensitive on Windows
bool wildcard_match(const std::string& pattern, const std::string& str, bool case_sensitive = false) {
    std::string p = case_sensitive ? normalize_internal_slashes(pattern)
                                   : to_lower_ascii(normalize_internal_slashes(pattern));
    std::string s = case_sensitive ? normalize_internal_slashes(str)
                                   : to_lower_ascii(normalize_internal_slashes(str));
    if (p == "*" || p == "*.*") return true;

    size_t pi = 0, si = 0;
    size_t star_idx = std::string::npos, match_idx = 0;
    while (si < s.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == s[si])) {
            ++pi;
            ++si;
        } else if (pi < p.size() && p[pi] == '*') {
            star_idx = pi++;
            match_idx = si;
        } else if (star_idx != std::string::npos) {
            pi = star_idx + 1;
            si = ++match_idx;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

bool matches_entry_filters(const CliConfig& cfg, const std::string& internal_name, uint64_t size, uint64_t mtime_winft) {
    std::string base_name = internal_name;
    auto slash_pos = base_name.find_last_of('/');
    if (slash_pos != std::string::npos) base_name = base_name.substr(slash_pos + 1);

    // Exclude masks (-x)
    for (const auto& ex : cfg.exclude_masks) {
        if (wildcard_match(ex, internal_name) || wildcard_match(ex, base_name)) {
            return false;
        }
    }

    // Include masks (-n)
    if (!cfg.include_masks.empty()) {
        bool inc_ok = false;
        for (const auto& inc : cfg.include_masks) {
            if (wildcard_match(inc, internal_name) || wildcard_match(inc, base_name)) {
                inc_ok = true;
                break;
            }
        }
        if (!inc_ok) return false;
    }

    // Positional file filters (if specified for x/e/l/v/t/d/p)
    if (!cfg.file_args.empty()) {
        bool arg_ok = false;
        for (const auto& farg : cfg.file_args) {
            std::string norm_arg = normalize_internal_slashes(farg);
            if (wildcard_match(norm_arg, internal_name) ||
                wildcard_match(norm_arg, base_name) ||
                (internal_name.size() > norm_arg.size() &&
                 internal_name.compare(0, norm_arg.size(), norm_arg) == 0 &&
                 internal_name[norm_arg.size()] == '/')) {
                arg_ok = true;
                break;
            }
        }
        if (!arg_ok) return false;
    }

    if (cfg.size_less > 0 && size >= cfg.size_less) return false;
    if (cfg.size_more > 0 && size <= cfg.size_more) return false;
    if (cfg.time_after > 0 && mtime_winft < cfg.time_after) return false;
    if (cfg.time_before > 0 && mtime_winft > cfg.time_before) return false;
    if (cfg.time_newer_sec > 0) {
        uint64_t now_ft = current_win_filetime();
        uint64_t cutoff = now_ft - cfg.time_newer_sec * 10000000ULL;
        if (mtime_winft < cutoff) return false;
    }
    if (cfg.time_older_sec > 0) {
        uint64_t now_ft = current_win_filetime();
        uint64_t cutoff = now_ft - cfg.time_older_sec * 10000000ULL;
        if (mtime_winft > cutoff) return false;
    }
    return true;
}

void print_banner(const CliConfig& cfg) {
    if (cfg.quiet_copyright || cfg.quiet_all || cfg.quiet_mode) return;
    out_println(cfg, "");
    out_println(cfg, msg("banner.title"));
    out_println(cfg, "");
}

void print_help(const CliConfig& cfg) {
    print_banner(cfg);
    out_println(cfg, msg("help.body"));
}


uint64_t parse_size_With_unit(const std::string& str, char default_unit = 'b') {
    if (str.empty()) return 0;
    size_t idx = 0;
    uint64_t val = 0;
    while (idx < str.size() && std::isdigit((unsigned char)str[idx])) {
        val = val * 10 + (str[idx] - '0');
        ++idx;
    }
    char unit = (idx < str.size()) ? str[idx] : default_unit;
    switch (unit) {
        case 'b': case 'B': return val;
        case 'k': return val * 1024ULL;
        case 'K': return val * 1000ULL;
        case 'm': return val * 1024ULL * 1024ULL;
        case 'M': return val * 1000ULL * 1000ULL;
        case 'g': return val * 1024ULL * 1024ULL * 1024ULL;
        case 'G': return val * 1000ULL * 1000ULL * 1000ULL;
        case 'f': return val * 1457664ULL;
        default:  return val * 1000ULL; // WinRAR default for -v<size> without suffix is *1000
    }
}

uint64_t parse_rar_date_to_winft(const std::string& dstr) {
    // Format: YYYYMMDD[HHMMSS]
    if (dstr.size() < 8) return 0;
    std::tm tm_val{};
    tm_val.tm_year = std::stoi(dstr.substr(0, 4)) - 1900;
    tm_val.tm_mon  = std::stoi(dstr.substr(4, 2)) - 1;
    tm_val.tm_mday = std::stoi(dstr.substr(6, 2));
    if (dstr.size() >= 10) tm_val.tm_hour = std::stoi(dstr.substr(8, 2));
    if (dstr.size() >= 12) tm_val.tm_min  = std::stoi(dstr.substr(10, 2));
    if (dstr.size() >= 14) tm_val.tm_sec  = std::stoi(dstr.substr(12, 2));
    tm_val.tm_isdst = -1;
    time_t t = std::mktime(&tm_val);
    if (t == (time_t)-1) return 0;
    return unix_to_win_filetime((int64_t)t, 0);
}

uint64_t parse_rar_duration_seconds(const std::string& tstr) {
    // Format: [Nd][Nh][Nm][Ns] e.g. 10d, 2h30m, 45s
    uint64_t total_sec = 0;
    uint64_t cur = 0;
    for (char c : tstr) {
        if (std::isdigit((unsigned char)c)) {
            cur = cur * 10 + (c - '0');
        } else {
            char lc = (char)std::tolower((unsigned char)c);
            if (lc == 'd') total_sec += cur * 86400ULL;
            else if (lc == 'h') total_sec += cur * 3600ULL;
            else if (lc == 'm') total_sec += cur * 60ULL;
            else if (lc == 's') total_sec += cur;
            cur = 0;
        }
    }
    total_sec += cur;
    return total_sec;
}

bool charset_applies(const CliConfig& cfg, char obj) {
    if (cfg.charset != 'a' && cfg.charset != 'o') return false;
    if (cfg.charset_objects.empty()) return true;
    return cfg.charset_objects.find(obj) != std::string::npos;
}

void read_list_file(const std::string& list_path, std::vector<std::string>& out_items, char charset = 0) {
    std::istream* in = nullptr;
    std::ifstream fin;
    if (list_path.empty()) {
        in = &std::cin;
    } else {
        fin.open(make_fspath(list_path));
        if (!fin) return;
        in = &fin;
    }
    std::string line;
    while (std::getline(*in, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ')) {
            line.pop_back();
        }
        size_t start = 0;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) ++start;
        line = line.substr(start);
        if (!line.empty() && line.substr(0, 3) == "\xEF\xBB\xBF") line = line.substr(3);
        if (!line.empty() && line[0] != ';') {
            if (line.size() >= 2 && line.front() == '"' && line.back() == '"') {
                line = line.substr(1, line.size() - 2);
            }
            if (charset == 'a' || charset == 'o') line = decode_text(line, charset);
            out_items.push_back(line);
        }
    }
}

void format_winft_datetime(uint64_t winft, std::string& out_date, std::string& out_time, std::string* out_full_ns = nullptr) {
    if (winft == 0) {
        out_date = "0000-00-00";
        out_time = "00:00";
        if (out_full_ns) *out_full_ns = "0000-00-00 00:00:00,0000000";
        return;
    }
    int64_t unix_sec = 0;
    uint32_t nsec = 0;
    win_filetime_to_unix(winft, unix_sec, nsec);
    time_t tt = (time_t)unix_sec;
    std::tm local_tm{};
#ifdef _WIN32
    localtime_s(&local_tm, &tt);
#else
    localtime_r(&tt, &local_tm);
#endif
    char dbuf[32], tbuf[32];
    std::snprintf(dbuf, sizeof(dbuf), "%04d-%02d-%02d",
                  local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday);
    std::snprintf(tbuf, sizeof(tbuf), "%02d:%02d",
                  local_tm.tm_hour, local_tm.tm_min);
    out_date = dbuf;
    out_time = tbuf;
    if (out_full_ns) {
        char fbuf[64];
        std::snprintf(fbuf, sizeof(fbuf), "%04d-%02d-%02d %02d:%02d:%02d,%07u",
                      local_tm.tm_year + 1900, local_tm.tm_mon + 1, local_tm.tm_mday,
                      local_tm.tm_hour, local_tm.tm_min, local_tm.tm_sec, nsec / 100);
        *out_full_ns = fbuf;
    }
}

std::string format_attributes(const RarFileEntry& e) {
    if (e.host_os == HOST5_UNIX) {
        unsigned mode = (unsigned)e.attributes;
        char buf[11];
        unsigned type = mode & 0170000u;
        if (e.redir_type == REDIR5_UNIXSYMLINK || e.redir_type == REDIR5_WINSYMLINK || type == 0120000u) buf[0] = 'l';
        else if (e.is_dir || type == 0040000u) buf[0] = 'd';
        else buf[0] = '-';
        const char* rwx = "rwxrwxrwx";
        for (int i = 0; i < 9; ++i) buf[1 + i] = (mode & (1u << (8 - i))) ? rwx[i] : '-';
        buf[10] = '\0';
        return std::string(buf);
    }
    char buf[8] = {'.', '.', '.', '.', '.', '.', '.', '\0'};
    if (e.is_dir || (e.attributes & 0x10)) buf[3] = 'D';
    if (e.attributes & 0x20) buf[2] = 'A';
    if (e.attributes & 0x04) buf[4] = 'S';
    if (e.attributes & 0x02) buf[5] = 'H';
    if (e.attributes & 0x01) buf[6] = 'R';
    return std::string(buf);
}

void get_file_times_and_attrs(const fs::path& p, bool is_dir,
                              uint64_t& mtime_winft, uint64_t& ctime_winft,
                              uint64_t& atime_winft, uint64_t& attrs,
                              OsFileInfo* full = nullptr) {
    OsFileInfo info;
    if (!get_file_info(fspath_to_utf8(p), info)) {
        mtime_winft = current_win_filetime();
        ctime_winft = mtime_winft;
        atime_winft = mtime_winft;
        attrs = is_dir ? 0x10 : 0x20;
        info.attributes = attrs;
        info.is_dir = is_dir;
        info.mtime_winft = mtime_winft;
        info.ctime_winft = ctime_winft;
        info.atime_winft = atime_winft;
#ifdef _WIN32
        info.host_os = HOST5_WINDOWS;
#else
        info.host_os = HOST5_UNIX;
#endif
    } else {
        mtime_winft = info.mtime_winft;
        ctime_winft = info.ctime_winft;
        atime_winft = info.atime_winft;
        attrs = info.attributes;
    }
    if (full) *full = info;
}

void apply_extracted_times_and_attrs(const fs::path& p, const RarFileEntry& e, const CliConfig& cfg) {
    OsFileInfo info;
    info.mtime_winft = e.mtime_winft;
    info.ctime_winft = e.ctime_winft;
    info.atime_winft = e.atime_winft;
    info.attributes = e.attributes;
    info.host_os = e.host_os;
    info.is_dir = e.is_dir;
    info.is_symlink = (e.redir_type == REDIR5_UNIXSYMLINK || e.redir_type == REDIR5_WINSYMLINK);
    info.has_owner = e.has_owner;
    info.uid = e.owner_uid;
    info.gid = e.owner_gid;
    info.user = e.owner_user;
    info.group = e.owner_group;
    apply_file_info(fspath_to_utf8(p), info, !cfg.ignore_attributes, cfg.save_owner,
                    cfg.clear_archive_attr, cfg.ntfs_compress);
}

std::string ensure_archive_extension(const std::string& path, bool is_sfx) {
    fs::path p = make_fspath(path);
    if (p.has_extension()) return path;
#ifdef _WIN32
    return path + (is_sfx ? ".exe" : ".rar");
#else
    return path + (is_sfx ? ".sfx" : ".rar");
#endif
}

std::string apply_ag_format(const std::string& base_path, const std::string& fmt) {
    if (fmt.empty()) return base_path;
    time_t now = std::time(nullptr);
    std::tm tm_now{};
#ifdef _WIN32
    localtime_s(&tm_now, &now);
#else
    localtime_r(&now, &tm_now);
#endif
    // Replace YYYY, YY, MM, DD, HH, MN, SS in format string
    std::string stamp;
    size_t i = 0;
    while (i < fmt.size()) {
        auto count_char = [&](char ch) {
            size_t cnt = 0;
            while (i + cnt < fmt.size() && fmt[i + cnt] == ch) ++cnt;
            return cnt;
        };
        if (fmt[i] == 'Y') {
            size_t cnt = count_char('Y');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%04d", tm_now.tm_year + 1900);
            std::string ys(buf);
            stamp += (cnt >= 4) ? ys : ys.substr(2);
            i += cnt;
        } else if (fmt[i] == 'M') {
            size_t cnt = count_char('M');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_mon + 1);
            stamp += buf;
            i += cnt;
        } else if (fmt[i] == 'D') {
            size_t cnt = count_char('D');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_mday);
            stamp += buf;
            i += cnt;
        } else if (fmt[i] == 'H') {
            size_t cnt = count_char('H');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_hour);
            stamp += buf;
            i += cnt;
        } else if (fmt[i] == 'S') {
            size_t cnt = count_char('S');
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%02d", tm_now.tm_sec);
            stamp += buf;
            i += cnt;
        } else {
            stamp.push_back(fmt[i++]);
        }
    }
    fs::path p = make_fspath(base_path);
    std::string ext = fspath_to_utf8(p.extension());
    std::string stem = fspath_to_utf8(p.parent_path() / p.stem());
    return stem + stamp + ext;
}

std::string compute_internal_name(const CliConfig& cfg, const fs::path& full_path, const fs::path& base_arg_path) {
    std::string name;
    if (cfg.ep_mode == 0) {
        // -ep: exclude all paths, store filename only
        name = fspath_to_utf8(full_path.filename());
    } else if (cfg.ep_mode == 2 || cfg.ep_mode == 3) {
        // -ep2 / -ep3: full path
        name = normalize_internal_slashes(fspath_to_utf8(full_path));
        if (cfg.ep_mode == 2 && name.size() >= 2 && name[1] == ':') {
            name = name.substr(2);
            while (!name.empty() && name.front() == '/') name.erase(name.begin());
        } else if (cfg.ep_mode == 3 && name.size() >= 2 && name[1] == ':') {
            name[1] = '_';
        }
    } else {
        // -ep1 (default): strip parent of base_arg_path
        fs::path parent = base_arg_path.parent_path();
        if (!parent.empty()) {
            std::error_code ec;
            fs::path rel = fs::relative(full_path, parent, ec);
            if (!ec && !rel.empty() && fspath_to_utf8(rel).substr(0, 2) != "..") {
                name = normalize_internal_slashes(fspath_to_utf8(rel));
            } else {
                name = normalize_internal_slashes(fspath_to_utf8(full_path.filename()));
            }
        } else {
            name = normalize_internal_slashes(fspath_to_utf8(full_path));
            if (name.size() >= 2 && name[1] == ':') {
                name = name.substr(2);
            }
            while (name.substr(0, 2) == "./") name = name.substr(2);
        }
    }

    if (!cfg.ep4_prefix.empty()) {
        std::string pfx = normalize_internal_slashes(cfg.ep4_prefix);
        if (!pfx.empty() && pfx.back() != '/') pfx.push_back('/');
        if (name.size() > pfx.size() &&
            to_lower_ascii(name.substr(0, pfx.size())) == to_lower_ascii(pfx)) {
            name = name.substr(pfx.size());
        }
    }

    if (!cfg.ap_prefix.empty()) {
        std::string ap = normalize_internal_slashes(cfg.ap_prefix);
        while (!ap.empty() && ap.back() == '/') ap.pop_back();
        if (!ap.empty()) name = ap + "/" + name;
    }

    if (cfg.case_convert == 1) name = to_lower_ascii(name);
    else if (cfg.case_convert == 2) name = to_upper_ascii(name);

    return normalize_internal_slashes(name);
}

bool parse_switch(const std::string& sw_raw, CliConfig& cfg, const std::vector<std::string>& args, size_t& arg_idx) {
    // Handle GNU long options (unrar-free compatibility)
    if (sw_raw.size() >= 2 && sw_raw[0] == '-' && sw_raw[1] == '-') {
        std::string lopt = sw_raw.substr(2);
        if (lopt.empty()) return false; // "--" stops switch scanning
        if (lopt == "help") { cfg.show_help = true; return true; }
        if (lopt == "version") { cfg.show_version = true; return true; }
        if (lopt == "extract") { if (cfg.command.empty()) cfg.command = "x"; return true; }
        if (lopt == "extract-no-paths") {
            if (cfg.command.empty()) cfg.command = "e";
            cfg.ep_mode = 0;
            return true;
        }
        if (lopt == "extract-newer") {
            cfg.extract_newer = true;
            if (cfg.command.empty()) cfg.command = "x";
            return true;
        }
        if (lopt == "list") { if (cfg.command.empty()) cfg.command = "l"; return true; }
        if (lopt == "print") { if (cfg.command.empty()) cfg.command = "p"; return true; }
        if (lopt == "force") { cfg.overwrite_mode = 1; cfg.assume_yes = true; return true; }
        if (lopt == "verbose") { if (cfg.command == "l") cfg.command = "v"; return true; }
        if (lopt == "password") {
            if (arg_idx + 1 < args.size()) cfg.arch_opts.password = args[++arg_idx];
            return true;
        }
        if (lopt.substr(0, 9) == "password=") {
            cfg.arch_opts.password = lopt.substr(9);
            return true;
        }
        if (lopt == "outfile") {
            if (arg_idx + 1 < args.size()) cfg.log_file = args[++arg_idx];
            return true;
        }
        return true;
    }

    std::string sw = sw_raw.substr(1);
    if (sw.empty() || sw == "-") return false; // "-" stops switch scanning
    std::string sw_low = to_lower_ascii(sw);

    if (sw_low == "?" || sw_low == "h") { cfg.show_help = true; return true; }
    if (sw_low == "iver" || sw == "V") { cfg.show_version = true; return true; }
    if (sw_low == "y") { cfg.assume_yes = true; cfg.overwrite_mode = 1; return true; }
    if (sw_low == "o+" || sw_low == "o") { cfg.overwrite_mode = 1; return true; }
    if (sw_low == "o-") { cfg.overwrite_mode = -1; return true; }
    if (sw_low == "or") { cfg.auto_rename = true; return true; }
    if (sw_low == "ol" || sw_low == "ola") { cfg.save_symlinks = true; return true; }
    if (sw_low == "ol-") { cfg.save_symlinks = false; return true; }
    if (sw_low == "oh") { cfg.save_hardlinks = true; return true; }
    if (sw_low == "ow") { cfg.save_owner = true; return true; }
    if (sw_low == "oc") { cfg.ntfs_compress = true; return true; }
    if (sw_low == "oni") { cfg.allow_incompatible = true; return true; }
    if (sw_low == "ao") { cfg.archive_attr_only = true; return true; }
    if (sw_low == "en") { cfg.arch_opts.omit_endarc = true; return true; }
    if (sw_low == "dh") { cfg.open_shared = true; return true; }
    if (sw_low == "f") { cfg.freshen_switch = true; cfg.update_switch = false; return true; }
    if (sw_low == "u") { cfg.update_switch = true; cfg.freshen_switch = false; return true; }
    if (sw_low == "@" || sw_low == "@-") { cfg.disable_lists = true; return true; }
    if (sw_low == "@+") { cfg.disable_lists = false; return true; }
    if (sw_low.substr(0, 2) == "ri") {
        std::string rest = sw_low.substr(2);
        auto colon = rest.find(':');
        std::string ps = (colon == std::string::npos) ? rest : rest.substr(0, colon);
        std::string ss = (colon == std::string::npos) ? std::string() : rest.substr(colon + 1);
        if (!ps.empty()) cfg.priority = std::atoi(ps.c_str());
        if (!ss.empty()) cfg.sleep_ms = std::atoi(ss.c_str());
        return true;
    }
    if (sw_low == "r") { cfg.recurse = true; cfg.disable_recurse = false; return true; }
    if (sw_low == "r0") { cfg.recurse_wildcard = true; return true; }
    if (sw_low == "r-") { cfg.disable_recurse = true; cfg.recurse = false; return true; }
    if (sw_low == "k") { cfg.arch_opts.lock_archive = true; return true; }
    if (sw_low == "kb") { cfg.keep_broken = true; return true; }
    if (sw_low == "t") { cfg.test_after_archive = true; return true; }
    if (sw_low == "df") { cfg.delete_after = true; cfg.wipe_after = false; cfg.recycle_after = false; return true; }
    if (sw_low == "dr") { cfg.delete_after = true; cfg.recycle_after = true; cfg.wipe_after = false; return true; }
    if (sw_low == "dw") { cfg.delete_after = true; cfg.wipe_after = true; cfg.recycle_after = false; return true; }
    if (sw_low == "ed") { cfg.no_empty_dirs = true; return true; }
    if (sw_low == "ac") { cfg.clear_archive_attr = true; return true; }
    if (sw_low == "ai") { cfg.ignore_attributes = true; return true; }
    if (sw_low == "cl") { cfg.case_convert = 1; return true; }
    if (sw_low == "cu") { cfg.case_convert = 2; return true; }
    if (sw_low == "ds") { cfg.disable_sort = true; return true; }
    if (sw_low == "as") { cfg.sync_archive = true; return true; }
    if (sw_low == "tk") { cfg.keep_archive_time = true; return true; }
    if (sw_low == "tl") { cfg.latest_archive_time = true; return true; }
    if (sw_low == "c-") { cfg.disable_comments = true; return true; }
    if (sw_low == "cfg-") { return true; }
    if (sw_low == "inul") { cfg.quiet_all = true; return true; }
    if (sw_low == "ierr") { cfg.msg_to_stderr = true; return true; }
    if (sw_low == "isnd") { cfg.beep_when_done = true; return true; }
    if (sw_low.substr(0, 4) == "ioff") {
        cfg.power_off = 1;
        if (sw_low.size() > 4 && std::isdigit(static_cast<unsigned char>(sw_low[4]))) {
            cfg.power_off = sw_low[4] - '0';
        }
        if (cfg.power_off < 1 || cfg.power_off > 4) cfg.power_off = 1;
        return true;
    }
    if (sw_low.substr(0, 4) == "ieml") {
        std::string rest = sw.substr(4);
        if (!rest.empty() && rest[0] == '.') rest.erase(rest.begin());
        cfg.email_to = rest;
        return true;
    }
    if (sw_low.substr(0, 2) == "id") {
        for (size_t i = 2; i < sw_low.size(); ++i) {
            if (sw_low[i] == 'c') cfg.quiet_copyright = true;
            else if (sw_low[i] == 'd') cfg.quiet_done = true;
            else if (sw_low[i] == 'n') cfg.quiet_names = true;
            else if (sw_low[i] == 'p') cfg.quiet_percent = true;
            else if (sw_low[i] == 'q') cfg.quiet_mode = true;
        }
        return true;
    }
    if (sw_low.substr(0, 4) == "ilog") {
        cfg.log_file = sw.size() > 4 ? sw.substr(4) : "rar.log";
        return true;
    }
    if (sw_low.substr(0, 3) == "log") {
        auto eq = sw.find('=');
        cfg.log_file = (eq != std::string::npos) ? sw.substr(eq + 1) : "rar.log";
        return true;
    }

    // Path modes (-ep, -ep1, -ep2, -ep3, -ep4<path>)
    if (sw_low == "ep") { cfg.ep_mode = 0; return true; }
    if (sw_low == "ep1") { cfg.ep_mode = 1; return true; }
    if (sw_low == "ep2") { cfg.ep_mode = 2; return true; }
    if (sw_low == "ep3") { cfg.ep_mode = 3; return true; }
    if (sw_low.substr(0, 3) == "ep4") { cfg.ep4_prefix = sw.substr(3); return true; }
    if (sw_low.substr(0, 2) == "ap") { cfg.ap_prefix = sw.substr(2); return true; }
    if (sw_low.substr(0, 2) == "op") { cfg.op_path = sw.substr(2); return true; }
    if (sw_low == "ad" || sw_low == "ad1") { cfg.append_arch_dir = 1; return true; }
    if (sw_low == "ad2") { cfg.append_arch_dir = 2; return true; }
    if (sw_low.substr(0, 1) == "w" && sw.size() > 1) { cfg.work_dir = sw.substr(1); return true; }

    // Compression level -m0..5 and dictionary -md<size> and store extensions -ms and threads -mt
    if (sw_low.size() == 2 && sw_low[0] == 'm' && sw_low[1] >= '0' && sw_low[1] <= '5') {
        cfg.arch_opts.method = sw_low[1] - '0';
        cfg.method_explicit = true;
        return true;
    }
    if (sw_low.substr(0, 2) == "ma") {
        int ver = std::atoi(sw_low.c_str() + 2);
        if (ver == 4 || ver == 5) cfg.format_version = ver;
        return true;
    }
    if (sw_low.substr(0, 2) == "md") {
        std::string dstr = sw_low.substr(2);
        if (!dstr.empty() && dstr[0] == 'x') dstr = dstr.substr(1);
        if (!dstr.empty() && dstr[0] == '=') dstr = dstr.substr(1);
        if (!dstr.empty()) {
            // Check letter codes a..j or numeric size
            if (dstr.size() == 1 && dstr[0] >= 'a' && dstr[0] <= 'j') {
                int idx = dstr[0] - 'a';
                cfg.arch_opts.dict_bits = std::max(0, idx - 1);
            } else {
                uint64_t bytes = parse_size_With_unit(dstr, 'm');
                if (bytes < 128 * 1024ULL && bytes <= 1024) {
                    // Bare number <= 1024 in -md<N> means MB in RAR5 (unless >= 128 where 128/256/512 = KB)
                    if (bytes >= 128) bytes *= 1024ULL;
                    else bytes *= 1024ULL * 1024ULL;
                }
                int bits = 0;
                uint64_t sz = 128 * 1024ULL;
                while (sz < bytes && bits < 15) { sz <<= 1; ++bits; }
                cfg.arch_opts.dict_bits = bits;
            }
        }
        return true;
    }
    if (sw_low.substr(0, 2) == "ms") {
        std::string exts = sw_low.substr(2);
        if (exts.empty()) exts = "rar;zip;7z;gz;bz2;xz;jpg;jpeg;png;mp3;mp4;mkv";
        std::stringstream ss(exts);
        std::string item;
        while (std::getline(ss, item, ';')) {
            if (!item.empty()) {
                if (item.front() == '.') item.erase(item.begin());
                cfg.store_exts.push_back(item);
            }
        }
        return true;
    }
    if (sw_low.substr(0, 2) == "mt") {
        std::string n = sw_low.substr(2);
        if (!n.empty() && n[0] == '=') n.erase(n.begin());
        cfg.threads = std::max(1, n.empty() ? 1 : std::atoi(n.c_str()));
        return true;
    }
    if (sw_low.substr(0, 2) == "mc") {
        return true;
    }

    // Solid switches (-s, -s-, -sN, -se, -sv, -sv-, -sc)
    if (sw_low == "s-") { cfg.arch_opts.solid = false; cfg.solid_explicit = true; return true; }
    if (sw_low.substr(0, 2) == "sc") {
        std::string rest = sw_low.substr(2);
        if (!rest.empty()) {
            cfg.charset = rest[0];
            cfg.charset_objects = rest.substr(1);
        }
        return true;
    }
    if (sw_low == "se") {
        cfg.arch_opts.solid = true;
        cfg.solid_by_extension = true;
        cfg.solid_explicit = true;
        return true;
    }
    if (sw_low == "sv") {
        cfg.arch_opts.solid = true;
        cfg.independent_volumes = true;
        cfg.solid_explicit = true;
        return true;
    }
    if (sw_low == "sv-") {
        cfg.arch_opts.solid = true;
        cfg.independent_volumes = false;
        cfg.solid_explicit = true;
        return true;
    }
    if (sw_low == "s") { cfg.arch_opts.solid = true; cfg.solid_explicit = true; return true; }
    if (sw_low.size() > 1 && sw_low[0] == 's' && std::isdigit(static_cast<unsigned char>(sw_low[1]))) {
        cfg.arch_opts.solid = true;
        cfg.solid_explicit = true;
        cfg.solid_files = std::max(1, std::atoi(sw_low.substr(1).c_str()));
        return true;
    }

    // Hash type (-htb, -htc)
    if (sw_low == "htb") { cfg.arch_opts.use_blake2sp = true; return true; }
    if (sw_low == "htc") { cfg.arch_opts.use_blake2sp = false; return true; }

    // Password (-p[pwd], -hp[pwd]). A bare -p or -hp asks on a terminal.
    if (sw_low == "hp" || sw_low == "p") {
        if (sw_low == "hp") cfg.arch_opts.encrypt_headers = true;
        cfg.arch_opts.password.clear();
        cfg.prompt_password = true;
        return true;
    }
    if (sw_low.substr(0, 2) == "hp") {
        cfg.arch_opts.encrypt_headers = true;
        cfg.arch_opts.password = sw.substr(2);
        cfg.prompt_password = cfg.arch_opts.password.empty();
        return true;
    }
    if (sw_low[0] == 'p' || sw[0] == 'P') {
        cfg.arch_opts.password = sw.substr(1);
        cfg.prompt_password = cfg.arch_opts.password.empty();
        return true;
    }

    // Recovery record (-rr[N]) and recovery volumes (-rv[N])
    if (sw_low.substr(0, 2) == "rr") {
        std::string rstr = sw_low.substr(2);
        int pct = 3;
        if (!rstr.empty()) pct = std::max(1, std::atoi(rstr.c_str()));
        cfg.arch_opts.recovery_percent = pct;
        return true;
    }
    if (sw_low.substr(0, 2) == "rv") {
        std::string rstr = sw_low.substr(2);
        cfg.recovery_volumes = rstr.empty() ? 1 : std::max(1, std::atoi(rstr.c_str()));
        return true;
    }

    // Quick open (-qo[-|+])
    if (sw_low.substr(0, 2) == "qo") {
        cfg.arch_opts.quick_open = (sw_low != "qo-");
        return true;
    }

    // SFX (-sfx[name])
    if (sw_low.substr(0, 3) == "sfx") {
        cfg.create_sfx = true;
        cfg.sfx_stub_name = sw.substr(3);
        return true;
    }

    if (sw_low == "vn") { cfg.arch_opts.old_volume_names = true; return true; }
    if (sw_low == "vp") { cfg.pause_volumes = true; return true; }
    if (sw_low == "vd") { return true; }

    // Volume size (-v<size>[u])
    if (sw_low[0] == 'v' && sw_low.substr(0, 3) != "ver") {
        std::string vstr = sw.substr(1);
        if (!vstr.empty()) {
            cfg.arch_opts.volume_size = parse_size_With_unit(vstr, '\0');
        }
        return true;
    }

    // File version control (-ver[n])
    if (sw_low.substr(0, 3) == "ver") {
        cfg.version_control = true;
        if (sw.size() > 3) cfg.max_versions = std::atoi(sw.substr(3).c_str());
        return true;
    }

    // Comment from file (-z[file])
    if (sw_low[0] == 'z') {
        cfg.comment_file = sw.substr(1);
        return true;
    }

    // Read from stdin (-si[name])
    if (sw_low.substr(0, 2) == "si") {
        cfg.read_from_stdin = true;
        cfg.stdin_name = sw.size() > 2 ? sw.substr(2) : "stdin";
        return true;
    }

    // Archive name timestamp (-ag[format])
    if (sw_low.substr(0, 2) == "ag") {
        cfg.ag_format = sw.size() > 2 ? sw.substr(2) : "YYYYMMDDHHMMSS";
        return true;
    }

    // Time saving (-ts[m,c,a])
    if (sw_low.substr(0, 2) == "ts") {
        for (size_t i = 2; i < sw_low.size(); ++i) {
            if (sw_low[i] == 'c') cfg.arch_opts.save_ctime = (i + 1 >= sw_low.size() || sw_low[i + 1] != '-');
            if (sw_low[i] == 'a') cfg.arch_opts.save_atime = (i + 1 >= sw_low.size() || sw_low[i + 1] != '-');
        }
        return true;
    }

    // Size & time filters (-sl, -sm, -ta, -tb, -tn, -to)
    if (sw_low.substr(0, 2) == "sl") { cfg.size_less = parse_size_With_unit(sw.substr(2), 'b'); return true; }
    if (sw_low.substr(0, 2) == "sm") { cfg.size_more = parse_size_With_unit(sw.substr(2), 'b'); return true; }
    if (sw_low.substr(0, 2) == "ta") { cfg.time_after = parse_rar_date_to_winft(sw.substr(2)); return true; }
    if (sw_low.substr(0, 2) == "tb") { cfg.time_before = parse_rar_date_to_winft(sw.substr(2)); return true; }
    if (sw_low.substr(0, 2) == "tn") { cfg.time_newer_sec = parse_rar_duration_seconds(sw.substr(2)); return true; }
    if (sw_low.substr(0, 2) == "to") { cfg.time_older_sec = parse_rar_duration_seconds(sw.substr(2)); return true; }

    // Include & Exclude masks (-n, -n@, -x, -x@)
    if (sw_low.substr(0, 2) == "n@") {
        read_list_file(sw.substr(2), cfg.include_masks, charset_applies(cfg, 'l') ? cfg.charset : 0);
        return true;
    }
    if (sw_low[0] == 'n' && sw.size() > 1) {
        cfg.include_masks.push_back(sw.substr(1));
        return true;
    }
    if (sw_low.substr(0, 2) == "x@") {
        read_list_file(sw.substr(2), cfg.exclude_masks, charset_applies(cfg, 'l') ? cfg.charset : 0);
        return true;
    }
    if (sw_low[0] == 'x' && sw.size() > 1) {
        cfg.exclude_masks.push_back(sw.substr(1));
        return true;
    }

    return true;
}

bool is_known_command(const std::string& token, CliConfig& cfg) {
    std::string low = to_lower_ascii(token);
    if (low == "a" || low == "c" || low == "ch" || low == "cw" || low == "d" ||
        low == "e" || low == "f" || low == "k" || low == "l" || low == "lt" ||
        low == "lta" || low == "lb" || low == "m" || low == "mf" || low == "p" ||
        low == "r" || low == "rc" || low == "rn" || low == "s-" || low == "t" ||
        low == "u" || low == "v" || low == "vt" || low == "vta" || low == "vb" ||
        low == "x") {
        cfg.command = low;
        if (low == "m") cfg.delete_after = true;
        if (low == "mf") { cfg.delete_after = true; cfg.move_files_only = true; }
        return true;
    }
    if (low.substr(0, 2) == "rr" && (low.size() == 2 || std::isdigit((unsigned char)low[2]))) {
        cfg.command = "rr";
        cfg.arch_opts.recovery_percent = (low.size() > 2) ? std::max(1, std::atoi(low.substr(2).c_str())) : 3;
        return true;
    }
    if (low.substr(0, 2) == "rv" && (low.size() == 2 || std::isdigit((unsigned char)low[2]))) {
        cfg.command = "rv";
        cfg.recovery_volumes = (low.size() > 2) ? std::max(1, std::atoi(low.substr(2).c_str())) : 1;
        return true;
    }
    if (low[0] == 's' && low != "s-") {
        cfg.command = "s";
        if (token.size() > 1) cfg.sfx_stub_name = token.substr(1);
        return true;
    }
    if (low[0] == 'i') {
        auto eq = token.find('=');
        if (eq != std::string::npos) {
            cfg.command = "i";
            cfg.find_params = to_lower_ascii(token.substr(1, eq - 1));
            cfg.find_str = token.substr(eq + 1);
            return true;
        }
    }
    return false;
}

std::vector<std::string> load_config_tokens(const std::string& exe_path) {
    std::vector<std::string> tokens;
    auto take_file = [&](const std::string& path) {
        std::ifstream in(make_fspath(path), std::ios::binary);
        if (!in) return;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            size_t i = 0;
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
            if (i >= line.size() || line[i] == '#' || line[i] == ';') continue;
            std::string cur;
            bool quote = false;
            for (; i < line.size(); ++i) {
                char ch = line[i];
                if (ch == '"') { quote = !quote; continue; }
                if (!quote && (ch == ' ' || ch == '\t')) {
                    if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
                } else {
                    cur.push_back(ch);
                }
            }
            if (!cur.empty()) tokens.push_back(cur);
        }
    };
    for (const auto& path : config_file_candidates(exe_path)) take_file(path);
    std::string env = getenv_utf8("RAR");
    if (!env.empty()) {
        std::string cur;
        bool quote = false;
        for (size_t i = 0; i <= env.size(); ++i) {
            char ch = (i == env.size()) ? ' ' : env[i];
            if (ch == '"') { quote = !quote; continue; }
            if (!quote && (ch == ' ' || ch == '\t')) {
                if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
            } else {
                cur.push_back(ch);
            }
        }
    }
    return tokens;
}

void maybe_prompt_password(CliConfig& cfg) {
    if (!cfg.prompt_password || !cfg.arch_opts.password.empty()) return;
    if (!stdin_is_tty()) return;
    cfg.arch_opts.password = prompt_line(msg("action.password"), true);
}

RarExitCode store_archive(const CliConfig& cfg, RarArchive& arch, const std::string& final_path,
                          const RarArchiveOptions& opts, std::vector<std::string>* volumes,
                          std::string* err) {
    std::error_code ec;
    bool keep_time = false;
    fs::file_time_type old_time{};
    if (cfg.keep_archive_time && fs::exists(make_fspath(final_path), ec)) {
        old_time = fs::last_write_time(make_fspath(final_path), ec);
        keep_time = !ec;
    }
    std::string save_path = final_path;
    if (!cfg.work_dir.empty()) {
        fs::create_directories(make_fspath(cfg.work_dir), ec);
        save_path = path_join(cfg.work_dir, fspath_to_utf8(make_fspath(final_path).filename()));
    }
    if (cfg.pause_volumes) {
        arch.before_volume = [&cfg](const std::string& vol) {
            if (stdin_is_tty()) prompt_line(msgf("action.pause_volume", vol), false);
            return true;
        };
    }
    std::vector<std::string> created;
    RarExitCode rc = arch.save(save_path, opts, &created, err);
    if (rc != RAR_EXIT_SUCCESS) return rc;
    if (save_path != final_path) {
        fs::path dest_dir = make_fspath(final_path).parent_path();
        std::vector<std::string> moved;
        for (const auto& v : created) {
            fs::path src = make_fspath(v);
            fs::path dst = dest_dir.empty() ? src.filename() : (dest_dir / src.filename());
            std::error_code rec;
            if (dst.has_parent_path()) fs::create_directories(dst.parent_path(), rec);
            fs::rename(src, dst, rec);
            if (rec) {
                rec.clear();
                fs::copy_file(src, dst, fs::copy_options::overwrite_existing, rec);
                fs::remove(src, rec);
            }
            moved.push_back(fspath_to_utf8(dst));
        }
        created.swap(moved);
    }
    if (cfg.create_sfx || cfg.command == "s") {
        for (const auto& v : created) make_executable(v);
    }
    if (keep_time) {
        for (const auto& v : created) fs::last_write_time(make_fspath(v), old_time, ec);
    }
    if (cfg.recovery_volumes > 0 && !created.empty()) {
        std::vector<std::string> revs;
        std::string rerr;
        if (write_recovery_volumes(created, cfg.recovery_volumes, opts.old_volume_names, revs, &rerr)) {
            for (const auto& rv : revs) out_println(cfg, msgf("action.rev_write", rv));
        } else if (!rerr.empty()) {
            err_println(cfg, rerr);
        }
    }
    if (!cfg.email_to.empty() && !created.empty()) {
        if (open_mail_composer(cfg.email_to, created.front()))
            out_println(cfg, msgf("action.email", cfg.email_to));
        else
            err_println(cfg, msgf("action.email_missing", cfg.email_to));
    }
    if (volumes) *volumes = std::move(created);
    return RAR_EXIT_SUCCESS;
}

// ============================================================================
// Command Implementations
// ============================================================================

int cmd_list(const CliConfig& cfg) {
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.with_path", err_msg, arch_path));
        return (int)rc;
    }

    bool bare = (cfg.command == "lb" || cfg.command == "vb");
    bool tech = (cfg.command == "lt" || cfg.command == "lta" || cfg.command == "vt" || cfg.command == "vta");
    bool verbose = (cfg.command[0] == 'v');

    if (bare) {
        for (const auto& e : arch.entries) {
            if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) continue;
            out_println(cfg, to_native_slashes(e.name));
        }
        return RAR_EXIT_SUCCESS;
    }

    print_banner(cfg);
    if (!cfg.disable_comments && !arch.comment.empty()) {
        out_println(cfg, arch.comment);
        out_println(cfg, "");
    }

    out_println(cfg, msgf("list.archive", to_native_slashes(arch_path)));
    std::string details = msg("list.details");
    if (arch.is_solid) details += msg("list.solid");
    if (arch.has_recovery) details += msg("list.recovery");
    if (arch.is_locked) details += msg("list.locked");
    if (arch.headers_encrypted) details += msg("list.enc_hdr");
    if (!arch.sfx_stub.empty()) details += msg("list.sfx");
    if (arch.is_volume) details += msg("list.volume");
    out_println(cfg, details);
    out_println(cfg, "");

    if (tech) {
        for (const auto& e : arch.entries) {
            if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) continue;
            out_println(cfg, msgf("list.name", to_native_slashes(e.name)));
            out_println(cfg, msgf("list.type", e.is_dir ? msg("list.type_dir") : msg("list.type_file")));
            if (!e.is_dir) {
                out_println(cfg, msgf("list.size", std::to_string(e.unpacked_size)));
                out_println(cfg, msgf("list.packed", std::to_string(e.packed_size)));
                int ratio = (e.unpacked_size > 0)
                                ? (int)((e.packed_size * 100ULL) / e.unpacked_size)
                                : 0;
                out_println(cfg, msgf("list.ratio", std::to_string(ratio)));
            }
            std::string d_str, t_str, full_ns;
            if (e.mtime_winft != 0) {
                format_winft_datetime(e.mtime_winft, d_str, t_str, &full_ns);
                out_println(cfg, msgf("list.mtime", full_ns));
            }
            if (e.ctime_winft != 0) {
                format_winft_datetime(e.ctime_winft, d_str, t_str, &full_ns);
                out_println(cfg, msgf("list.ctime", full_ns));
            }
            if (e.atime_winft != 0) {
                format_winft_datetime(e.atime_winft, d_str, t_str, &full_ns);
                out_println(cfg, msgf("list.atime", full_ns));
            }
            out_println(cfg, msgf("list.attr", format_attributes(e)));
            if (e.has_blake2sp) {
                std::ostringstream hs;
                hs << std::hex << std::setfill('0');
                for (int i = 0; i < 32; ++i) hs << std::setw(2) << (int)e.blake2sp[i];
                out_println(cfg, "    BLAKE2sp: " + hs.str());
            } else if (e.has_crc32) {
                char cbuf[16];
                std::snprintf(cbuf, sizeof(cbuf), "%08X", e.crc32);
                out_println(cfg, msgf("list.crc", cbuf));
            }
            out_println(cfg, msgf("list.host", e.host_os == HOST5_WINDOWS ? msg("host.windows") : msg("host.unix")));
            uint64_t dict_kb = 128ULL << e.dict_bits;
            std::string dict_str = (dict_kb >= 1024) ? (std::to_string(dict_kb / 1024) + "m") : (std::to_string(dict_kb) + "k");
            out_println(cfg, msgf("list.comp", std::to_string(e.comp_method), dict_str) + (e.solid ? msg("list.solid_word") : ""));
            if (e.encrypted || arch.headers_encrypted) {
                out_println(cfg, msg("list.password"));
            }
            out_println(cfg, "");
        }
        return RAR_EXIT_SUCCESS;
    }

    if (verbose) {
        out_println(cfg, msg("list.hdr_verbose"));
        out_println(cfg, msg("list.rule_verbose"));
    } else {
        out_println(cfg, msg("list.hdr_brief"));
        out_println(cfg, msg("list.rule_brief"));
    }

    uint64_t total_unp = 0;
    uint64_t total_pck = 0;
    size_t count = 0;

    for (const auto& e : arch.entries) {
        if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) continue;
        std::string attr_s = format_attributes(e);
        if (e.encrypted || arch.headers_encrypted) attr_s = "*" + attr_s;
        else attr_s = " " + attr_s;

        std::string d_str, t_str;
        format_winft_datetime(e.mtime_winft, d_str, t_str);
        std::string disp_name = to_native_slashes(e.name);
        if (e.has_version && cfg.version_control) {
            disp_name += ";" + std::to_string(e.version_num);
        }

        if (verbose) {
            int ratio = (e.unpacked_size > 0)
                            ? (int)((e.packed_size * 100ULL) / e.unpacked_size)
                            : 0;
            char cbuf[16];
            if (e.has_crc32) std::snprintf(cbuf, sizeof(cbuf), "%08X", e.crc32);
            else if (e.has_blake2sp) std::snprintf(cbuf, sizeof(cbuf), "%02x%02x%02x%02x", e.blake2sp[0], e.blake2sp[1], e.blake2sp[2], e.blake2sp[3]);
            else std::snprintf(cbuf, sizeof(cbuf), "        ");

            char line[1024];
            std::snprintf(line, sizeof(line), "%-11s %9llu  %8llu %4d%% %10s %5s  %8s  %s",
                          attr_s.c_str(),
                          (unsigned long long)e.unpacked_size,
                          (unsigned long long)e.packed_size,
                          ratio,
                          d_str.c_str(), t_str.c_str(), cbuf, disp_name.c_str());
            out_println(cfg, line);
        } else {
            char line[1024];
            std::snprintf(line, sizeof(line), "%-11s %9llu  %10s %5s  %s",
                          attr_s.c_str(),
                          (unsigned long long)e.unpacked_size,
                          d_str.c_str(), t_str.c_str(), disp_name.c_str());
            out_println(cfg, line);
        }

        total_unp += e.unpacked_size;
        total_pck += e.packed_size;
        ++count;
    }

    if (verbose) {
        out_println(cfg, msg("list.rule_verbose"));
        int total_ratio = (total_unp > 0) ? (int)((total_pck * 100ULL) / total_unp) : 0;
        char sline[256];
        std::snprintf(sline, sizeof(sline), "            %9llu  %8llu %4d%%                             %zu",
                      (unsigned long long)total_unp, (unsigned long long)total_pck, total_ratio, count);
        out_println(cfg, sline);
    } else {
        out_println(cfg, msg("list.rule_brief"));
        char sline[256];
        std::snprintf(sline, sizeof(sline), "            %9llu                    %zu",
                      (unsigned long long)total_unp, count);
        out_println(cfg, sline);
    }

    return RAR_EXIT_SUCCESS;
}

int cmd_test(const CliConfig& cfg) {
    print_banner(cfg);
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)rc;
    }

    if (!cfg.disable_comments && !arch.comment.empty()) {
        out_println(cfg, arch.comment);
        out_println(cfg, "");
    }

    out_println(cfg, msgf("action.testing", to_native_slashes(arch_path)));
    out_println(cfg, "");

    Rar5Decompressor decomp;
    int err_count = 0;
    for (size_t i = 0; i < arch.entries.size(); ++i) {
        const auto& e = arch.entries[i];
        bool selected = matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft);
        if (!selected && !arch.is_solid) continue;

        std::vector<uint8_t> out_data;
        std::string extr_err;
        RarExitCode erc = arch.extract_entry(i, cfg.arch_opts.password, decomp, out_data, &extr_err);
        if (!selected) continue;

        if (erc == RAR_EXIT_SUCCESS) {
            if (!cfg.quiet_names) {
                out_println(cfg, msgf("action.testing_file", to_native_slashes(e.name), msg("status.ok")));
            }
        } else {
            err_println(cfg, msgf("err.test", to_native_slashes(e.name), extr_err));
            ++err_count;
        }
    }

    if (err_count == 0) {
        if (!cfg.quiet_done) out_println(cfg, msg("status.all_ok"));
        return RAR_EXIT_SUCCESS;
    } else {
        err_println(cfg, msgf("err.total", std::to_string(err_count)));
        return RAR_EXIT_CRC_ERROR;
    }
}

int cmd_extract_or_print(CliConfig& cfg, const std::string& self_sfx_path = "") {
    bool is_print = (cfg.command == "p");
    bool full_paths = (cfg.command == "x") && (cfg.ep_mode != 0);

    if (!is_print) print_banner(cfg);

    std::string arch_path = self_sfx_path.empty()
                                ? ensure_archive_extension(cfg.archive_path, false)
                                : self_sfx_path;
    if (self_sfx_path.empty() && !fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }

    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)rc;
    }

    if (!is_print) {
        if (!cfg.disable_comments && !arch.comment.empty()) {
            out_println(cfg, arch.comment);
            out_println(cfg, "");
        }
        out_println(cfg, msgf("action.extracting_from", to_native_slashes(arch_path)));
        out_println(cfg, "");
    }

    fs::path base_out = cfg.op_path.empty() ? make_fspath(cfg.dest_dir) : make_fspath(cfg.op_path);
    if (cfg.append_arch_dir == 1 || cfg.append_arch_dir == 2) {
        base_out /= make_fspath(arch_path).stem();
    }

#ifdef _WIN32
    if (is_print) {
        _setmode(_fileno(stdout), _O_BINARY);
    }
#endif

    Rar5Decompressor decomp;
    int extracted_count = 0;

    for (size_t i = 0; i < arch.entries.size(); ++i) {
        const auto& e = arch.entries[i];
        bool selected = matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft);
        if (!selected && !arch.is_solid) continue;

        std::vector<uint8_t> out_data;
        std::string extr_err;
        RarExitCode erc = arch.extract_entry(i, cfg.arch_opts.password, decomp, out_data, &extr_err);
        if (!selected) continue;

        if (erc != RAR_EXIT_SUCCESS && !cfg.keep_broken) {
            err_println(cfg, msgf("err.extract", to_native_slashes(e.name), extr_err));
            return (int)erc;
        }

        if (is_print) {
            if (!e.is_dir && !out_data.empty()) {
                fwrite(out_data.data(), 1, out_data.size(), stdout);
                fflush(stdout);
            }
            ++extracted_count;
            continue;
        }

        // Compute output relative path
        std::string rel_name = e.name;
        if (!full_paths) {
            auto slash = rel_name.find_last_of('/');
            if (slash != std::string::npos) rel_name = rel_name.substr(slash + 1);
        }
        if (cfg.case_convert == 1) rel_name = to_lower_ascii(rel_name);
        else if (cfg.case_convert == 2) rel_name = to_upper_ascii(rel_name);

        // Sanitize any path traversal ("..") components
        fs::path rel_path;
        for (const auto& part : make_fspath(rel_name)) {
            std::string ps = fspath_to_utf8(part);
            if (ps == ".." || ps == "." || ps.find(':') != std::string::npos) continue;
            rel_path /= part;
        }
        if (rel_path.empty()) continue;

        fs::path out_path = base_out.empty() ? rel_path : (base_out / rel_path);

        if (e.is_dir && e.redir_type == REDIR5_NONE) {
            if (full_paths) {
                std::error_code ec;
                fs::create_directories(out_path, ec);
                apply_extracted_times_and_attrs(out_path, e, cfg);
                if (!cfg.quiet_names) {
                    out_println(cfg, msgf("action.creating_dir", fspath_to_utf8(out_path), msg("status.ok")));
                }
            }
            continue;
        }

        if (out_path.has_parent_path()) {
            std::error_code ec;
            fs::create_directories(out_path.parent_path(), ec);
        }

        if (fs::exists(out_path)) {
            if (cfg.extract_newer) {
                std::error_code tec;
                auto disk_time = fs::last_write_time(out_path, tec);
                if (!tec && e.mtime_winft != 0) {
                    int64_t sec = 0;
                    uint32_t nsec = 0;
                    win_filetime_to_unix(e.mtime_winft, sec, nsec);
                    auto arch_time = std::chrono::system_clock::from_time_t((std::time_t)sec);
                    auto disk_sys = std::chrono::time_point_cast<std::chrono::seconds>(
                        disk_time - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
                    if (disk_sys >= arch_time) continue;
                }
            }
            if (cfg.overwrite_mode == -1) {
                continue; // -o- skip existing
            }
            if (cfg.overwrite_mode == 0 && !cfg.auto_rename) {
                int ans = 0;
                if (!stdin_is_tty()) ans = -1;
                else {
                    std::string line = prompt_line(msgf("action.overwrite", fspath_to_utf8(out_path)), false);
                    char ch = line.empty() ? 'n' : (char)std::tolower((unsigned char)line[0]);
                    if (ch == 'y') ans = 1;
                    else if (ch == 'a') { cfg.overwrite_mode = 1; ans = 1; }
                    else if (ch == 'q') return RAR_EXIT_USER_BREAK;
                    else ans = -1;
                }
                if (ans < 0) continue;
            }
            if (cfg.auto_rename) {
                // -or auto-rename to filename(1).ext
                fs::path parent = out_path.parent_path();
                std::string stem = fspath_to_utf8(out_path.stem());
                std::string ext = fspath_to_utf8(out_path.extension());
                int idx = 1;
                while (fs::exists(out_path)) {
                    out_path = parent / make_fspath(stem + "(" + std::to_string(idx++) + ")" + ext);
                }
            }
        }

        bool linked = false;
        if (e.redir_type == REDIR5_UNIXSYMLINK || e.redir_type == REDIR5_WINSYMLINK) {
            bool as_dir = e.is_dir;
            linked = create_symlink_utf8(e.redir_target, fspath_to_utf8(out_path), as_dir);
        } else if (e.redir_type == REDIR5_HARDLINK || e.redir_type == REDIR5_FILECOPY) {
            std::string target_rel = e.redir_target;
            fs::path target_rel_path;
            for (const auto& part : make_fspath(target_rel)) {
                std::string ps = fspath_to_utf8(part);
                if (ps == ".." || ps == "." || ps.find(':') != std::string::npos) continue;
                target_rel_path /= part;
            }
            fs::path target_abs = base_out.empty() ? target_rel_path : (base_out / target_rel_path);
            linked = create_hardlink_utf8(fspath_to_utf8(target_abs), fspath_to_utf8(out_path));
        }
        if (!linked) {
            std::ofstream fout(out_path, std::ios::binary | std::ios::trunc);
            if (!fout) {
                err_println(cfg, msgf("err.create_file", fspath_to_utf8(out_path)));
                return RAR_EXIT_CREATE_ERROR;
            }
            if (!out_data.empty()) {
                fout.write(reinterpret_cast<const char*>(out_data.data()), (std::streamsize)out_data.size());
            }
            fout.close();
        }

        apply_extracted_times_and_attrs(out_path, e, cfg);

        if (!cfg.quiet_names) {
            out_println(cfg, msgf("action.extracting", fspath_to_utf8(out_path), msg("status.ok")));
        }
        ++extracted_count;
    }

    if (!is_print) {
        if (extracted_count == 0 && !arch.entries.empty()) {
            out_println(cfg, msg("action.no_files_extract"));
        } else if (!cfg.quiet_done) {
            out_println(cfg, msg("status.all_ok"));
        }
    }
    return RAR_EXIT_SUCCESS;
}

int cmd_add_or_update(const CliConfig& cfg, const std::string& self_exe_path) {
    print_banner(cfg);

    std::string raw_arch_path = cfg.archive_path;
    if (!cfg.ag_format.empty()) {
        raw_arch_path = apply_ag_format(raw_arch_path, cfg.ag_format);
    }
    std::string arch_path = ensure_archive_extension(raw_arch_path, cfg.create_sfx);

    RarArchive arch;
    bool updating_existing = false;
    if (fs::exists(make_fspath(arch_path))) {
        std::string err_msg;
        RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
        if (rc != RAR_EXIT_SUCCESS) {
            err_println(cfg, msgf("err.generic", err_msg));
            return (int)rc;
        }
        if (arch.is_locked) {
            err_println(cfg, msg("err.locked_modify"));
            return RAR_EXIT_LOCKED;
        }
        updating_existing = true;
    }

    if (cfg.create_sfx && arch.sfx_stub.empty()) {
        std::string stub_src = cfg.sfx_stub_name.empty() ? self_exe_path : cfg.sfx_stub_name;
        arch.sfx_stub = RarArchive::create_default_sfx_stub(stub_src);
    }

    if (!cfg.comment_file.empty()) {
        out_println(cfg, msgf("action.reading_comment", cfg.comment_file));
        std::ifstream cf(make_fspath(cfg.comment_file), std::ios::binary);
        if (cf) {
            arch.comment.assign((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
            if (charset_applies(cfg, 'c')) arch.comment = decode_text(arch.comment, cfg.charset);
        }
    }

    if (updating_existing) {
        out_println(cfg, msgf("action.updating", to_native_slashes(arch_path)));
    } else if (cfg.create_sfx) {
        out_println(cfg, msgf("action.creating_sfx", to_native_slashes(arch_path)));
    } else {
        out_println(cfg, msgf("action.creating", to_native_slashes(arch_path)));
    }
    out_println(cfg, "");

    struct CandidateFile {
        fs::path    disk_path;
        std::string internal_name;
        bool        is_dir = false;
        bool        is_link = false;
        uint64_t    redir_type = REDIR5_NONE;
        std::string link_target;
        bool        has_owner = false;
        std::string owner_user;
        std::string owner_group;
        uint32_t    owner_uid = 0;
        uint32_t    owner_gid = 0;
        uint64_t    host_os = 0;
        uint64_t    size = 0;
        uint64_t    mtime_winft = 0;
        uint64_t    ctime_winft = 0;
        uint64_t    atime_winft = 0;
        uint64_t    attrs = 0x20;
    };
    std::vector<CandidateFile> candidates;
    struct InodeKey {
        uint64_t dev = 0;
        uint64_t ino = 0;
        bool operator<(const InodeKey& o) const {
            return dev < o.dev || (dev == o.dev && ino < o.ino);
        }
    };
    std::map<InodeKey, std::string> hardlink_names;
    std::vector<fs::path> paths_to_delete_after;

    // Handle -si[name] (read from stdin)
    if (cfg.read_from_stdin) {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
        std::vector<uint8_t> stdin_buf;
        uint8_t chunk[16384];
        while (size_t n = fread(chunk, 1, sizeof(chunk), stdin)) {
            stdin_buf.insert(stdin_buf.end(), chunk, chunk + n);
        }
        Rar5Compressor comp;
        comp.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
        uint64_t now_ft = current_win_filetime();
        arch.add_entry_from_memory(cfg.stdin_name, stdin_buf.data(), stdin_buf.size(),
                                   false, 0x20, now_ft, now_ft, now_ft,
                                   cfg.arch_opts, comp, false);
        if (!cfg.quiet_names) {
            out_println(cfg, msgf("action.adding", cfg.stdin_name, msg("status.ok")));
        }
    } else {
        // Expand file_args and @listfiles
        std::vector<std::string> raw_inputs = cfg.file_args;
        if (raw_inputs.empty()) raw_inputs.push_back("*");

        std::vector<std::string> expanded_args;
        for (const auto& arg : raw_inputs) {
            if (!arg.empty() && arg[0] == '@' && !fs::exists(make_fspath(arg))) {
                read_list_file(arg.substr(1), expanded_args, charset_applies(cfg, 'l') ? cfg.charset : 0);
            } else {
                expanded_args.push_back(arg);
            }
        }

        auto add_candidate = [&](const fs::path& p, const fs::path& base_arg) {
            std::error_code ec;
            // Avoid adding the archive itself
            if (fs::exists(make_fspath(arch_path), ec) && fs::equivalent(p, make_fspath(arch_path), ec)) {
                return;
            }
            OsFileInfo info;
            uint64_t m_ft = 0, c_ft = 0, a_ft = 0, attrs = 0;
            get_file_times_and_attrs(p, false, m_ft, c_ft, a_ft, attrs, &info);
            bool is_link = cfg.save_symlinks && info.is_symlink;
            bool is_d = !is_link && (info.is_dir || fs::is_directory(p, ec));
            if (is_d && cfg.no_empty_dirs) {
                if (fs::is_empty(p, ec)) return;
            }
            if (cfg.archive_attr_only && !is_d && !is_link && !info.archive_bit) return;
            uint64_t sz = (is_d || is_link) ? 0 : (uint64_t)fs::file_size(p, ec);
            std::string int_name = compute_internal_name(cfg, p, base_arg);
            if (int_name.empty()) return;

            CliConfig filter_cfg = cfg;
            filter_cfg.file_args.clear();
            if (!matches_entry_filters(filter_cfg, int_name, sz, m_ft)) return;

            CandidateFile cf;
            cf.disk_path = p;
            cf.internal_name = int_name;
            cf.is_dir = is_d;
            cf.is_link = is_link;
            cf.host_os = info.host_os;
            cf.size = sz;
            cf.mtime_winft = m_ft;
            cf.ctime_winft = cfg.arch_opts.save_ctime ? c_ft : 0;
            cf.atime_winft = cfg.arch_opts.save_atime ? a_ft : 0;
            cf.attrs = cfg.ignore_attributes ? (is_d ? 0x10 : 0x20) : attrs;
            if (is_link) {
                cf.redir_type = (info.host_os == HOST5_UNIX) ? REDIR5_UNIXSYMLINK : REDIR5_WINSYMLINK;
                cf.link_target = info.link_target;
                cf.size = info.link_target.size();
            } else if (cfg.save_hardlinks && !is_d && info.nlink > 1 && info.inode != 0) {
                InodeKey key{info.dev, info.inode};
                auto found = hardlink_names.find(key);
                if (found != hardlink_names.end()) {
                    cf.is_link = true;
                    cf.redir_type = REDIR5_HARDLINK;
                    cf.link_target = found->second;
                    cf.size = 0;
                } else {
                    hardlink_names.emplace(key, int_name);
                }
            }
            if (cfg.save_owner && info.has_owner) {
                cf.has_owner = true;
                cf.owner_user = info.user;
                cf.owner_group = info.group;
                cf.owner_uid = info.uid;
                cf.owner_gid = info.gid;
            }
            candidates.push_back(cf);
        };

        for (const auto& arg : expanded_args) {
            fs::path p = make_fspath(arg);
            bool has_wild = (arg.find('*') != std::string::npos || arg.find('?') != std::string::npos);

            if (!has_wild && fs::exists(p)) {
                std::error_code sec;
                if (cfg.save_symlinks && fs::is_symlink(p, sec)) {
                    add_candidate(p, p);
                } else if (fs::is_directory(p)) {
                    add_candidate(p, p);
                    if (!cfg.disable_recurse) {
                        std::error_code ec;
                        for (auto it = fs::recursive_directory_iterator(p, ec);
                             it != fs::recursive_directory_iterator(); it.increment(ec)) {
                            add_candidate(it->path(), p);
                        }
                    }
                } else {
                    add_candidate(p, p);
                }
            } else {
                // Wildcard expansion
                fs::path search_dir = p.parent_path();
                if (search_dir.empty()) search_dir = ".";
                std::string mask = fspath_to_utf8(p.filename());
                std::error_code ec;
                if (cfg.recurse || cfg.recurse_wildcard) {
                    for (auto it = fs::recursive_directory_iterator(search_dir, ec);
                         it != fs::recursive_directory_iterator(); it.increment(ec)) {
                        std::string fname = fspath_to_utf8(it->path().filename());
                        if (wildcard_match(mask, fname)) {
                            add_candidate(it->path(), search_dir / "dummy");
                        }
                    }
                } else {
                    for (auto it = fs::directory_iterator(search_dir, ec);
                         it != fs::directory_iterator(); it.increment(ec)) {
                        std::string fname = fspath_to_utf8(it->path().filename());
                        if (wildcard_match(mask, fname)) {
                            add_candidate(it->path(), search_dir / "dummy");
                            if (fs::is_directory(it->path(), ec) && !cfg.disable_recurse) {
                                for (auto rit = fs::recursive_directory_iterator(it->path(), ec);
                                     rit != fs::recursive_directory_iterator(); rit.increment(ec)) {
                                    add_candidate(rit->path(), search_dir / "dummy");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort candidates for solid archives (by extension unless -ds)
    if (cfg.arch_opts.solid && !cfg.disable_sort) {
        std::sort(candidates.begin(), candidates.end(), [](const CandidateFile& a, const CandidateFile& b) {
            if (a.is_dir != b.is_dir) return a.is_dir > b.is_dir;
            auto ext_a = make_fspath(a.internal_name).extension();
            auto ext_b = make_fspath(b.internal_name).extension();
            if (ext_a != ext_b) return ext_a < ext_b;
            return a.internal_name < b.internal_name;
        });
    }

    // Synchronize (-as): remove archive entries not present in candidates
    if (cfg.sync_archive && updating_existing) {
        arch.entries.erase(
            std::remove_if(arch.entries.begin(), arch.entries.end(), [&](const RarFileEntry& e) {
                for (const auto& c : candidates) {
                    if (to_lower_ascii(c.internal_name) == to_lower_ascii(e.name)) return false;
                }
                out_println(cfg, msgf("action.deleting", to_native_slashes(e.name)));
                return true;
            }),
            arch.entries.end());
    }

    struct PendingAdd {
        CandidateFile c;
        int existing_idx = -1;
        std::vector<uint8_t> raw;
        RarEntryExtra extra;
        bool use_extra = false;
        RarArchiveOptions opts;
    };
    std::vector<PendingAdd> pending;
    const bool parallel_ok = cfg.threads > 1 && !cfg.arch_opts.solid && !cfg.version_control;

    Rar5Compressor compressor;
    compressor.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
    bool has_prior_solid_file = false;
    int solid_index = 0;
    std::string prev_solid_ext;
    size_t solid_packed = 0;

    for (const auto& c : candidates) {
        // Check update (u) and freshen (f) semantics
        int existing_idx = -1;
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            if (to_lower_ascii(arch.entries[i].name) == to_lower_ascii(c.internal_name)) {
                existing_idx = (int)i;
                break;
            }
        }

        if (cfg.command == "f" && existing_idx < 0) {
            continue; // Freshen only updates files already in archive
        }
        if ((cfg.command == "u" || cfg.command == "f") && existing_idx >= 0) {
            if (c.mtime_winft <= arch.entries[existing_idx].mtime_winft) {
                continue; // Not newer
            }
        }

        std::vector<uint8_t> raw_data;
        RarEntryExtra extra;
        bool use_extra = false;
        if (c.is_link && c.redir_type == REDIR5_HARDLINK) {
            extra.redir_type = c.redir_type;
            extra.redir_target = c.link_target;
            extra.host_os_set = true;
            extra.host_os = c.host_os ? c.host_os : HOST5_UNIX;
            use_extra = true;
        } else if (c.is_link) {
            raw_data.assign(c.link_target.begin(), c.link_target.end());
            extra.redir_type = c.redir_type;
            extra.redir_target = c.link_target;
            extra.host_os_set = true;
            extra.host_os = c.host_os ? c.host_os : HOST5_UNIX;
            use_extra = true;
        } else if (!c.is_dir) {
            if (!read_file_bytes(fspath_to_utf8(c.disk_path), raw_data, cfg.open_shared)) {
                err_println(cfg, msgf("err.open_file", fspath_to_utf8(c.disk_path)));
                continue;
            }
        }
        if (c.has_owner) {
            extra.has_owner = true;
            extra.owner_user = c.owner_user;
            extra.owner_group = c.owner_group;
            extra.owner_uid = c.owner_uid;
            extra.owner_gid = c.owner_gid;
            extra.host_os_set = true;
            extra.host_os = c.host_os ? c.host_os : extra.host_os;
            use_extra = true;
        } else if (c.host_os != 0) {
            extra.host_os_set = true;
            extra.host_os = c.host_os;
            use_extra = true;
        }
        const RarEntryExtra* extra_ptr = use_extra ? &extra : nullptr;

        // Check if extension is in -ms store list
        RarArchiveOptions entry_opts = cfg.arch_opts;
        if (!c.is_dir && !cfg.store_exts.empty()) {
            std::string ext = to_lower_ascii(fspath_to_utf8(c.disk_path.extension()));
            if (!ext.empty() && ext.front() == '.') ext.erase(ext.begin());
            for (const auto& se : cfg.store_exts) {
                if (ext == se) {
                    entry_opts.method = 0;
                    break;
                }
            }
        }

        bool solid_cont = entry_opts.solid && has_prior_solid_file && !c.is_dir && !c.is_link;
        if (entry_opts.solid && !c.is_dir && !c.is_link) {
            std::string ext = to_lower_ascii(fspath_to_utf8(make_fspath(c.internal_name).extension()));
            if (cfg.solid_by_extension && !prev_solid_ext.empty() && ext != prev_solid_ext) solid_cont = false;
            if (cfg.solid_files > 0 && solid_index > 0 && (solid_index % cfg.solid_files) == 0) solid_cont = false;
            if (cfg.independent_volumes && cfg.arch_opts.volume_size > 0 &&
                solid_packed >= cfg.arch_opts.volume_size) {
                solid_cont = false;
                solid_packed = 0;
            }
            prev_solid_ext = ext;
            ++solid_index;
        }

        if (parallel_ok) {
            PendingAdd item;
            item.c = c;
            item.existing_idx = existing_idx;
            item.raw = std::move(raw_data);
            item.extra = extra;
            item.use_extra = use_extra;
            item.opts = entry_opts;
            pending.push_back(std::move(item));
            continue;
        }

        // Handle -ver[n] file versioning
        if (cfg.version_control && existing_idx >= 0 && !c.is_dir) {
            uint64_t max_ver = 0;
            for (const auto& e : arch.entries) {
                if (to_lower_ascii(e.name) == to_lower_ascii(c.internal_name) && e.has_version) {
                    max_ver = std::max(max_ver, e.version_num);
                }
            }
            arch.entries[existing_idx].has_version = true;
            arch.entries[existing_idx].version_num = max_ver + 1;
            // Temporarily rename old entry so add_entry_from_memory appends new head entry
            std::string orig_name = arch.entries[existing_idx].name;
            arch.entries[existing_idx].name = orig_name + "\x01ver";
            arch.add_entry_from_memory(c.internal_name, raw_data.data(), raw_data.size(),
                                       c.is_dir, c.attrs, c.mtime_winft, c.ctime_winft, c.atime_winft,
                                       entry_opts, compressor,
                                       solid_cont,
                                       extra_ptr);
            arch.entries[existing_idx].name = orig_name;
        } else {
            arch.add_entry_from_memory(c.internal_name, raw_data.data(), raw_data.size(),
                                       c.is_dir, c.attrs, c.mtime_winft, c.ctime_winft, c.atime_winft,
                                       entry_opts, compressor,
                                       solid_cont,
                                       extra_ptr);
        }

        if (!c.is_dir && !c.is_link && entry_opts.method > 0 && entry_opts.solid) {
            has_prior_solid_file = true;
            solid_packed += raw_data.size();
        }
        if (cfg.sleep_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(cfg.sleep_ms));

        if (!cfg.quiet_names) {
            const char* action_key = (existing_idx >= 0) ? "action.updating_file" : "action.adding";
            out_println(cfg, msgf(action_key, to_native_slashes(c.internal_name), msg("status.ok")));
        }

        if (cfg.delete_after) {
            paths_to_delete_after.push_back(c.disk_path);
        }
        if (cfg.clear_archive_attr && !c.is_dir && !c.is_link) {
            clear_archive_attribute(fspath_to_utf8(c.disk_path));
        }
    }

    if (!pending.empty()) {
        const int workers = std::max(1, cfg.threads);
        for (size_t base = 0; base < pending.size();) {
            size_t batch = std::min(static_cast<size_t>(workers), pending.size() - base);
            std::vector<std::future<RarFileEntry>> built;
            built.reserve(batch);
            for (size_t i = 0; i < batch; ++i) {
                PendingAdd* item = &pending[base + i];
                built.push_back(std::async(std::launch::async, [item, &arch]() {
                    Rar5Compressor comp;
                    comp.reset((128ULL * 1024ULL) << item->opts.dict_bits);
                    return arch.build_entry_from_memory(
                        item->c.internal_name, item->raw.data(), item->raw.size(),
                        item->c.is_dir, item->c.attrs, item->c.mtime_winft,
                        item->c.ctime_winft, item->c.atime_winft,
                        item->opts, comp, false, item->use_extra ? &item->extra : nullptr);
                }));
            }
            for (size_t i = 0; i < batch; ++i) {
                arch.commit_entry(built[i].get());
                const CandidateFile& c = pending[base + i].c;
                if (cfg.sleep_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(cfg.sleep_ms));
                if (!cfg.quiet_names) {
                    const char* action_key = (pending[base + i].existing_idx >= 0) ? "action.updating_file" : "action.adding";
                    out_println(cfg, msgf(action_key, to_native_slashes(c.internal_name), msg("status.ok")));
                }
                if (cfg.delete_after) paths_to_delete_after.push_back(c.disk_path);
                if (cfg.clear_archive_attr && !c.is_dir && !c.is_link) {
                    clear_archive_attribute(fspath_to_utf8(c.disk_path));
                }
            }
            base += batch;
        }
    }

    if (cfg.arch_opts.recovery_percent > 0) {
        out_println(cfg, msg("action.adding_rr"));
    }
    if (cfg.arch_opts.lock_archive) {
        out_println(cfg, msg("action.locking"));
    }

    std::vector<std::string> volumes;
    std::string save_err;
    RarExitCode src = store_archive(cfg, arch, arch_path, cfg.arch_opts, &volumes, &save_err);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.save", save_err));
        return (int)src;
    }

    // Set archive timestamp to latest file if -tl
    if (cfg.latest_archive_time && !arch.entries.empty()) {
        uint64_t max_ft = 0;
        for (const auto& e : arch.entries) max_ft = std::max(max_ft, e.mtime_winft);
        if (max_ft > 0) {
            RarFileEntry dummy{};
            dummy.mtime_winft = max_ft;
            for (const auto& vp : volumes) {
                apply_extracted_times_and_attrs(make_fspath(vp), dummy, cfg);
            }
        }
    }

    // Test after archiving if -t
    if (cfg.test_after_archive && !volumes.empty()) {
        CliConfig tcfg = cfg;
        tcfg.command = "t";
        tcfg.archive_path = volumes.front();
        tcfg.file_args.clear();
        tcfg.quiet_copyright = true;
        int trc = cmd_test(tcfg);
        if (trc != RAR_EXIT_SUCCESS) return trc;
    }

    // Delete source files after successful archiving if -df / m / mf
    if (cfg.delete_after) {
        // Delete files first, then directories in reverse depth order
        std::sort(paths_to_delete_after.begin(), paths_to_delete_after.end(),
                  [](const fs::path& a, const fs::path& b) {
                      return a.native().size() > b.native().size();
                  });
        for (const auto& dp : paths_to_delete_after) {
            std::error_code ec;
            if (fs::is_directory(dp, ec) && cfg.move_files_only) continue;
            std::string utf = fspath_to_utf8(dp);
            if (cfg.recycle_after) {
                if (!move_to_trash(utf)) err_println(cfg, msgf("err.trash", utf));
            } else if (cfg.wipe_after) {
                wipe_file(utf);
            } else {
                fs::remove(dp, ec);
            }
        }
    }

    if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
    return RAR_EXIT_SUCCESS;
}

int cmd_delete(const CliConfig& cfg) {
    print_banner(cfg);
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)rc;
    }
    if (arch.is_locked) {
        err_println(cfg, msg("err.locked"));
        return RAR_EXIT_LOCKED;
    }

    out_println(cfg, msgf("action.updating", to_native_slashes(arch_path)));
    out_println(cfg, "");

    size_t orig_count = arch.entries.size();
    std::vector<RarFileEntry> remaining;
    for (const auto& e : arch.entries) {
        if (matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) {
            out_println(cfg, msgf("action.deleting", to_native_slashes(e.name)));
        } else {
            remaining.push_back(e);
        }
    }

    if (remaining.size() == orig_count) {
        out_println(cfg, msg("action.no_files_delete"));
        return RAR_EXIT_NO_FILES;
    }

    if (remaining.empty()) {
        std::error_code ec;
        fs::remove(make_fspath(arch_path), ec);
        out_println(cfg, msgf("action.delete_empty", to_native_slashes(arch_path)));
        if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
        return RAR_EXIT_SUCCESS;
    }

    // If archive was solid, re-compress remaining entries so solid dictionary chain remains valid
    if (arch.is_solid) {
        RarArchive rebuilt = arch;
        rebuilt.entries.clear();
        Rar5Decompressor decomp;
        Rar5Compressor comp;
        comp.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
        bool has_solid = false;
        RarArchiveOptions ropts = cfg.arch_opts;
        ropts.solid = true;
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            const auto& e = arch.entries[i];
            std::vector<uint8_t> raw;
            arch.extract_entry(i, cfg.arch_opts.password, decomp, raw, nullptr);
            if (!matches_entry_filters(cfg, e.name, e.unpacked_size, e.mtime_winft)) {
                rebuilt.add_entry_from_memory(e.name, raw.data(), raw.size(), e.is_dir,
                                              e.attributes, e.mtime_winft, e.ctime_winft, e.atime_winft,
                                              ropts, comp, has_solid && !e.is_dir);
                if (!e.is_dir) has_solid = true;
            }
        }
        arch = std::move(rebuilt);
    } else {
        arch.entries = std::move(remaining);
    }

    RarArchiveOptions sopts = cfg.arch_opts;
    sopts.solid = arch.is_solid;
    sopts.lock_archive = arch.is_locked || cfg.arch_opts.lock_archive;
    RarExitCode src = store_archive(cfg, arch, arch_path, sopts, nullptr, &err_msg);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)src;
    }
    if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
    return RAR_EXIT_SUCCESS;
}

int cmd_rename(const CliConfig& cfg) {
    print_banner(cfg);
    if (cfg.file_args.size() < 2 || (cfg.file_args.size() % 2) != 0) {
        err_println(cfg, msg("err.rn_pairs"));
        return RAR_EXIT_USER_ERROR;
    }
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }
    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)rc;
    }
    if (arch.is_locked) {
        err_println(cfg, msg("err.locked"));
        return RAR_EXIT_LOCKED;
    }

    out_println(cfg, msgf("action.updating", to_native_slashes(arch_path)));
    out_println(cfg, "");

    size_t renamed = 0;
    for (size_t p = 0; p + 1 < cfg.file_args.size(); p += 2) {
        std::string src_pat = normalize_internal_slashes(cfg.file_args[p]);
        std::string dst_pat = normalize_internal_slashes(cfg.file_args[p + 1]);
        for (auto& e : arch.entries) {
            if (wildcard_match(src_pat, e.name)) {
                std::string old_name = e.name;
                std::string new_name = dst_pat;
                if (dst_pat.find('*') != std::string::npos) {
                    // Simple wildcard extension replacement (e.g. *.txt -> *.bak)
                    fs::path ep = make_fspath(old_name);
                    if (dst_pat.substr(0, 2) == "*.") {
                        new_name = normalize_internal_slashes(
                            fspath_to_utf8(ep.parent_path() / ep.stem()) + dst_pat.substr(1));
                    }
                }
                out_println(cfg, msgf("action.renaming", to_native_slashes(old_name), to_native_slashes(new_name)));
                e.name = new_name;
                ++renamed;
            }
        }
    }

    if (renamed == 0) {
        out_println(cfg, msg("action.no_match"));
        return RAR_EXIT_NO_FILES;
    }

    RarArchiveOptions sopts = cfg.arch_opts;
    sopts.solid = arch.is_solid;
    RarExitCode src = store_archive(cfg, arch, arch_path, sopts, nullptr, &err_msg);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)src;
    }
    if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
    return RAR_EXIT_SUCCESS;
}

int cmd_comment_or_modify(const CliConfig& cfg, const std::string& self_exe_path) {
    print_banner(cfg);
    std::string arch_path = ensure_archive_extension(cfg.archive_path, false);
    if (!fs::exists(make_fspath(arch_path)) && fs::exists(make_fspath(cfg.archive_path))) {
        arch_path = cfg.archive_path;
    }

    if (cfg.command == "rv") {
        std::vector<std::string> vols;
        std::string first = locate_first_volume(arch_path);
        bool old_style = false;
        std::string second_old = make_volume_name(first, 2, true);
        std::string second_new = make_volume_name(first, 2, false);
        if (fs::exists(make_fspath(second_old))) old_style = true;
        else if (fs::exists(make_fspath(second_new))) old_style = false;
        else old_style = false;
        for (size_t i = 1; i < 100000; ++i) {
            std::string name = make_volume_name(first, i, old_style);
            if (i == 1 && !fs::exists(make_fspath(name))) name = first;
            if (!fs::exists(make_fspath(name))) break;
            vols.push_back(name);
        }
        if (vols.empty()) vols.push_back(first);
        int parity = cfg.recovery_volumes > 0 ? cfg.recovery_volumes : 1;
        std::vector<std::string> revs;
        std::string rerr;
        if (!write_recovery_volumes(vols, parity, old_style, revs, &rerr)) {
            err_println(cfg, rerr.empty() ? msg("err.rev_write") : rerr);
            return RAR_EXIT_FATAL;
        }
        for (const auto& rv : revs) out_println(cfg, msgf("action.rev_write", rv));
        if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.command == "rc") {
        std::vector<std::string> restored;
        std::string rc_err;
        if (!reconstruct_missing_volumes(arch_path, restored, &rc_err)) {
            err_println(cfg, rc_err.empty() ? msg("err.rev") : rc_err);
            return RAR_EXIT_FATAL;
        }
        for (const auto& name : restored) {
            out_println(cfg, msgf("action.rev_restore", to_native_slashes(name)));
        }
        if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.command == "r" || cfg.command == "rc") {
        // Repair archive
        fs::path ap = make_fspath(arch_path);
        fs::path fixed_path = ap.parent_path() / make_fspath("fixed." + fspath_to_utf8(ap.filename()));
        out_println(cfg, msgf("action.repairing", to_native_slashes(arch_path)));
        out_println(cfg, msgf("action.rebuilding", fspath_to_utf8(fixed_path)));
        std::vector<std::string> found_names;
        bool used_rr = false;
        RarExitCode rrc = RarArchive::repair_archive(arch_path, fspath_to_utf8(fixed_path),
                                                     cfg.arch_opts.password, found_names, used_rr);
        if (used_rr) {
            out_println(cfg, msg("action.found_rr"));
        }
        for (const auto& fn : found_names) {
            out_println(cfg, msgf("action.found", to_native_slashes(fn)));
        }
        if (rrc == RAR_EXIT_SUCCESS) {
            out_println(cfg, msg("action.repair_done"));
        } else {
            err_println(cfg, msg("err.repair"));
        }
        return (int)rrc;
    }

    RarArchive arch;
    std::string err_msg;
    RarExitCode rc = arch.load(arch_path, cfg.arch_opts.password, &err_msg);
    if (rc != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)rc;
    }

    if (cfg.command == "cw") {
        if (cfg.file_args.empty()) {
            err_println(cfg, msg("err.cw_needs_file"));
            return RAR_EXIT_USER_ERROR;
        }
        std::string out_cfile = cfg.file_args[0];
        if (fs::exists(make_fspath(out_cfile)) && cfg.overwrite_mode == -1) {
            return RAR_EXIT_SUCCESS;
        }
        std::ofstream cf(make_fspath(out_cfile), std::ios::binary | std::ios::trunc);
        if (!cf) {
            err_println(cfg, msgf("err.create_comment", out_cfile));
            return RAR_EXIT_CREATE_ERROR;
        }
        cf.write(arch.comment.data(), (std::streamsize)arch.comment.size());
        cf.close();
        out_println(cfg, msgf("action.writing_comment", out_cfile, msg("status.ok")));
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.command == "i") {
        // Search string inside archive files
        Rar5Decompressor decomp;
        bool case_sens = (cfg.find_params.find('c') != std::string::npos);
        std::string needle = case_sens ? cfg.find_str : to_lower_ascii(cfg.find_str);
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            const auto& e = arch.entries[i];
            if (e.is_dir) continue;
            std::vector<uint8_t> data;
            if (arch.extract_entry(i, cfg.arch_opts.password, decomp, data, nullptr) == RAR_EXIT_SUCCESS) {
                std::string haystack(reinterpret_cast<const char*>(data.data()), data.size());
                std::string search_in = case_sens ? haystack : to_lower_ascii(haystack);
                size_t pos = search_in.find(needle);
                if (pos != std::string::npos) {
                    out_println(cfg, "");
                    out_println(cfg, msgf("action.processing", to_native_slashes(arch_path)));
                    out_println(cfg, msgf("action.found_in", to_native_slashes(e.name)));
                    // Print matching line
                    size_t ls = haystack.rfind('\n', pos);
                    ls = (ls == std::string::npos) ? 0 : (ls + 1);
                    size_t le = haystack.find('\n', pos);
                    if (le != std::string::npos && le > ls && haystack[le - 1] == '\r') --le;
                    out_println(cfg, haystack.substr(ls, le - ls));
                }
            }
        }
        return RAR_EXIT_SUCCESS;
    }

    if (arch.is_locked) {
        err_println(cfg, msg("err.locked"));
        return RAR_EXIT_LOCKED;
    }

    RarArchiveOptions sopts = cfg.arch_opts;
    sopts.solid = arch.is_solid;
    sopts.lock_archive = arch.is_locked || cfg.arch_opts.lock_archive || (cfg.command == "k");
    if (arch.has_recovery && sopts.recovery_percent == 0) sopts.recovery_percent = 3;

    if (cfg.command == "c" || !cfg.comment_file.empty()) {
        if (!cfg.comment_file.empty()) {
            out_println(cfg, msgf("action.reading_comment", cfg.comment_file));
            std::ifstream cf(make_fspath(cfg.comment_file), std::ios::binary);
            if (cf) {
                arch.comment.assign((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
                if (charset_applies(cfg, 'c')) arch.comment = decode_text(arch.comment, cfg.charset);
            }
        } else {
            out_println(cfg, msg("action.comment_prompt"));
            std::ostringstream ss;
            ss << std::cin.rdbuf();
            arch.comment = ss.str();
        }
        out_println(cfg, msgf("action.adding_comment", to_native_slashes(arch_path), msg("status.ok")));
    }

    if (cfg.command == "k") {
        out_println(cfg, msgf("action.locking_path", to_native_slashes(arch_path)));
        sopts.lock_archive = true;
    }

    if (cfg.command == "ch" && cfg.case_convert != 0) {
        for (auto& e : arch.entries) {
            e.name = (cfg.case_convert == 1) ? to_lower_ascii(e.name) : to_upper_ascii(e.name);
        }
    }
    if (cfg.command == "ch" && (cfg.method_explicit || cfg.solid_explicit)) {
        out_println(cfg, msg("action.recompress"));
        Rar5Decompressor decomp;
        struct Blob {
            RarFileEntry meta;
            std::vector<uint8_t> data;
        };
        std::vector<Blob> blobs;
        for (size_t i = 0; i < arch.entries.size(); ++i) {
            Blob b;
            b.meta = arch.entries[i];
            if (!b.meta.is_dir && b.meta.redir_type == REDIR5_NONE) {
                arch.extract_entry(i, cfg.arch_opts.password, decomp, b.data, nullptr);
            }
            blobs.push_back(std::move(b));
        }
        arch.entries.clear();
        Rar5Compressor comp;
        comp.reset((128ULL * 1024ULL) << cfg.arch_opts.dict_bits);
        sopts.method = cfg.arch_opts.method;
        sopts.solid = cfg.arch_opts.solid;
        bool prior = false;
        for (auto& b : blobs) {
            RarEntryExtra ex;
            ex.host_os_set = true;
            ex.host_os = b.meta.host_os;
            ex.redir_type = b.meta.redir_type;
            ex.redir_target = b.meta.redir_target;
            ex.has_owner = b.meta.has_owner;
            ex.owner_user = b.meta.owner_user;
            ex.owner_group = b.meta.owner_group;
            ex.owner_uid = b.meta.owner_uid;
            ex.owner_gid = b.meta.owner_gid;
            bool cont = sopts.solid && prior && !b.meta.is_dir && b.meta.redir_type == REDIR5_NONE;
            arch.add_entry_from_memory(b.meta.name, b.data.data(), b.data.size(), b.meta.is_dir,
                                       b.meta.attributes, b.meta.mtime_winft, b.meta.ctime_winft,
                                       b.meta.atime_winft, sopts, comp, cont, &ex);
            if (!b.meta.is_dir && sopts.method > 0 && sopts.solid) prior = true;
        }
    }

    if (cfg.command == "rr" || cfg.command == "rv") {
        out_println(cfg, msgf("action.adding_rr_to", to_native_slashes(arch_path)));
    }

    if (cfg.command == "s") {
        std::string stub_src = cfg.sfx_stub_name.empty() ? self_exe_path : cfg.sfx_stub_name;
        arch.sfx_stub = RarArchive::create_default_sfx_stub(stub_src);
        fs::path ap = make_fspath(arch_path);
#ifdef _WIN32
        ap.replace_extension(".exe");
#else
        ap.replace_extension(".sfx");
#endif
        arch_path = fspath_to_utf8(ap);
        out_println(cfg, msgf("action.creating_sfx", to_native_slashes(arch_path)));
    } else if (cfg.command == "s-") {
        arch.sfx_stub.clear();
        fs::path ap = make_fspath(arch_path);
        ap.replace_extension(".rar");
        arch_path = fspath_to_utf8(ap);
        out_println(cfg, msgf("action.creating", to_native_slashes(arch_path)));
    }

    RarExitCode src = store_archive(cfg, arch, arch_path, sopts, nullptr, &err_msg);
    if (src != RAR_EXIT_SUCCESS) {
        err_println(cfg, msgf("err.generic", err_msg));
        return (int)src;
    }
    if (!cfg.quiet_done) out_println(cfg, msg("status.done"));
    return RAR_EXIT_SUCCESS;
}

// Check if the running executable itself has a RAR 5.0 archive appended (SFX execution mode)
bool is_self_sfx_archive(const std::string& exe_path) {
    if (exe_path.empty()) return false;
    RarArchive test_arch;
    return test_arch.load(exe_path) == RAR_EXIT_SUCCESS && !test_arch.sfx_stub.empty();
}

} // anonymous namespace

int CliRunner::run(int argc, const std::vector<std::string>& args) {
    set_binary_stdio(true, true);
    CliConfig cfg;
    std::vector<std::string> argv(args.begin(), args.end());
    std::string resolved = executable_path();
    if (!resolved.empty()) {
        if (argv.empty()) argv.push_back(resolved);
        else argv[0] = resolved;
    }
    std::string self_exe_path = (!argv.empty()) ? argv[0] : "";
    bool skip_cfg = false;
    bool saw_disk_erase = false;
    for (size_t i = 1; i < argv.size(); ++i) {
        std::string low = to_lower_ascii(argv[i]);
        if (low == "-cfg-") skip_cfg = true;
        if (low == "-vd") saw_disk_erase = true;
    }
    if (!skip_cfg) {
        auto extra = load_config_tokens(self_exe_path);
        argv.insert(argv.begin() + 1, extra.begin(), extra.end());
    }
    argc = (int)argv.size();

    // Check if binary name starts with "unrar" (unrar-free mode defaults)
    std::string exe_name = to_lower_ascii(fspath_to_utf8(make_fspath(self_exe_path).filename()));
    bool is_unrar_persona = (exe_name.find("unrar") != std::string::npos);

    bool stop_switches = false;
    std::vector<std::string> positional;

    for (size_t i = 1; i < (size_t)argc && i < argv.size(); ++i) {
        const std::string& tok = argv[i];
        if (!stop_switches && !tok.empty() && tok[0] == '-') {
            if (!parse_switch(tok, cfg, argv, i)) {
                stop_switches = true;
            }
            continue;
        }
        if (cfg.command.empty() && positional.empty() && is_known_command(tok, cfg)) {
            continue;
        }
        positional.push_back(tok);
    }

    if (cfg.show_version) {
        out_println(cfg, "7.01");
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.show_help) {
        print_help(cfg);
        return RAR_EXIT_SUCCESS;
    }

    // If invoked without command on an SFX executable, automatically extract self!
    if (cfg.command.empty() && is_self_sfx_archive(self_exe_path)) {
        cfg.command = "x";
        if (!positional.empty()) {
            cfg.dest_dir = positional[0];
        }
        return cmd_extract_or_print(cfg, self_exe_path);
    }

    // In unrar-free persona, if no command was specified but an archive was given, default to "x"
    if (cfg.command.empty() && is_unrar_persona && !positional.empty()) {
        cfg.command = "x";
    }

    if (cfg.command.empty()) {
        print_help(cfg);
        return RAR_EXIT_SUCCESS;
    }

    if (cfg.format_version < 5) {
        err_println(cfg, msg("err.ma4"));
        return RAR_EXIT_USER_ERROR;
    }
    if (saw_disk_erase) err_println(cfg, msg("warn.vd"));
#ifndef _WIN32
    if (cfg.archive_attr_only) err_println(cfg, msg("warn.ao"));
#endif
    if ((cfg.command == "a" || cfg.command == "m" || cfg.command == "mf") && cfg.update_switch) cfg.command = "u";
    else if ((cfg.command == "a" || cfg.command == "m" || cfg.command == "mf") && cfg.freshen_switch) cfg.command = "f";
    if (cfg.priority >= 0) set_process_priority(cfg.priority);
    if (cfg.threads <= 0) {
        unsigned hc = std::thread::hardware_concurrency();
        cfg.threads = (int)std::min<unsigned>(hc == 0 ? 1 : hc, 32);
    }
    maybe_prompt_password(cfg);
    auto finish = [&](int code) {
        if (code == RAR_EXIT_SUCCESS) {
            if (cfg.beep_when_done) beep();
            if (cfg.power_off > 0) request_power_action(cfg.power_off);
        }
        return code;
    };

    // Handle special `rar i[par]=<str> <archive>` case where archive is first positional
    if (positional.empty()) {
        err_println(cfg, msg("err.no_archive"));
        return RAR_EXIT_USER_ERROR;
    }

    cfg.archive_path = positional[0];
    for (size_t i = 1; i < positional.size(); ++i) {
        cfg.file_args.push_back(positional[i]);
    }

    // For extraction commands (x, e), check if the last positional argument is a destination directory
    if ((cfg.command == "x" || cfg.command == "e") && !cfg.file_args.empty()) {
        const std::string& last_arg = cfg.file_args.back();
        bool ends_with_slash = (!last_arg.empty() && (last_arg.back() == '\\' || last_arg.back() == '/'));
        std::error_code ec;
        bool exists_as_dir = fs::is_directory(make_fspath(last_arg), ec);
        if (ends_with_slash || exists_as_dir) {
            cfg.dest_dir = last_arg;
            cfg.file_args.pop_back();
        }
    }

    if (cfg.command == "l" || cfg.command == "lt" || cfg.command == "lta" || cfg.command == "lb" ||
        cfg.command == "v" || cfg.command == "vt" || cfg.command == "vta" || cfg.command == "vb") {
        return finish(cmd_list(cfg));
    }
    if (cfg.command == "t") {
        return finish(cmd_test(cfg));
    }
    if (cfg.command == "x" || cfg.command == "e" || cfg.command == "p") {
        return finish(cmd_extract_or_print(cfg));
    }
    if (cfg.command == "a" || cfg.command == "u" || cfg.command == "f" ||
        cfg.command == "m" || cfg.command == "mf") {
        return finish(cmd_add_or_update(cfg, self_exe_path));
    }
    if (cfg.command == "d") {
        return finish(cmd_delete(cfg));
    }
    if (cfg.command == "rn") {
        return finish(cmd_rename(cfg));
    }
    if (cfg.command == "c" || cfg.command == "cw" || cfg.command == "k" ||
        cfg.command == "rr" || cfg.command == "rv" || cfg.command == "s" ||
        cfg.command == "s-" || cfg.command == "r" || cfg.command == "rc" ||
        cfg.command == "ch" || cfg.command == "i") {
        return finish(cmd_comment_or_modify(cfg, self_exe_path));
    }

    err_println(cfg, msgf("err.unknown_cmd", cfg.command));
    return RAR_EXIT_USER_ERROR;
}

} // namespace openrar
