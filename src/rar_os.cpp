/*
 * OpenRAR - Host helpers for Windows, Linux, macOS and the BSDs.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_os.h"
#include "rar_archive.h"
#include "rar_defs.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <random>
#include <filesystem>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <io.h>
#include <fcntl.h>
#include <winioctl.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <spawn.h>
extern char** environ;
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/syslimits.h>
#elif defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/sysctl.h>
#endif
#if defined(__has_include)
#  if __has_include(<iconv.h>)
#    include <iconv.h>
#    define OPENRAR_HAS_ICONV 1
#  endif
#endif
#endif

namespace fs = std::filesystem;

namespace openrar {

namespace {

fs::path to_path(const std::string& utf8) {
#if defined(_WIN32)
    if (utf8.empty()) return fs::path();
    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), nullptr, 0);
    if (len <= 0) return fs::path();
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), (int)utf8.size(), &ws[0], len);
    return fs::path(ws);
#else
    return fs::path(utf8);
#endif
}

std::string from_path(const fs::path& p) {
#if defined(_WIN32)
    std::wstring ws = p.wstring();
    if (ws.empty()) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
#else
    return p.string();
#endif
}

uint64_t unix_to_winft(int64_t sec, uint32_t nsec) {
    return unix_to_win_filetime(sec, nsec);
}

} // namespace

std::string executable_path() {
#if defined(_WIN32)
    wchar_t buf[32768];
    DWORD n = GetModuleFileNameW(nullptr, buf, 32768);
    if (n == 0 || n >= 32768) return std::string();
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, &s[0], len, nullptr, nullptr);
    return s;
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) != 0) return std::string();
    char resolved[PATH_MAX];
    if (!realpath(buf, resolved)) return std::string(buf);
    return std::string(resolved);
#elif defined(__linux__)
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    buf[n] = '\0';
    return std::string(buf);
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1};
    char buf[4096];
    size_t cb = sizeof(buf);
    if (sysctl(mib, 4, buf, &cb, nullptr, 0) != 0 || cb == 0) return std::string();
    if (cb > 0 && buf[cb - 1] == '\0') cb--;
    return std::string(buf, cb);
#elif defined(__NetBSD__)
    int mib[4] = {CTL_KERN, KERN_PROC_ARGS, -1, KERN_PROC_PATHNAME};
    char buf[4096];
    size_t cb = sizeof(buf);
    if (sysctl(mib, 4, buf, &cb, nullptr, 0) != 0 || cb == 0) return std::string();
    if (cb > 0 && buf[cb - 1] == '\0') cb--;
    return std::string(buf, cb);
#else
    // OpenBSD and other Unix systems: /proc may be absent. Callers fall back to argv[0].
    char buf[4096];
    ssize_t n = ::readlink("/proc/curproc/file", buf, sizeof(buf) - 1);
    if (n <= 0) n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return std::string();
    buf[n] = '\0';
    return std::string(buf);
#endif
}

std::string path_dirname(const std::string& path) {
    fs::path p = to_path(path);
    fs::path parent = p.parent_path();
    if (parent.empty()) return std::string();
    return from_path(parent);
}

std::string path_join(const std::string& dir, const std::string& name) {
    if (dir.empty()) return name;
    return from_path(to_path(dir) / to_path(name));
}

std::string getenv_utf8(const char* name) {
    if (!name) return std::string();
#if defined(_WIN32)
    wchar_t wname[256];
    int wn = MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 256);
    if (wn <= 0) return std::string();
    DWORD need = GetEnvironmentVariableW(wname, nullptr, 0);
    if (need == 0) return std::string();
    std::wstring ws(need, L'\0');
    DWORD got = GetEnvironmentVariableW(wname, &ws[0], need);
    if (got == 0) return std::string();
    ws.resize(got);
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return std::string();
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
#else
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
#endif
}

std::vector<std::string> config_file_candidates(const std::string& exe_path) {
    std::vector<std::string> out;
    std::string dir = path_dirname(exe_path);
#if defined(_WIN32)
    if (!dir.empty()) {
        out.push_back(path_join(dir, "rar.ini"));
        out.push_back(path_join(dir, "rarrc"));
    }
    std::string app = getenv_utf8("APPDATA");
    if (!app.empty()) {
        out.push_back(path_join(path_join(app, "OpenRAR"), "rar.ini"));
    }
#else
    out.push_back("/etc/rarrc");
    std::string home = getenv_utf8("HOME");
    if (!home.empty()) out.push_back(path_join(home, ".rarrc"));
    if (!dir.empty()) out.push_back(path_join(dir, "rarrc"));
#endif
    return out;
}

bool read_file_bytes(const std::string& utf8_path, std::vector<uint8_t>& out, bool shared) {
#if defined(_WIN32)
    fs::path p = to_path(utf8_path);
    DWORD share = shared ? (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) : FILE_SHARE_READ;
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, share, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 0) {
        CloseHandle(h);
        return false;
    }
    out.resize(static_cast<size_t>(sz.QuadPart));
    size_t off = 0;
    while (off < out.size()) {
        DWORD chunk = 0;
        DWORD want = (DWORD)std::min<size_t>(1 << 20, out.size() - off);
        if (!ReadFile(h, out.data() + off, want, &chunk, nullptr)) {
            CloseHandle(h);
            return false;
        }
        if (chunk == 0) break;
        off += chunk;
    }
    CloseHandle(h);
    out.resize(off);
    return true;
#else
    (void)shared;
    std::ifstream ifs(to_path(utf8_path), std::ios::binary | std::ios::ate);
    if (!ifs) return false;
    std::streamsize sz = ifs.tellg();
    if (sz < 0) return false;
    out.resize(static_cast<size_t>(sz));
    ifs.seekg(0, std::ios::beg);
    if (sz > 0 && !ifs.read(reinterpret_cast<char*>(out.data()), sz)) return false;
    return true;
#endif
}

bool get_file_info(const std::string& utf8_path, OsFileInfo& info) {
    info = OsFileInfo{};
    fs::path p = to_path(utf8_path);
    std::error_code ec;
    auto lst = fs::symlink_status(p, ec);
    if (ec) return false;
    info.is_symlink = fs::is_symlink(lst);
    info.is_dir = info.is_symlink ? false : fs::is_directory(lst);
#if defined(_WIN32)
    info.host_os = HOST5_WINDOWS;
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad)) {
        info.attributes = fad.dwFileAttributes;
        info.archive_bit = (fad.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) != 0;
        info.is_dir = (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && !info.is_symlink;
        info.mtime_winft = (uint64_t(fad.ftLastWriteTime.dwHighDateTime) << 32) | fad.ftLastWriteTime.dwLowDateTime;
        info.ctime_winft = (uint64_t(fad.ftCreationTime.dwHighDateTime) << 32) | fad.ftCreationTime.dwLowDateTime;
        info.atime_winft = (uint64_t(fad.ftLastAccessTime.dwHighDateTime) << 32) | fad.ftLastAccessTime.dwLowDateTime;
    } else {
        info.attributes = info.is_dir ? 0x10 : 0x20;
        info.archive_bit = true;
        info.mtime_winft = current_win_filetime();
        info.ctime_winft = info.mtime_winft;
        info.atime_winft = info.mtime_winft;
    }
    if (info.is_symlink) {
        std::error_code lec;
        info.link_target = from_path(fs::read_symlink(p, lec));
        info.is_dir = false;
    }
    HANDLE h = CreateFileW(p.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        BY_HANDLE_FILE_INFORMATION fi{};
        if (GetFileInformationByHandle(h, &fi)) {
            info.nlink = fi.nNumberOfLinks ? fi.nNumberOfLinks : 1;
            info.inode = (uint64_t(fi.nFileIndexHigh) << 32) | fi.nFileIndexLow;
            info.dev = fi.dwVolumeSerialNumber;
        }
        CloseHandle(h);
    }
#else
    info.host_os = HOST5_UNIX;
    struct stat st{};
    if (::lstat(utf8_path.c_str(), &st) != 0) return false;
    info.attributes = (uint64_t)st.st_mode;
    info.is_dir = S_ISDIR(st.st_mode);
    info.is_symlink = S_ISLNK(st.st_mode);
    info.nlink = (uint64_t)st.st_nlink;
    info.inode = (uint64_t)st.st_ino;
    info.dev = (uint64_t)st.st_dev;
    info.uid = (uint32_t)st.st_uid;
    info.gid = (uint32_t)st.st_gid;
    info.has_owner = true;
    info.archive_bit = true;
    info.mtime_winft = unix_to_winft((int64_t)st.st_mtime, 0);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    info.mtime_winft = unix_to_winft((int64_t)st.st_mtimespec.tv_sec, (uint32_t)st.st_mtimespec.tv_nsec);
    info.atime_winft = unix_to_winft((int64_t)st.st_atimespec.tv_sec, (uint32_t)st.st_atimespec.tv_nsec);
    info.ctime_winft = unix_to_winft((int64_t)st.st_ctimespec.tv_sec, (uint32_t)st.st_ctimespec.tv_nsec);
#else
    info.mtime_winft = unix_to_winft((int64_t)st.st_mtim.tv_sec, (uint32_t)st.st_mtim.tv_nsec);
    info.atime_winft = unix_to_winft((int64_t)st.st_atim.tv_sec, (uint32_t)st.st_atim.tv_nsec);
    info.ctime_winft = unix_to_winft((int64_t)st.st_ctim.tv_sec, (uint32_t)st.st_ctim.tv_nsec);
#endif
    if (info.is_symlink) {
        std::error_code lec;
        info.link_target = from_path(fs::read_symlink(p, lec));
        info.is_dir = false;
    }
    if (const passwd* pw = getpwuid(st.st_uid)) info.user = pw->pw_name;
    if (const group* gr = getgrgid(st.st_gid)) info.group = gr->gr_name;
#endif
    return true;
}

bool apply_file_info(const std::string& utf8_path, const OsFileInfo& info,
                     bool restore_attr, bool restore_owner, bool clear_archive_bit,
                     bool ntfs_compress) {
    fs::path p = to_path(utf8_path);
    std::error_code ec;
#if defined(_WIN32)
    HANDLE h = CreateFileW(p.c_str(), FILE_WRITE_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING,
                           info.is_dir ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        FILETIME ft_m{}, ft_c{}, ft_a{};
        const FILETIME* pm = nullptr;
        const FILETIME* pc = nullptr;
        const FILETIME* pa = nullptr;
        auto fill = [](FILETIME& ft, uint64_t v) {
            ft.dwLowDateTime = (DWORD)(v & 0xFFFFFFFFULL);
            ft.dwHighDateTime = (DWORD)(v >> 32);
        };
        if (info.mtime_winft) { fill(ft_m, info.mtime_winft); pm = &ft_m; }
        if (info.ctime_winft) { fill(ft_c, info.ctime_winft); pc = &ft_c; }
        if (info.atime_winft) { fill(ft_a, info.atime_winft); pa = &ft_a; }
        SetFileTime(h, pc, pa, pm);
        if (ntfs_compress && !info.is_dir) {
            USHORT fmt = COMPRESSION_FORMAT_DEFAULT;
            DWORD got = 0;
            DeviceIoControl(h, FSCTL_SET_COMPRESSION, &fmt, sizeof(fmt), nullptr, 0, &got, nullptr);
        }
        CloseHandle(h);
    }
    if (restore_attr && info.host_os == HOST5_WINDOWS && info.attributes != 0 && !info.is_dir) {
        DWORD attr = (DWORD)(info.attributes & 0x27);
        if (clear_archive_bit) attr &= ~FILE_ATTRIBUTE_ARCHIVE;
        if (attr == 0) attr = FILE_ATTRIBUTE_NORMAL;
        SetFileAttributesW(p.c_str(), attr);
    } else if (clear_archive_bit && !info.is_dir) {
        clear_archive_attribute(utf8_path);
    }
    (void)restore_owner;
    (void)ec;
#else
    (void)ntfs_compress;
    if (!info.is_symlink) {
        int64_t sec = 0;
        uint32_t nsec = 0;
        if (info.mtime_winft) {
            win_filetime_to_unix(info.mtime_winft, sec, nsec);
            struct timespec ts[2];
            int64_t asec = sec;
            uint32_t ansec = nsec;
            if (info.atime_winft) win_filetime_to_unix(info.atime_winft, asec, ansec);
            ts[0].tv_sec = (time_t)asec;
            ts[0].tv_nsec = (long)ansec;
            ts[1].tv_sec = (time_t)sec;
            ts[1].tv_nsec = (long)nsec;
            ::utimensat(AT_FDCWD, utf8_path.c_str(), ts, 0);
        }
        if (restore_attr && info.host_os == HOST5_UNIX && info.attributes != 0) {
            ::chmod(utf8_path.c_str(), (mode_t)(info.attributes & 07777));
        }
        if (restore_owner && info.has_owner) {
            uid_t uid = (uid_t)info.uid;
            gid_t gid = (gid_t)info.gid;
            if (!info.user.empty()) {
                if (const passwd* pw = getpwnam(info.user.c_str())) uid = pw->pw_uid;
            }
            if (!info.group.empty()) {
                if (const group* gr = getgrnam(info.group.c_str())) gid = gr->gr_gid;
            }
            if (::chown(utf8_path.c_str(), uid, gid) != 0) {
                // Ownership restore is best-effort; a non-root process may not be allowed.
            }
        }
    } else if (info.mtime_winft) {
        int64_t sec = 0;
        uint32_t nsec = 0;
        win_filetime_to_unix(info.mtime_winft, sec, nsec);
        struct timespec ts[2];
        ts[0].tv_sec = (time_t)sec;
        ts[0].tv_nsec = (long)nsec;
        ts[1] = ts[0];
#if defined(AT_SYMLINK_NOFOLLOW)
        ::utimensat(AT_FDCWD, utf8_path.c_str(), ts, AT_SYMLINK_NOFOLLOW);
#endif
    }
    (void)clear_archive_bit;
#endif
    return true;
}

bool create_symlink_utf8(const std::string& target, const std::string& link_path, bool directory) {
    std::error_code ec;
    fs::path link = to_path(link_path);
    fs::path tgt = to_path(target);
    if (fs::exists(link, ec)) fs::remove(link, ec);
    if (directory) fs::create_directory_symlink(tgt, link, ec);
    else fs::create_symlink(tgt, link, ec);
    return !ec;
}

bool create_hardlink_utf8(const std::string& existing, const std::string& link_path) {
    std::error_code ec;
    fs::path link = to_path(link_path);
    if (fs::exists(link, ec)) return false;
    fs::create_hard_link(to_path(existing), link, ec);
    return !ec;
}

bool move_to_trash(const std::string& utf8_path) {
#if defined(_WIN32)
    fs::path p = to_path(utf8_path);
    std::wstring ws = p.wstring();
    ws.push_back(L'\0');
    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = ws.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI;
    return SHFileOperationW(&op) == 0;
#else
    std::error_code ec;
    if (!fs::exists(to_path(utf8_path), ec)) return false;
    std::string home = getenv_utf8("HOME");
    if (home.empty()) return false;
#if defined(__APPLE__)
    std::string trash_files = path_join(home, ".Trash");
    std::error_code dec;
    fs::create_directories(to_path(trash_files), dec);
#else
    std::string data = getenv_utf8("XDG_DATA_HOME");
    if (data.empty()) data = path_join(home, ".local/share");
    std::string trash_root = path_join(data, "Trash");
    std::string trash_files = path_join(trash_root, "files");
    std::string trash_info = path_join(trash_root, "info");
    fs::create_directories(to_path(trash_files), ec);
    fs::create_directories(to_path(trash_info), ec);
#endif
    fs::path src = to_path(utf8_path);
    std::string base = from_path(src.filename());
    if (base.empty()) base = "file";
    std::string dest_name = base;
    for (int i = 1; fs::exists(to_path(path_join(trash_files, dest_name))); ++i) {
        dest_name = base + "." + std::to_string(i);
    }
    std::string dest = path_join(trash_files, dest_name);
    fs::rename(src, to_path(dest), ec);
    if (ec) {
        ec.clear();
        fs::copy(src, to_path(dest), fs::copy_options::recursive | fs::copy_options::copy_symlinks, ec);
        if (ec) return false;
        fs::remove_all(src, ec);
    }
#if !defined(__APPLE__)
    std::ofstream info(to_path(path_join(trash_info, dest_name + ".trashinfo")));
    if (info) {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char stamp[64];
        std::snprintf(stamp, sizeof(stamp), "%04d-%02d-%02dT%02d:%02d:%02d",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec);
        info << "[Trash Info]\nPath=" << utf8_path << "\nDeletionDate=" << stamp << "\n";
    }
#endif
    return true;
#endif
}

bool wipe_file(const std::string& utf8_path) {
    std::error_code ec;
    if (fs::is_directory(to_path(utf8_path), ec)) {
        fs::remove_all(to_path(utf8_path), ec);
        return !ec;
    }
    std::fstream f(to_path(utf8_path), std::ios::binary | std::ios::in | std::ios::out);
    if (!f) {
        fs::remove(to_path(utf8_path), ec);
        return !ec;
    }
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    if (sz < 0) sz = 0;
    std::vector<uint8_t> buf(1 << 20);
    std::mt19937 rng{std::random_device{}()};
    for (int pass = 0; pass < 3; ++pass) {
        f.seekp(0, std::ios::beg);
        std::streamoff left = sz;
        while (left > 0) {
            size_t n = (size_t)std::min<std::streamoff>(left, (std::streamoff)buf.size());
            if (pass == 0) std::memset(buf.data(), 0x00, n);
            else if (pass == 1) std::memset(buf.data(), 0xFF, n);
            else {
                for (size_t i = 0; i < n; ++i) buf[i] = (uint8_t)rng();
            }
            f.write(reinterpret_cast<char*>(buf.data()), (std::streamsize)n);
            if (!f) break;
            left -= (std::streamoff)n;
        }
        f.flush();
    }
    f.close();
    fs::remove(to_path(utf8_path), ec);
    return !ec;
}

bool make_executable(const std::string& utf8_path) {
#if defined(_WIN32)
    (void)utf8_path;
    return true;
#else
    struct stat st{};
    if (::stat(utf8_path.c_str(), &st) != 0) return false;
    mode_t mode = st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH;
    return ::chmod(utf8_path.c_str(), mode) == 0;
#endif
}

void clear_archive_attribute(const std::string& utf8_path) {
#if defined(_WIN32)
    fs::path p = to_path(utf8_path);
    DWORD a = GetFileAttributesW(p.c_str());
    if (a != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(p.c_str(), a & ~FILE_ATTRIBUTE_ARCHIVE);
    }
#else
    (void)utf8_path;
#endif
}

void set_binary_stdio(bool stdin_bin, bool stdout_bin) {
#if defined(_WIN32)
    if (stdin_bin) _setmode(_fileno(stdin), _O_BINARY);
    if (stdout_bin) _setmode(_fileno(stdout), _O_BINARY);
#else
    (void)stdin_bin;
    (void)stdout_bin;
#endif
}

bool stdin_is_tty() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return ::isatty(STDIN_FILENO) != 0;
#endif
}

std::string prompt_line(const std::string& prompt, bool hidden) {
    std::fputs(prompt.c_str(), stderr);
    std::fflush(stderr);
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    bool changed = false;
    if (hidden && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode)) {
        SetConsoleMode(h, mode & ~ENABLE_ECHO_INPUT);
        changed = true;
    }
    std::string line;
    std::getline(std::cin, line);
    if (changed) {
        SetConsoleMode(h, mode);
        std::fputc('\n', stderr);
    }
    return line;
#else
    termios oldt{};
    bool changed = false;
    if (hidden && ::isatty(STDIN_FILENO)) {
        if (tcgetattr(STDIN_FILENO, &oldt) == 0) {
            termios newt = oldt;
            newt.c_lflag &= ~(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            changed = true;
        }
    }
    std::string line;
    std::getline(std::cin, line);
    if (changed) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::fputc('\n', stderr);
    }
    return line;
#endif
}

void set_process_priority(int level_0_to_15) {
    if (level_0_to_15 < 0) level_0_to_15 = 0;
    if (level_0_to_15 > 15) level_0_to_15 = 15;
#if defined(_WIN32)
    DWORD cls = NORMAL_PRIORITY_CLASS;
    if (level_0_to_15 <= 2) cls = IDLE_PRIORITY_CLASS;
    else if (level_0_to_15 <= 5) cls = BELOW_NORMAL_PRIORITY_CLASS;
    else if (level_0_to_15 <= 10) cls = NORMAL_PRIORITY_CLASS;
    else if (level_0_to_15 <= 13) cls = ABOVE_NORMAL_PRIORITY_CLASS;
    else cls = HIGH_PRIORITY_CLASS;
    SetPriorityClass(GetCurrentProcess(), cls);
#else
    int nice = 10 - level_0_to_15;
    if (nice > 19) nice = 19;
    if (nice < -20) nice = -20;
    ::setpriority(PRIO_PROCESS, 0, nice);
#endif
}

void beep() {
#if defined(_WIN32)
    MessageBeep(MB_OK);
#else
    if (::isatty(STDERR_FILENO)) {
        const char bell = '\a';
        ssize_t unused = ::write(STDERR_FILENO, &bell, 1);
        (void)unused;
    }
#endif
}

bool request_power_action(int kind) {
#if defined(_WIN32)
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES tp{};
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
        CloseHandle(token);
    }
    if (kind == 2) return SetSystemPowerState(TRUE, TRUE) != 0;
    if (kind == 3) return SetSystemPowerState(FALSE, TRUE) != 0;
    UINT flags = EWX_SHUTDOWN | EWX_POWEROFF | EWX_FORCEIFHUNG;
    if (kind == 4) flags = EWX_REBOOT | EWX_FORCEIFHUNG;
    return ExitWindowsEx(flags, SHTDN_REASON_FLAG_PLANNED) != 0;
#else
    const char* cmd = "/sbin/shutdown";
    const char* arg = (kind == 4) ? "-r" : "-h";
    if (kind == 2 || kind == 3) return false;
    if (::access(cmd, X_OK) != 0) cmd = "/usr/sbin/shutdown";
    if (::access(cmd, X_OK) != 0) return false;
    pid_t pid = 0;
    char* argv[] = {const_cast<char*>(cmd), const_cast<char*>(arg), const_cast<char*>("now"), nullptr};
    if (posix_spawn(&pid, cmd, nullptr, nullptr, argv, environ) != 0) return false;
    return true;
#endif
}

bool open_mail_composer(const std::string& address, const std::string& attachment) {
    if (address.empty()) return false;
#if defined(_WIN32)
    std::string url = "mailto:" + address + "?subject=Archive&body=" + attachment;
    fs::path p = to_path(url);
    HINSTANCE h = ShellExecuteW(nullptr, L"open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return (intptr_t)h > 32;
#else
    const char* bin = nullptr;
    if (::access("/usr/bin/xdg-email", X_OK) == 0) bin = "/usr/bin/xdg-email";
    else if (::access("/usr/local/bin/xdg-email", X_OK) == 0) bin = "/usr/local/bin/xdg-email";
    if (!bin) return false;
    pid_t pid = 0;
    char* argv[] = {
        const_cast<char*>(bin),
        const_cast<char*>("--attach"),
        const_cast<char*>(attachment.c_str()),
        const_cast<char*>(address.c_str()),
        nullptr
    };
    if (posix_spawn(&pid, bin, nullptr, nullptr, argv, environ) != 0) return false;
    return true;
#endif
}

std::string decode_text(const std::string& bytes, char charset) {
    if (charset == 0 || charset == 'u' || charset == 'U') return bytes;
#if defined(_WIN32)
    UINT cp = (charset == 'o' || charset == 'O') ? CP_OEMCP : CP_ACP;
    int wlen = MultiByteToWideChar(cp, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
    if (wlen <= 0) return bytes;
    std::wstring ws(wlen, L'\0');
    MultiByteToWideChar(cp, 0, bytes.data(), (int)bytes.size(), &ws[0], wlen);
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.data(), wlen, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return bytes;
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.data(), wlen, &s[0], len, nullptr, nullptr);
    return s;
#elif defined(OPENRAR_HAS_ICONV)
    const char* from = "ISO-8859-1";
    iconv_t cd = iconv_open("UTF-8", from);
    if (cd == (iconv_t)-1) return bytes;
    std::string out(bytes.size() * 4 + 8, '\0');
    char* inbuf = const_cast<char*>(bytes.data());
    size_t inleft = bytes.size();
    char* outbuf = &out[0];
    size_t outleft = out.size();
    size_t rc = iconv(cd, &inbuf, &inleft, &outbuf, &outleft);
    iconv_close(cd);
    if (rc == (size_t)-1) return bytes;
    out.resize(out.size() - outleft);
    return out;
#else
    std::string out;
    out.reserve(bytes.size() * 2);
    for (unsigned char c : bytes) {
        if (c < 0x80) out.push_back((char)c);
        else {
            out.push_back((char)(0xC0 | (c >> 6)));
            out.push_back((char)(0x80 | (c & 0x3F)));
        }
    }
    return out;
#endif
}

} // namespace openrar
