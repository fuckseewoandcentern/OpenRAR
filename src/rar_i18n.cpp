/*
 * OpenRAR - Compile-time message table.
 * rar_lang_table.inc is generated from lang/en.txt overlaid with the
 * language selected by -DOPENRAR_LANG.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#include "rar_i18n.h"
#include <cstring>

namespace openrar {

struct MsgEntry {
    const char* key;
    const char* value;
};

static const MsgEntry kMsgs[] = {
#include "rar_lang_table.inc"
};

const char* msg(const char* key) {
    if (!key) return "";
    for (const auto& e : kMsgs) {
        if (std::strcmp(e.key, key) == 0) return e.value;
    }
    return key;
}

std::string msgf(const char* key, const std::string& a0, const std::string& a1) {
    std::string s = msg(key);
    auto repl = [&](const char* tok, const std::string& v) {
        const size_t n = std::strlen(tok);
        size_t p = 0;
        while ((p = s.find(tok, p)) != std::string::npos) {
            s.replace(p, n, v);
            p += v.size();
        }
    };
    repl("{0}", a0);
    repl("{1}", a1);
    return s;
}

} // namespace openrar
