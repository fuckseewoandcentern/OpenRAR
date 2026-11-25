/*
 * OpenRAR - Compile-time user interface strings.
 * The active language is chosen with -DOPENRAR_LANG=<code> and embedded
 * from lang/<code>.txt. Source code refers to messages by English keys.
 *
 * Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).
 */

#ifndef OPENRAR_I18N_H
#define OPENRAR_I18N_H

#include <string>

namespace openrar {

// Look up a message baked in at compile time. Unknown keys return the key.
const char* msg(const char* key);

// Replace {0} and {1} in the message.
std::string msgf(const char* key, const std::string& a0, const std::string& a1 = std::string());

} // namespace openrar

#endif
