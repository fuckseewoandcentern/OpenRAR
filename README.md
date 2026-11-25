# OpenRAR — clean-room RAR 5.0 archiver

OpenRAR is a clean-room RAR 5.0 compressor and extractor licensed under the GNU General Public License v3.0 or later. The program text is English. Other languages are compiled in from `lang/`.

The previous Chinese README, including its disclaimer, is kept unchanged as [readme_CN.md](readme_CN.md).

## Disclaimer

This project was written independently as a study of published archive formats. It is not finished work and it may contain design defects. The authors are not liable for loss caused by using it, including archives that do not round-trip or a machine that fails while the program is running.

Everything in this directory is for learning and research. It is not offered for commercial use or for any unlawful use. If you use it anyway, you carry the legal consequences yourself.

The format notes come from public specifications and from open-source community references. Copyright questions belong with the original authors. The person who wrote this notice does not take on that dispute.

If a download of this tree is only a temporary copy for study, delete it from your computer within 24 hours.

If RAR is useful to you, buy WinRAR or the RAR command-line tools from RARLAB. A real license is what gets you their support and updates.

Article 17 of the Regulations on Computers Software Protection of the People’s Republic of China (in force 1 January 2002) allows installing, displaying, transmitting, or storing software without the copyright holder’s permission and without payment when the purpose is to study the ideas and principles inside the software. Use of this tree should stay inside that kind of study.

The author of the disclaimer is the person who explains it if a sentence in it is unclear. That is a request for a clear reading, not a term that strips anyone of a right the law already gives them.

Using the files in this directory means you have read this notice.

## What this program does not do

OpenRAR does not implement WinRAR product activation. A `rarreg.key` file next to the binary is not read, not checked, and not displayed. There is no trial banner and no “Registered to” line, with or without that file. The project does not include, port, or depend on a key generator.

`-vd` is accepted so old command lines still parse, and it does not erase disks. `-ma4` is rejected because RAR 4.x is a different codec. `-mc` is accepted and does not change the compressor. Recovery volumes written by `rv` use OpenRAR’s own parity files (magic `ORREV1`). `rc` restores missing volumes from those files. They are not RARLAB `.rev` files, and RARLAB `.rev` files are not read.

## Build

The UI language is chosen at compile time. Packs live in `lang/` (`en`, `zh`, `de`, `fr`, `es`, `ja`, `ru`, `pt`). English is the fallback for any missing line. The default is English.

```sh
cmake -B build -DOPENRAR_LANG=en
cmake --build build -j
```

```sh
cmake -B build -DOPENRAR_LANG=zh
```

`./build.sh zh` does the same on Unix. `build.bat zh` does it with MSVC: it embeds the selected pack and compiles `rar.exe`.

The same sources build on Windows, Linux, macOS, FreeBSD, NetBSD, OpenBSD, and DragonFly. Windows file attributes and NTFS compression apply on Windows. Unix mode, symbolic links, hard links, and owner/group apply on the other systems. `-ao` follows the Windows Archive attribute; elsewhere every file is included and a warning is printed.

## Commands

`a c ch cw d e f i k l lt lta lb m mf p r rc rn rr rv s s- t u v vt vta vb x`, plus the unrar-free long options `--extract`, `--extract-no-paths`, `--extract-newer`, `--list`, `--print`, `--force`, `--password`, `--verbose`, `--version`, and `--help`.

Switches include the usual RAR 5 set: compression `-m` `-md` `-s` `-sN` `-se` `-sv`, encryption `-p` `-hp`, checksums `-htb` `-htc`, volumes `-v` `-vn` `-vp`, recovery record `-rr` and recovery volumes `-rv`, SFX `-sfx`, comments, locks, rename, delete, filters, `-ol` `-oh` `-ow`, `-tk` `-tl` `-w`, `-mt`, `-ri`, `-cfg-`, and `-sc`. Configuration is read from `rarrc` / `rar.ini` and from the `RAR` environment variable unless `-cfg-` is present. `-f` and `-u` work as switches as well as commands.

`rar -iver` prints `7.01`.

## Layout

```text
include/     public headers (format, codec, archive, CLI, OS, messages)
src/         implementations
lang/        UI packs, one key<TAB>value file per language
tools/       embed_lang.py, used by CMake and build.bat
tests/       test_compat.py
```

## License

See [LICENSE](LICENSE). GPL-3.0-or-later.
