#!/bin/sh
# Build OpenRAR. Optional first argument is the UI language (default: en).
#   ./build.sh
#   ./build.sh zh
set -eu
cd "$(dirname "$0")"
lang="${1:-en}"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
cmake -B build -DOPENRAR_LANG="$lang"
cmake --build build -j"$jobs"
echo "Built build/rar and build/unrar-free ($lang)"
