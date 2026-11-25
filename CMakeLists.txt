cmake_minimum_required(VERSION 3.16)
project(OpenRAR VERSION 7.01 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Bake one UI language into the binary. Packs live in lang/.
#   cmake -B build -DOPENRAR_LANG=en
#   cmake -B build -DOPENRAR_LANG=zh
set(OPENRAR_LANG "en" CACHE STRING "UI language baked into the binary (en, zh, de, fr, es, ja, ru, pt)")
set(OPENRAR_LANG_FILE "${CMAKE_SOURCE_DIR}/lang/${OPENRAR_LANG}.txt")
if(NOT EXISTS "${OPENRAR_LANG_FILE}")
    message(FATAL_ERROR "OPENRAR_LANG='${OPENRAR_LANG}' has no pack at ${OPENRAR_LANG_FILE}")
endif()

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(OPENRAR_LANG_INC "${CMAKE_BINARY_DIR}/generated/rar_lang_table.inc")
add_custom_command(
    OUTPUT "${OPENRAR_LANG_INC}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/generated"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tools/embed_lang.py"
            "${CMAKE_SOURCE_DIR}/lang/en.txt"
            "${OPENRAR_LANG_FILE}"
            "${OPENRAR_LANG_INC}"
    DEPENDS
        "${CMAKE_SOURCE_DIR}/tools/embed_lang.py"
        "${CMAKE_SOURCE_DIR}/lang/en.txt"
        "${OPENRAR_LANG_FILE}"
    VERBATIM
)
add_custom_target(openrar_lang DEPENDS "${OPENRAR_LANG_INC}")

set(OPENRAR_SOURCES
    src/rar_crypto.cpp
    src/rar_codec.cpp
    src/rar_archive.cpp
    src/rar_recover.cpp
    src/rar_os.cpp
    src/rar_i18n.cpp
    src/rar_cli.cpp
    src/main.cpp
)

find_package(Threads REQUIRED)

function(openrar_target name)
    add_executable(${name} ${OPENRAR_SOURCES})
    add_dependencies(${name} openrar_lang)
    target_include_directories(${name} PRIVATE include "${CMAKE_BINARY_DIR}/generated")
    target_link_libraries(${name} PRIVATE Threads::Threads)
    if(WIN32)
        target_link_libraries(${name} PRIVATE shell32 advapi32)
    endif()
    if(MSVC)
        target_compile_options(${name} PRIVATE /utf-8 /W3 /O2 /EHsc)
    else()
        target_compile_options(${name} PRIVATE -Wall -Wextra -O2)
    endif()
endfunction()

openrar_target(rar)
openrar_target(unrar-free)
