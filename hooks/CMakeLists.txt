cmake_minimum_required(VERSION 3.21)

# Optional Detours-based API hook DLL (x64 only). Disabled by default.
# Build requires Detours built separately. Set DETOURS_ROOT to the Detours repo root (containing src/detours.h and lib.X64/detours.lib).
project(MiniEDR_Hooks LANGUAGES CXX)

option(MINIEDR_BUILD_APIOOK_DLL "Build Detours-based ApiHook DLL (x64)" OFF)

if (NOT MINIEDR_BUILD_APIOOK_DLL)
  message(STATUS "MINIEDR_BUILD_APIOOK_DLL=OFF (skipping hook DLL)")
  return()
endif()

if (NOT DEFINED DETOURS_ROOT)
  message(FATAL_ERROR "Set -DDETOURS_ROOT=... (Detours repo root)")
endif()

set(DETOURS_INC "${DETOURS_ROOT}/src")
# Common Detours output dirs: lib.X64 (nmake) or build output. We support user override.
if (NOT DEFINED DETOURS_LIB)
  set(DETOURS_LIB "${DETOURS_ROOT}/lib.X64/detours.lib")
endif()

add_library(MiniEDR_ApiHookDll64 SHARED
  ApiHookDll64.cpp
)

target_include_directories(MiniEDR_ApiHookDll64 PRIVATE "${DETOURS_INC}")
target_link_libraries(MiniEDR_ApiHookDll64 PRIVATE "${DETOURS_LIB}" advapi32)

target_compile_definitions(MiniEDR_ApiHookDll64 PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

set_target_properties(MiniEDR_ApiHookDll64 PROPERTIES
  OUTPUT_NAME "MiniEDR.ApiHookDll64"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
