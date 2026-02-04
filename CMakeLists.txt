cmake_minimum_required(VERSION 3.21)
project(MiniEDR LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

FetchContent_Declare(
  krabsetw
  GIT_REPOSITORY https://github.com/microsoft/krabsetw.git
  GIT_TAG v0.12.0
)

FetchContent_GetProperties(krabsetw)
if (NOT krabsetw_POPULATED)
  FetchContent_Populate(krabsetw)
endif()

FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3
)

FetchContent_MakeAvailable(nlohmann_json)

# Sensible defaults for MSVC
if (MSVC)
  add_compile_options(/W4 /permissive-)
  add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_subdirectory(agent)


# Optional Detours-based hook DLL (Phase 6)
add_subdirectory(hooks)
