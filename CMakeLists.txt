cmake_minimum_required(VERSION 3.20)
project(bcrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(bcrypt INTERFACE)
add_library(bcrypt::bcrypt ALIAS bcrypt)

target_include_directories(bcrypt INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

if (MSVC)
  target_compile_options(bcrypt INTERFACE /W4 /permissive-)
else()
  target_compile_options(bcrypt INTERFACE -Wall -Wextra -Wpedantic)
endif()

# bcrypt wrapper uses the system crypt backend when BCRYPT_USE_CRYPT is enabled.
# On many Linux distros, crypt symbols live in libcrypt and must be linked explicitly.
if (UNIX AND NOT APPLE)
  include(CheckLibraryExists)
  check_library_exists(crypt crypt "" HAVE_LIBCRYPT)

  if (HAVE_LIBCRYPT)
    target_link_libraries(bcrypt INTERFACE crypt)
    target_compile_definitions(bcrypt INTERFACE BCRYPT_USE_CRYPT=1)
  else()
    # crypt may still be available from libc on some systems, but if not found
    # consumers can define BCRYPT_CUSTOM_BACKEND to provide their own implementation.
  endif()
endif()

include(CTest)
enable_testing()

add_executable(bcrypt_basic_test tests/test_basic.cpp)
target_link_libraries(bcrypt_basic_test PRIVATE bcrypt::bcrypt)
add_test(NAME bcrypt.basic COMMAND bcrypt_basic_test)
