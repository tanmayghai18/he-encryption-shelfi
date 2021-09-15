cmake_minimum_required(VERSION 3.5.1)
### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac

project(SHELFI_FHE)
set(CMAKE_CXX_STANDARD 11)

find_package(Palisade REQUIRED)
find_package(OpenMP)

set(CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS})
set(CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS})

include_directories(${OPENMP_INCLUDES})
include_directories(${PALISADE_INCLUDE})
include_directories(${PALISADE_INCLUDE}/third-party/include)
include_directories(${PALISADE_INCLUDE}/core)
include_directories(${PALISADE_INCLUDE}/pke)
include_directories(${PALISADE_INCLUDE}/binfhe)
### add directories for other PALISADE modules as needed for your project

link_directories(${PALISADE_LIBDIR})
link_directories(${OPENMP_LIBRARIES})
link_libraries(${PALISADE_LIBRARIES})


add_subdirectory(pybind11)
# TODO Try to find another way to remove the os specifications postfix in the .so output file.
pybind11_add_module(SHELFI_FHE MODULE src/main.cpp)

# EXAMPLE_VERSION_INFO is defined by setup.py and passed into the C++ code as a
# define (VERSION_INFO) here.
target_compile_definitions(SHELFI_FHE PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})


target_compile_options(SHELFI_FHE PRIVATE -Wall ${OpenMP_CXX_FLAGS})
target_link_libraries(SHELFI_FHE PRIVATE ${OpenMP_CXX_FLAGS})


# Set relative path to CryptoParams directory.
target_compile_definitions(SHELFI_FHE PRIVATE CRYPTO_PARAMS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/resources/cryptoparams")
#target_compile_definitions(SHELFI_FHE PRIVATE CRYPTO_PARAMS_DIR="../resources/cryptoparams")

# We need to include the install command in order for the foreign_cc cmake bazel rule to work.
# Pay attention to the fact that for normal uses, the generated binary does not need to be installed system-wise.
install(TARGETS SHELFI_FHE LIBRARY DESTINATION lib)

# We need to adjust the prefix and the suffix of the target because by default the
# generated pybind11 shared object has the OS distribution as part of its suffix.
# Name target as `target_name` with ".so" extension.
set_target_properties(SHELFI_FHE PROPERTIES PREFIX "" SUFFIX ".so")
