cmake_minimum_required(VERSION 3.13)

project(SHELFI_FHE LANGUAGES CXX)
#set(CMAKE_CXX_STANDARD 11)


find_package(SEAL 4.0.0 EXACT REQUIRED)
find_package(OpenMP REQUIRED)


set(CMAKE_MODULE_PATH
    ${CMAKE_CURRENT_LIST_DIR}/cmake
    ${CMAKE_MODULE_PATH}
)



include_directories(${OPENMP_INCLUDES})

### add directories for other PALISADE modules as needed for your project


include_directories(include)
include_directories(src)

add_subdirectory(pybind11)
# TODO Try to find another way to remove the os specifications postfix in the .so output file.
pybind11_add_module(SHELFI_FHE MODULE src/binding.cpp src/ckks.cpp  )

# EXAMPLE_VERSION_INFO is defined by setup.py and passed into the C++ code as a
# define (VERSION_INFO) here.
target_compile_definitions(SHELFI_FHE PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})

#target_compile_options(SHELFI_FHE PRIVATE -Wall ${OpenMP_CXX_FLAGS})
target_compile_options(SHELFI_FHE PRIVATE $<$<COMPILE_LANG_AND_ID:CXX,GNU>:-Wall;${OpenMP_CXX_FLAGS}>)



target_link_libraries(SHELFI_FHE PRIVATE SEAL::seal ${OpenMP_CXX_FLAGS})

# We need to include the install command in order for the foreign_cc cmake bazel rule to work.
# Pay attention to the fact that for normal uses, the generated binary does not need to be installed system-wise.
install(TARGETS SHELFI_FHE LIBRARY DESTINATION lib)

# We need to adjust the prefix and the suffix of the target because by default the
# generated pybind11 shared object has the OS distribution as part of its suffix.
# Name target as `target_name` with ".so" extension.
set_target_properties(SHELFI_FHE PROPERTIES PREFIX "" SUFFIX ".so")
