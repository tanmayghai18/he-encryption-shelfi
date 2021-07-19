cmake_minimum_required (VERSION 3.5.1)
### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac

project(SHELFI_FHE)
set(CMAKE_CXX_STANDARD 11)

find_package(Palisade)

set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )
set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${PALISADE_INCLUDE} )
include_directories( ${PALISADE_INCLUDE}/third-party/include )
include_directories( ${PALISADE_INCLUDE}/core )
include_directories( ${PALISADE_INCLUDE}/pke )
include_directories( ${PALISADE_INCLUDE}/binfhe )
### add directories for other PALISADE modules as needed for your project

link_directories( ${PALISADE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
link_libraries( ${PALISADE_LIBRARIES} )


add_subdirectory(pybind11)
pybind11_add_module(SHELFI_FHE src/main.cpp)

# EXAMPLE_VERSION_INFO is defined by setup.py and passed into the C++ code as a
# define (VERSION_INFO) here.
target_compile_definitions(SHELFI_FHE PRIVATE VERSION_INFO=${EXAMPLE_VERSION_INFO})

# We need to adjust the prefix and the suffix of the target because by default the
# generated pybind11 shared object has the OS distribution as part of its suffix.
# Name target as `target_name` with ".so" extension.
set_target_properties(SHELFI_FHE PROPERTIES PREFIX "" SUFFIX ".so")
