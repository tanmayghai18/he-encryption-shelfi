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

find_package(Palisade REQUIRED)
find_package(OpenMP)

set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )
set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${PALISADE_INCLUDE} )
include_directories( ${PALISADE_INCLUDE}/third-party/include )
include_directories( ${PALISADE_INCLUDE}/core )
include_directories( ${PALISADE_INCLUDE}/pke )
include_directories(${PALISADE_INCLUDE}/binfhe)
### add directories for other PALISADE modules as needed for your project

link_directories( ${PALISADE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
link_libraries( ${PALISADE_LIBRARIES} )


include_directories(include)
include_directories(src)

add_executable( SHELFI_FHE src/main.cpp src/FHE_Helper.cpp)


target_compile_options(SHELFI_FHE PRIVATE -Wall ${OpenMP_CXX_FLAGS})
target_link_libraries(SHELFI_FHE PRIVATE ${OpenMP_CXX_FLAGS})



