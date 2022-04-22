cmake_minimum_required(VERSION 3.13)

project(SHELFI LANGUAGES CXX)


# Import Microsoft SEAL
find_package(SEAL 4.0.0 EXACT REQUIRED)

find_package(OpenMP REQUIRED)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)

add_executable(shelfi)


include_directories( ${CMAKE_CURRENT_LIST_DIR}/src/ )
include_directories( ${CMAKE_CURRENT_LIST_DIR}/include/ )
include_directories( ${OPENMP_INCLUDES} )

#Required for Mac
include_directories( /usr/local/opt/libomp/include/ )



target_sources(shelfi
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/src/main.cpp
        ${CMAKE_CURRENT_LIST_DIR}/src/FHE_Helper.cpp
        )

if(TARGET SEAL::seal)
    target_link_libraries(shelfi PRIVATE SEAL::seal ${OpenMP_CXX_FLAGS})
elseif(TARGET SEAL::seal_shared)
    target_link_libraries(shelfi PRIVATE SEAL::seal_shared ${OpenMP_CXX_FLAGS})
else()
    message(FATAL_ERROR "Cannot find target SEAL::seal or SEAL::seal_shared")
endif()


target_compile_options(shelfi PRIVATE -Wall ${OpenMP_CXX_FLAGS})

