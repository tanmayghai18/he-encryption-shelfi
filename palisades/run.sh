#run after cloning he-encryption-shelfi project
#https://gitlab.com/palisade/palisade-development/-/wikis/Instructions-for-building-PALISADE-in-macOS

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"

brew install cmake
brew install autoconf
brew install libomp


git clone git@gitlab.com:palisade/palisade-development.git

cp pwa_bgvrns.cpp palisade-development/src/pke/examples
cp pwa_ckks.cpp palisade-development/src/pke/examples
cp pwa_utils.h palisade-development/src/pke/examples

cp cnpy/cnpy.h palisade-development/src/pke/
cp cnpy/cnpy.cpp palisade-development/src/pke/
cp csvstream.h palisade-development/src/pke/examples

cp learners_flattened palisade-development/src/pke/examples


mkdir palisade-development/build
cd palisade-development/build

cmake ..
cmake -DCMAKE_CROSSCOMPILING=1 -DRUN_HAVE_STD_REGEX=0 -DRUN_HAVE_POSIX_REGEX=0 ..

echo "add_library(cnpy SHARED "cnpy.cpp")" >> palisade-development/src/pke/CMakeLists.txt
echo "target_link_libraries(pwa_ckks PRIVATE cnpy)" >> palisade-development/src/pke/CMakeLists.txt
echo "target_link_libraries(pwa_bgvrns PRIVATE cnpy)" >> palisade-development/src/pke/CMakeLists.txt
#to compile
make
make pwa_bgvrns
make pwa_ckks

#to run
bin/examples/pke/pwa_bgvrns
bin/examples/pke/pwa_ckks