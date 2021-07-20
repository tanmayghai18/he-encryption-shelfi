# he-encryption-shelfi

This repo contains scripts for benchmarking the BGN, Pailler, BGVrns, and CKKS crypto-systems. 


palisade_pybind folder contains the implementation of weighted average operation with python bindings.

To run this:

Install Palisades and Pybind11.

Then open terminal in the palisade_pybind/SHELFI_FHE/src folder and install the library as:

pip install ../

Then you can test the library using a sample python script in SHELFI_FHE/tests/test.py as:

python3 ../tests/test.py


palisade_shelfi_interface folder contains the normal C++ implementation of the weighted average computation which make be compiled using cmake.


Each folder contains a script (run.sh) to download/install all dependencies and run evaluation scripts.

BGN -> Makefile project, use run.sh to compile and run for evaluation

PaillerCPP -> Makefile project, use run.sh to compile and run for evaluation

palisades -> CMake project, run.sh downloads and installs palisade-developement from a gitlab repo, installs various dependencies and libraries used for evaluation (i.e. cnpy), and runs for evaluation
