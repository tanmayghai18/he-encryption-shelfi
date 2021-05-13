# he-encryption-shelfi

This repo contains scripts for benchmarking the BGN, Pailler, BGVrns, and CKKS crypto-systems. Each folder contains a script (run.sh) to download/install all dependencies and run evaluation scripts.

BGN -> Makefile project, use run.sh to compile and run for evaluation

PaillerCPP -> Makefile project, use run.sh to compile and run for evaluation

palisades -> CMake project, run.sh downloads and installs palisade-developement from a gitlab repo, installs various dependencies and libraries used for evaluation (i.e. cnpy), and runs for evaluation
