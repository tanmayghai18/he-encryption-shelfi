# he-encryption-shelfi

Benchmarking for various crypto-systems (e.g. Paillier, CKKS) integrated with a federated learning architecture

`FHE_CPP`: cpp only implementation for CKKS 

`Pailler_Offline_Online_CPP`: cpp only implementation for Pailler (offline + online)

`palisade_pybind`: implementation of private weighted average integrated with underlying schemes with python wrapper and bindings. 

### Dependencies (tested in Ubuntu)
- `PALISADE`: a lattice-based homomorphic encryption library in C++. Follow the instructions on https://gitlab.com/palisade/palisade-release to download, compile, and install the library. Make sure to run `make install` in the user-created `\build` directory for a complete installation. 

- `Crypto++`: a Linux cryptographic library to provide various functionality (we primarily utilize this for our Pailler implementation). Follow the instructions https://github.com/weidai11/cryptopp and make sure to run `make install` in the root dir. of the library for a complete install.

- `pybind-11`: pip install pybind11, make sure to have have `python3` and `cmake` already installed. 

`palisade_pybind` folder contains the implementation of weighted average operation with python bindings.

### To Run

go to the `palisade_pybind/SHELFI_FHE/src` folder and run `pip install ../`

Tests/Examples as wella as the `pybind11` binding code are located in the `../pythonApi` directory (relative to dir. above) and can be run by simply running:

`python3 ../pythonApi/[example].py`

