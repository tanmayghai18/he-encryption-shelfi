#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <omp.h>
#include "scheme.h"

#include <seal/seal.h>
#include <iostream>
#include <fstream>
#include <sstream>

using namespace seal;
using namespace std;

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;

class CKKS : public Scheme {

private:

	uint batchSize;
	uint scaleFactorBits;
	std::string cryptodir;

	SEALContext* context = nullptr;
	PublicKey public_key;
	SecretKey secret_key;

public:
	CKKS(string scheme, uint batchSize, uint scaleFactorBits, string cryptodir);

	virtual int genCryptoContextAndKeyGen();
	virtual void loadCryptoParams();

	virtual py::bytes encrypt(py::array_t<double> data_array);
	virtual py::bytes computeWeightedAverage(py::list learner_data, py::list scaling_factors);
	virtual py::array_t<double> decrypt(string learner_data, unsigned long int data_dimensions);

	
};