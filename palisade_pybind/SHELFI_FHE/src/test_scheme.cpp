#include "PaillierUtils.h"
#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <omp.h>
#include <scheme.h>

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;

class TestScheme : public Scheme {

private:
	usint batchSize;
	usint scaleFactorBits;
	string cryptodir;

public:
	TestScheme(usint batchSize, usint scaleFactorBits, string cryptodir) {
		this->batchSize = batchSize;
		this->scaleFactorBits = scaleFactorBits;
		this->cryptodir = cryptodir;
	}

	