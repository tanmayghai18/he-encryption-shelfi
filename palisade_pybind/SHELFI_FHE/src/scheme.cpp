#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>

#include <omp.h>

using namespace std;
namespace py = pybind11;

class Scheme {

private:
    string scheme;
    int learners;

public:
    Scheme(string scheme, int learners) : scheme(scheme), learners(learners){};

    virtual void loadCryptoParams() = 0;
    virtual int genCryptoContextAndKeyGen() = 0;
    virtual py::bytes encrypt(py::array_t<double> data_array, unsigned int iteration);
    virtual py::bytes computeWeightedAverage(py::list learners_data, py::list scaling_factors, int params);
    virtual py::array_t<double> decrypt( string learner_data, unsigned long int data_dimensions, unsigned int iteration);
};
