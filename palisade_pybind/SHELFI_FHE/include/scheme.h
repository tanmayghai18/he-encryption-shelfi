#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>

#include <omp.h>

class Scheme {

private:
    string scheme;
    int learners;

public:
    Scheme(string scheme, int learners) {
        this->scheme = scheme;
        this->learners = learners;
    }

    void loadCryptoParams();
    void genCryptoContextAndKeyGen();
    py::bytes encrypt(py::array_t<double> data_array, unsigned int iteration);
    py::bytes computeWeightedAverage(py::list learners_data, py::list scaling_factors, int params);
    py::array_t<double> decrypt( string learner_data, unsigned long int data_dimensions, unsigned int iteration);
};
