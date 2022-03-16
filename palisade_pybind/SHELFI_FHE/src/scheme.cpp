#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <omp.h>

class Scheme {

private:
     int totalLearners;

public:
    Scheme(int learners) {
        this->totalLearners = learners;
    }

    virtual void loadCryptoParams();
    virtual void genCryptoContextAndKeyGen();
    virtual py::bytes encrypt(py::array_t<double> data_array, unsigned int iteration);
    virtual py::bytes computeWeightedAverage(py::list learners_Data, py::list scalingFactors, int params);
    virtual py::array_t<double> decrypt( string learner_Data, unsigned long int data_dimesions, unsigned int iteration);
    virtual py::bytes computeWeightedAverage(py::list learners_Data, py::list scalingFactors, int params);
};

py::class_<FHE_Helper>(m, "Scheme")
        .def(int, py::arg("learners") = 10)
        .def("loadCryptoParams", &Scheme::loadCryptoParams)
        .def("genCryptoContextAndKeyGen", &Scheme:genCryptoContextAndKeyGen)
        .def("encrypt", &Scheme::encrypt)
        .def("decrypt", &Scheme::decrypt)
        .def("computeWeightedAverage", &Scheme::computeWeightedAverage)

  m.doc() = R"pbdoc(
        Pybind11 example plugin
        -----------------------
        .. currentmodule:: cmake_example
        .. autosummary::
           :toctree: _generate
    )pbdoc";

#ifdef VERSION_INFO
  m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
  m.attr("__version__") = "dev";
#endif