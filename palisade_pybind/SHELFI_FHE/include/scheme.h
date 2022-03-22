#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>

#include <omp.h>

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;

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

PYBIND11_MODULE(SHELFI_FHE, m) {

py::class_<Scheme>(m, "Scheme")
        .def(py::init<std::string &, int>(),
            py::arg("scheme") = py::str(""),
            py::arg("learners") = 10)
        .def("loadCryptoParams", &Scheme::loadCryptoParams)
        .def("genCryptoContextAndKeyGen", &Scheme::genCryptoContextAndKeyGen)
        .def("encrypt", &Scheme::encrypt)
        .def("computeWeightedAverage", &Scheme::computeWeightedAverage)
        .def("decrypt", &Scheme::decrypt);

py::class_<Ckks, Scheme>(m, "Ckks")
        .def(py::init<int, int, int, std::string &>(),
                py::arg("batchSize") = 8192, 
                py::arg("scaleFactorBits") = 52, 
                py::arg("cryptodir") = py::str("../resources/cryptoparams/"))
      .def("loadCryptoParams", &Ckks::loadCryptoParams)
      .def("genCryptoContextAndKeyGen", &Ckks::genCryptoContextAndKeyGen);
      // .def("encrypt", &Ckks::encrypt)
      // .def("decrypt", &Ckks::decrypt)
      // .def("computeWeightedAverage", &Ckks::computeWeightedAverage);

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

}