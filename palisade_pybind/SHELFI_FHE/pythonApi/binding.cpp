#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>

#include "../src/scheme.h"
#include "../src/ckks.cpp"
#include "../src/paillier.cpp"

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;

PYBIND11_MODULE(SHELFI_FHE, m) {

py::class_<Scheme>(m, "Scheme");

py::class_<Ckks, Scheme>(m, "Ckks")
        .def(py::init<std::string &, int, int, int, std::string &>(),
            py::arg("scheme") = py::str("ckks"),
            py::arg("learners") = 10,
            py::arg("batchSize") = 8192, 
            py::arg("scaleFactorBits") = 52, 
            py::arg("cryptodir") = py::str("../resources/cryptoparams/"))
      .def("loadCryptoParams", &Ckks::loadCryptoParams)
      .def("genCryptoContextAndKeyGen", &Ckks::genCryptoContextAndKeyGen)
      .def("encrypt", &Ckks::encrypt)
      .def("decrypt", &Ckks::decrypt)
      .def("computeWeightedAverage", &Ckks::computeWeightedAverage);

py::class_<Paillier, Scheme>(m, "Paillier")
    .def(py::init<std::string &, int, int, int, int, std::string &, std::string &>(),
            py::arg("scheme") = py::str("paillier"),
            py::arg("learners") = 10,
            py::arg("modulus_bits") = 2048, 
            py::arg("num_bits") = 17, 
            py::arg("precision_bits") = 13,
            py::arg("cryptodir") = py::str("../resources/cryptoparams/"),
            py::arg("randomnessdir") = py::str("../resources/random_params/"))
      .def("genPaillierRandOffline", &Pailler::genPaillierRandOffline)
      .def("addPaillierRandOffline", &Pailler::addPaillierRandOffline)
      .def("loadCryptoParams", &Pailler::loadCryptoParams)
      .def("genCryptoContextAndKeyGen", &Pailler:genCryptoContextAndKeyGen)
      .def("encrypt", &Pailler::encrypt)
      .def("decrypt", &Pailler::decrypt)
      .def("computeWeightedAverage", &Pailler::computeWeightedAverage)

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