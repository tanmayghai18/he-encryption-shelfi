#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "palisade.h"
#include "pubkeylp-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include <string>

#include <pybind11/numpy.h>

using namespace std;
using namespace lbcrypto;
// using namespace std::chrono;

// CEREAL_REGISTER_TYPE(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>);

// lbcrypto::CryptoContextImpl<lbcrypto::DCRTPolyImpl

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)

namespace py = pybind11;

class FHE_Helper {

private:
  // Using the cmake target compilation definition. This enables the placement
  // of the CryptoParams directory relative to the working directory.
  const std::string DATAFOLDER = CRYPTO_PARAMS_DIR;

  string scheme;
  usint batchSize;
  usint scaleFactorBits;

  CryptoContext<DCRTPoly> cc;
  LPPublicKey<DCRTPoly> pk;
  LPPrivateKey<DCRTPoly> sk;

public:
  FHE_Helper(string scheme, usint batchSize, usint scaleFactorBits) {

    this->scheme = scheme;
    this->batchSize = batchSize;
    this->scaleFactorBits = scaleFactorBits;
  }

  void load_cyrpto_params() {

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
                                     SerType::BINARY)) {
      std::cout << "Could not read serialization from "
                << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                     SerType::BINARY)) {
      std::cout << "Could not read public key" << std::endl;
    }

    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", sk,
                                    SerType::BINARY) == false) {
      std::cerr << "Could not read secret key" << std::endl;
    }
  }

  int genCryptoContextAndKeyGen() {
    CryptoContext<DCRTPoly> cryptoContext;
    if (scheme == "bgvrns") {
      int plaintextModulus = 65537;
      double sigma = 3.2;
      SecurityLevel securityLevel = HEStd_128_classic;
      uint32_t depth = 2;

      // Instantiate the crypto context
      cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV,
          0, 0, 0, 0, 0, batchSize);

      std::cout << "\nThe cryptocontext has been generated.\n" << std::endl;

    } else if (scheme == "ckks") {

      usint multDepth = 2;

      cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize);
    }

    // enable features that you wish to use
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);
    // cryptoContext->Enable(LEVELEDSHE);

    std::cout << "\nThe cryptocontext has been generated." << std::endl;

    // Serialize cryptocontext
    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt",
                                 cryptoContext, SerType::BINARY)) {
      std::cerr << "Error writing serialization of the crypto context to "
                   "cryptocontext.txt"
                << std::endl;
      return 0;
    }
    std::cout << "The cryptocontext has been serialized." << std::endl;

    // Initialize Public Key Containers
    LPKeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::cout << "The key pair has been generated." << std::endl;

    // Serialize the public key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt",
                                 keyPair.publicKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of public key to key-public.txt"
                << std::endl;
      return 0;
    }
    std::cout << "The public key has been serialized." << std::endl;

    // Serialize the secret key
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt",
                                 keyPair.secretKey, SerType::BINARY)) {
      std::cerr
          << "Error writing serialization of private key to key-private.txt"
          << std::endl;
      return 0;
    }
    std::cout << "The secret key has been serialized." << std::endl;

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    std::cout << "The eval mult keys have been generated." << std::endl;

    // Serialize the relinearization (evaluation) key for homomorphic
    // multiplication
    std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt",
                            std::ios::out | std::ios::binary);
    if (emkeyfile.is_open()) {
      if (cryptoContext->SerializeEvalMultKey(emkeyfile, SerType::BINARY) ==
          false) {
        std::cerr << "Error writing serialization of the eval mult keys to "
                     "key-eval-mult.txt"
                  << std::endl;
        return 0;
      }
      std::cout << "The eval mult keys have been serialized." << std::endl;

      emkeyfile.close();
    } else {
      std::cerr << "Error serializing eval mult keys" << std::endl;
      return 0;
    }
    return 1;
  }

  py::bytes encrypt(py::array_t<double> data_array) {

    unsigned long int size = data_array.size();

    auto learner_Data = data_array.data();

    // double elapsed_time = 0.0;

    vector<Ciphertext<DCRTPoly>> ciphertext_data(
        (int)((size + batchSize) / batchSize));

    // ciphertext_data.reserve((int)((size + batchSize) / batchSize));

    if (scheme == "ckks") {

      if (size > (unsigned long int)batchSize) {

        int j = 0;

        for (unsigned long int i = 0; i < size; i += batchSize) {

          unsigned long int last = std::min((long)size, (long)i + batchSize);

          vector<double> batch;
          batch.reserve(last - i + 1);

          for (unsigned long int j = i; j < last; j++) {

            batch.push_back(learner_Data[j]);
          }

          // auto start = std::chrono::system_clock::now();

          Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(batch);
          ciphertext_data[j++] = cc->Encrypt(pk, plaintext_data);

          // auto end = std::chrono::system_clock::now();

          // elapsed_time+=std::chrono::duration_cast<std::chrono::milliseconds>(end
          // - start).count();

          batch.clear();
        }

      }

      else {

        vector<double> batch;

        batch.reserve(size);

        for (unsigned long int i = 0; i < size; i++) {

          // float dat = py::float_(learner_Data[i]);
          batch.push_back(py::float_(learner_Data[i]));
        }

        Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(batch);
        ciphertext_data[0] = cc->Encrypt(pk, plaintext_data);
      }

    }

    else {

      std::cout << "Not supported!" << std::endl;
      return "";
    }

    // end = std::chrono::system_clock::now();
    // elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end -
    // start);
    // std::cout <<"Encryption: "<< elapsed_time << " milliseconds"<<'\n';

    // auto start = std::chrono::system_clock::now();

    stringstream s;
    const SerType::SERBINARY st;
    Serial::Serialize(ciphertext_data, s, st);

    // ciphertext_data.clear();

    py::bytes res(s.str());

    // auto end = std::chrono::system_clock::now();
    // auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end
    // - start); std::cout <<"Serialization: "<< elapsed.count() << "
    // milliseconds"<<'\n';

    return res;
  }

  /*py::bytes encrypt_list(py::list data_list_array, unsigned long int
  total_params) {


          unsigned long int size = total_params;

          vector<Ciphertext<DCRTPoly>> ciphertext_data((int)((size + batchSize)
  / batchSize));


          if (scheme == "ckks") {


                  int vec_index = 0;
                  int cipher_index=0;

                  vector<double> batch;
                  batch.reserve(batchSize);


                  for(unsigned long int i=0; i<data_list_array.size(); i++){

                          py::array_t<double> casted_array =
  py::cast<py::array>(data_list_array[i]);

                          unsigned long int arr_size = casted_array.size();

                          auto layer_data_req = casted_array.request();

                          double* layer_data = (double*) layer_data_req.ptr;

                          for(unsigned long int j=0; j<arr_size; j++){

                                  if(vec_index<batchSize){

                                          batch.push_back(py::float_(layer_data[vec_index++]));

                                  }

                                  else{

                                          vec_index = 0;

                                          Plaintext plaintext_data =
  cc->MakeCKKSPackedPlaintext(batch); ciphertext_data[cipher_index++] =
  cc->Encrypt(pk, plaintext_data);

                                          batch.clear();
                                          batch.reserve(batchSize);

                                  }


                          }

                  }

                  if(batch.size() > 0){

                          Plaintext plaintext_data =
  cc->MakeCKKSPackedPlaintext(batch); ciphertext_data[cipher_index++] =
  cc->Encrypt(pk, plaintext_data);

                          batch.clear();

                  }



          }

          else {

                  std::cout << "Not supported!" << std::endl;
                  return "";

          }

          // end = std::chrono::system_clock::now();
          // elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end
  - start);
          //std::cout <<"Encryption: "<< elapsed_time << " milliseconds"<<'\n';




          //auto start = std::chrono::system_clock::now();

          stringstream s;
          const SerType::SERBINARY st;
          Serial::Serialize(ciphertext_data, s, st);

          //ciphertext_data.clear();

          py::bytes res(s.str());


          //auto end = std::chrono::system_clock::now();
          //auto elapsed =
  std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
          //std::cout <<"Serialization: "<< elapsed.count() << "
  milliseconds"<<'\n';


          return res;


  }*/

  py::bytes computeWeightedAverage(py::list learners_Data,
                                   py::list scalingFactors) {

    if (scheme != "ckks") {
      std::cout << "Not supported!" << std::endl;
    }

    if (learners_Data.size() != scalingFactors.size()) {
      cout << "Error: learners_Data and scalingFactors size mismatch" << endl;
      return "";
    }

    const SerType::SERBINARY st;

    vector<Ciphertext<DCRTPoly>> result_ciphertext;

    for (unsigned long int i = 0; i < learners_Data.size(); i++) {

      string dat = std::string(py::str(learners_Data[i]));

      stringstream ss(dat);
      vector<Ciphertext<DCRTPoly>> learner_ciphertext;

      Serial::Deserialize(learner_ciphertext, ss, st);

      for (unsigned long int j = 0; j < learner_ciphertext.size(); j++) {

        float sc = py::float_(scalingFactors[i]);

        learner_ciphertext[j] = cc->EvalMult(learner_ciphertext[j], sc);
      }

      if (result_ciphertext.size() == 0) {

        result_ciphertext = learner_ciphertext;
      }

      else {

        for (unsigned long int j = 0; j < learner_ciphertext.size(); j++) {

          result_ciphertext[j] =
              cc->EvalAdd(result_ciphertext[j], learner_ciphertext[j]);
        }
      }

      learner_ciphertext.clear();
    }

    stringstream ss;
    Serial::Serialize(result_ciphertext, ss, st);

    result_ciphertext.clear();

    return py::bytes(ss.str());
  }

  py::array_t<double> decrypt(string learner_Data,
                              unsigned long int data_dimesions) {

    const SerType::SERBINARY st;
    stringstream ss(learner_Data);

    vector<Ciphertext<DCRTPoly>> learner_ciphertext;
    Serial::Deserialize(learner_ciphertext, ss, st);

    // py::array_t<double> result(data_dimesions);

    auto result = py::array_t<double>(data_dimesions);

    py::buffer_info buf3 = result.request();

    double *ptr3 = static_cast<double *>(buf3.ptr);

    // result.reserve(data_dimesions);

    size_t m = 0;

    for (unsigned long int i = 0; i < learner_ciphertext.size(); i++) {

      Plaintext pt;
      cc->Decrypt(sk, learner_ciphertext[i], &pt);

      int length;

      if (i == learner_ciphertext.size() - 1) {

        length = data_dimesions - (i)*batchSize;
      }

      else {

        length = batchSize;
      }

      pt->SetLength(length);

      vector<double> layer_data = pt->GetRealPackedValue();

      for (unsigned long int j = 0; j < layer_data.size(); j++) {

        ptr3[m++] = layer_data[j];
      }

      // cout<<endl;

      // result.insert(result.end(), layer_data.begin(), layer_data.end());
    }

    learner_ciphertext.clear();

    return result;
  }
};

PYBIND11_MODULE(SHELFI_FHE, m) {

  py::class_<FHE_Helper>(m, "FHE_Helper")
      .def(py::init<std::string &, usint, usint>())
      .def("load_cyrpto_params", &FHE_Helper::load_cyrpto_params)
      .def("encrypt", &FHE_Helper::encrypt)
      //.def("encrypt_list", &FHE_Helper::encrypt_list)
      .def("decrypt", &FHE_Helper::decrypt)
      .def("computeWeightedAverage", &FHE_Helper::computeWeightedAverage)
      .def("genCryptoContextAndKeyGen", &FHE_Helper::genCryptoContextAndKeyGen);

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
