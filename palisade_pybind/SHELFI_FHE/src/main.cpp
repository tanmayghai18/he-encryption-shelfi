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
#include <omp.h>


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

  string scheme;
  usint batchSize;
  usint scaleFactorBits;
  std::string cryptodir;

  CryptoContext<DCRTPoly> cc;
  LPPublicKey<DCRTPoly> pk;
  LPPrivateKey<DCRTPoly> sk;

public:
  FHE_Helper(string scheme, usint batchSize, usint scaleFactorBits, string cryptodir = "") {

    this->scheme = scheme;
    this->batchSize = batchSize;
    this->scaleFactorBits = scaleFactorBits;
    this->cryptodir = cryptodir;
  }

  void load_crypto_params() {

    if (!Serial::DeserializeFromFile(cryptodir + "/cryptocontext.txt", cc,
                                     SerType::BINARY)) {
      std::cout << "Could not read serialization from "
                << cryptodir + "/cryptocontext.txt" << std::endl;
    }

    if (!Serial::DeserializeFromFile(cryptodir + "/key-public.txt", pk,
                                     SerType::BINARY)) {
      std::cout << "Could not read public key" << std::endl;
    }

    if (Serial::DeserializeFromFile(cryptodir + "/key-private.txt", sk,
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
    if (!Serial::SerializeToFile(cryptodir + "/cryptocontext.txt",
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
    if (!Serial::SerializeToFile(cryptodir + "/key-public.txt",
                                 keyPair.publicKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of public key to key-public.txt"
                << std::endl;
      return 0;
    }
    std::cout << "The public key has been serialized." << std::endl;

    // Serialize the secret key
    if (!Serial::SerializeToFile(cryptodir + "/key-private.txt",
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
    std::ofstream emkeyfile(cryptodir + "/" + "key-eval-mult.txt",
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

    //double elapsed_time_encryption = 0.0;
    //double elapsed_time_serialize = 0.0;

    unsigned long int size = data_array.size();
    auto learner_Data = data_array.data();

    vector<Ciphertext<DCRTPoly>> ciphertext_data(
        (int)((size + batchSize) / batchSize));


    //auto start_enc = omp_get_wtime();

    if (scheme == "ckks") {

      if (size > (unsigned long int)batchSize) {

        //int j = 0;

        #pragma omp parallel for
        for (unsigned long int i = 0; i < size; i += batchSize) {


          unsigned long int last = std::min((long)size, (long)i + batchSize);

          vector<double> batch;
          batch.reserve(last - i + 1);


          for (unsigned long int j = i; j < last; j++) {

            batch.push_back(learner_Data[j]);
          }


          Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(batch);
          ciphertext_data[(int)(i/batchSize)] = cc->Encrypt(pk, plaintext_data);


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


    //auto end_enc = omp_get_wtime();

    //elapsed_time_encryption = end_enc - start_enc;



    //auto start_serialize = omp_get_wtime();

    stringstream s;
    const SerType::SERBINARY st;
    Serial::Serialize(ciphertext_data, s, st);


    py::bytes res(s.str());

    //auto end_serialize = omp_get_wtime();

    //elapsed_time_serialize = end_serialize - start_serialize;



    //std::cout <<"Encryption Time: "<< elapsed_time_encryption*1000 << " milliseconds"<<'\n';
    //std::cout <<"Serialization Time: "<< elapsed_time_serialize*1000 << " milliseconds"<<'\n';

    return res;
  }

  

  py::bytes computeWeightedAverage(py::list learners_Data,
                                   py::list scalingFactors) {

    //double elapsed_time_deserialize = 0.0;
    //double elapsed_time_pwa = 0.0;
    //double elapsed_time_serialize = 0.0;


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

      //auto start_deserialize = omp_get_wtime();

      string dat = std::string(py::str(learners_Data[i]));

      stringstream ss(dat);
      vector<Ciphertext<DCRTPoly>> learner_ciphertext;

      Serial::Deserialize(learner_ciphertext, ss, st);

      //auto end_deserialize = omp_get_wtime();


      //elapsed_time_deserialize+=end_deserialize - start_deserialize; 


      //auto start_pwa = omp_get_wtime();

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

      //auto end_pwa = omp_get_wtime();

      //elapsed_time_pwa+=end_pwa - start_pwa; 

      learner_ciphertext.clear();
    }


    //auto start_serialize = std::chrono::system_clock::now();

    stringstream ss;
    Serial::Serialize(result_ciphertext, ss, st);
    py::bytes res(ss.str());

    //auto end_serialize = std::chrono::system_clock::now();

    //elapsed_time_serialize+=std::chrono::duration_cast<std::chrono::milliseconds>(end_serialize
      //- start_serialize).count(); 


    //std::cout <<"Deserialization time: "<< elapsed_time_deserialize*1000 << " milliseconds"<<'\n';
    //std::cout <<"PWA Time: "<< elapsed_time_pwa*1000 << " milliseconds"<<'\n';
    //std::cout <<"Serialization Time: "<< elapsed_time_serialize << " milliseconds"<<'\n';



    result_ciphertext.clear();

    return res;
  }

  py::array_t<double> decrypt(string learner_Data,
                              unsigned long int data_dimesions) {

    //double elapsed_time_deserialize = 0.0;
    //double elapsed_time_decrypt = 0.0;


    //auto start_deserialize = std::chrono::system_clock::now();
    const SerType::SERBINARY st;
    stringstream ss(learner_Data);

    vector<Ciphertext<DCRTPoly>> learner_ciphertext;
    Serial::Deserialize(learner_ciphertext, ss, st);

    //auto end_deserialize = std::chrono::system_clock::now();

    //elapsed_time_deserialize+=std::chrono::duration_cast<std::chrono::milliseconds>(end_deserialize
      //- start_deserialize).count(); 



    auto result = py::array_t<double>(data_dimesions);

    py::buffer_info buf3 = result.request();

    double *ptr3 = static_cast<double *>(buf3.ptr);


    //auto start_decrypt = omp_get_wtime();

    #pragma omp parallel for
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

      int m = i*batchSize;

      for (unsigned long int j = 0; j < layer_data.size(); j++) {

        ptr3[m++] = layer_data[j];
      }

      
    }

    //auto end_decrypt = omp_get_wtime();

    //elapsed_time_decrypt+=end_decrypt - start_decrypt; 

    //std::cout <<"Deserialization time: "<< elapsed_time_deserialize<< " milliseconds"<<'\n';
    //std::cout <<"Decryption Time: "<< elapsed_time_decrypt *1000<< " milliseconds"<<'\n';


    learner_ciphertext.clear();

    return result;
  }
};

PYBIND11_MODULE(SHELFI_FHE, m) {

py::class_<FHE_Helper>(m, "FHE_Helper")
        .def(py::init<std::string &, usint, usint, std::string &>(),
                py::arg("scheme") = py::str("ckks"), py::arg("batchSize") = 8192,
                py::arg("scaleFactorBits") = 52, py::arg("cryptodir") = py::str("../resources/cryptoparams"))
      .def("load_crypto_params", &FHE_Helper::load_crypto_params)
      .def("encrypt", &FHE_Helper::encrypt)
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
