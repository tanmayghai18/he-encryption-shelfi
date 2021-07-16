#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/complex.h>
#include <pybind11/pytypes.h>


#include "palisade.h"
#include "cryptocontext-ser.h"
#include "ciphertext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include <string>



using namespace std;
using namespace lbcrypto;
using namespace std::chrono;


//CEREAL_REGISTER_TYPE(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>);

//lbcrypto::CryptoContextImpl<lbcrypto::DCRTPolyImpl

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)


const std::string DATAFOLDER = "SHELFI_FHE/CryptoParams";
namespace py = pybind11;

usint batchSize = 8192;


PYBIND11_MAKE_OPAQUE(std::vector<float, std::allocator<float>>);
using FloatVector = std::vector<float, std::allocator<float>>;

PYBIND11_MAKE_OPAQUE(std::vector<int, std::allocator<int>>);
using IntVector = std::vector<int, std::allocator<int>>;

PYBIND11_MAKE_OPAQUE(std::vector<std::string, std::allocator<std::string>>);
using StringList = std::vector<std::string, std::allocator<std::string>>;


PYBIND11_MAKE_OPAQUE(std::vector<double, std::allocator<double>>);
using DoubleVector = std::vector<double, std::allocator<double>>;

PYBIND11_MAKE_OPAQUE(std::vector<complex<double>, std::allocator<complex<double>>>);
using ComplexVector = std::vector<complex<double>, std::allocator<complex<double>>>;

PYBIND11_MAKE_OPAQUE(std::vector<vector<double>, std::allocator<vector<double>>>);
using VecVecDouble = std::vector<vector<double>, std::allocator<vector<double>>>;

PYBIND11_MAKE_OPAQUE(std::vector<vector<complex<double>>, std::allocator<vector<complex<double>>>>);
using VecVecComplex = std::vector<vector<complex<double>>, std::allocator<vector<complex<double>>>>;


/**
 * input: (string) cryptoscheme to use, generates, serializes, and stores all relevant content 
 * (i.e. cryptocontext, public/private/evaluation keys) in binary form into files stored in the `demoData` 
 * directory
 **/
int genCryptoContextAndKeyGen(string scheme) {
    CryptoContext<DCRTPoly> cryptoContext;
    if (scheme == "bgvrns") {
        int plaintextModulus = 65537;
        double sigma = 3.2;
        SecurityLevel securityLevel = HEStd_128_classic;
        uint32_t depth = 2;
        

        // Instantiate the crypto context
        cryptoContext =
          CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
              depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV,
              0, 0, 0, 0, 0,batchSize);

        std::cout << "\nThe cryptocontext has been generated.\n" << std::endl;

    } else if (scheme == "ckks") {

        usint multDepth = 2;
        usint scaleFactorBits = 52;
        

        cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize);
    }

    // enable features that you wish to use
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);
    //cryptoContext->Enable(LEVELEDSHE);

    std::cout << "\nThe cryptocontext has been generated." << std::endl;

    // Serialize cryptocontext
    if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext,
                               SerType::BINARY)) {
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
    std::cerr << "Error writing serialization of private key to key-private.txt"
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
    if (cryptoContext->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
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



/**
 * input: (string) cryptoscheme to use, (vector<vector<double>>) learner weights
 * encrypts all model weights and serializes them into a string
 **/

py::bytes encryption(string scheme, ComplexVector learner_Data) {


    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
                                   SerType::BINARY)) {
    std::cout << "Could not read serialization from "
              << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }

    LPPublicKey<DCRTPoly> pk;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                  SerType::BINARY)) {
    std::cout << "Could not read public key" << std::endl;
    }


    vector<Ciphertext<DCRTPoly>> ciphertext_data((int)((learner_Data.size() + batchSize) / batchSize));


    if (scheme == "ckks") {


        if(learner_Data.size()>(long unsigned int)batchSize){

            int j=0;

            for(long unsigned int i = 0; i < learner_Data.size(); i += batchSize) {

                auto last = std::min(learner_Data.size(), i + batchSize);

                ComplexVector batch(learner_Data.begin() + i, learner_Data.begin() + last);

                Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(batch);
                ciphertext_data[j++] = cc->Encrypt(pk, plaintext_data);


            }

        }

        else{

        Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(learner_Data);

        ciphertext_data[0] = cc->Encrypt(pk, plaintext_data);


        }




       

    }
    else {


        /*for(int i=0; i<learner_Data.size(); i++){

            vector<int> row(learner_Data[i].begin(), learner_Data[i].end());
            Plaintext plaintext_data = cc->MakePackedPlaintext(row);
            ciphertext_data.push_back(cc->Encrypt(pk, plaintext_data));

        }*/

        std::cout << "Not supported!" << std::endl;
        return "";



    }


    stringstream s;
    const SerType::SERBINARY st;
    Serial::Serialize(ciphertext_data, s, st);


    return py::bytes(s.str());

}



/**
 * input: (string) scheme, (vector<string>) learners_Data a vector of binary ciphertext of all learners,
 * (vector<float>) scalingFactors is a vector with scaling factor for each learner
 * computes private weighted average over all learner data returns binary ciphertext of result
 **/

//std::vector<float> scalingFactors

py::bytes computeWeightedAverage(string scheme, StringList learners_Data, FloatVector scalingFactors) {


    if(scheme!= "ckks"){
        std::cout<<"Not supported!"<<std::endl;
    }


    if(learners_Data.size() != scalingFactors.size()){
        cout<<"Error: learners_Data and scalingFactors size mismatch"<<endl;
        return "";
    }


    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
                                   SerType::BINARY)) {
    std::cerr << "Could not read serialization from "
              << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }


    const SerType::SERBINARY st;

    vector<Ciphertext<DCRTPoly>> result_ciphertext;



     for(unsigned long int i=0; i<learners_Data.size(); i++){

        stringstream ss(learners_Data[i]);
        vector<Ciphertext<DCRTPoly>> learner_ciphertext;

        Serial::Deserialize(learner_ciphertext, ss, st);


        for(unsigned long int j=0; j<learner_ciphertext.size(); j++){

            float sc = scalingFactors[i];

            learner_ciphertext[j] = cc->EvalMult(learner_ciphertext[j], sc);

        }


        if(result_ciphertext.size() == 0){

            result_ciphertext = learner_ciphertext;
        }

        else{

            for(unsigned long int j=0; j<learner_ciphertext.size(); j++){

                result_ciphertext[j] = cc->EvalAdd(result_ciphertext[j], learner_ciphertext[j]);

            }

        }


    }


    stringstream ss;
    Serial::Serialize(result_ciphertext, ss, st);

    return py::bytes(ss.str());


}


/**
 * data_dimesions is a list containing number of parameters in each layer 
 **/

vector<double> decryption(string scheme, string learner_Data, unsigned long int data_dimesions) {


    CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
                                   SerType::BINARY)) {
    std::cerr << "Could not read serialization from "
              << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }


    LPPrivateKey<DCRTPoly> sk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", sk,
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read secret key" << std::endl;
    }


    const SerType::SERBINARY st;
    stringstream ss(learner_Data);
    
    vector<Ciphertext<DCRTPoly>> learner_ciphertext;
    Serial::Deserialize(learner_ciphertext, ss, st);


    vector<double> result;


    for(unsigned long int i=0; i<learner_ciphertext.size(); i++){

        Plaintext pt;
        cc->Decrypt(sk, learner_ciphertext[i], &pt);

        int length;

        if(i==learner_ciphertext.size()-1){

            length = data_dimesions - (i)*batchSize;
        }

        else{

            length = batchSize;
        }

        pt->SetLength(length);

        //cout<<pt<<endl<<endl<<endl;

        vector<complex<double>> layer_complex = pt->GetCKKSPackedValue();
        

        for(int j=0; j<layer_complex.size(); j++){

            result.push_back(layer_complex[j].real());

        }


    }


    return result;

}

PYBIND11_MODULE(SHELFI_FHE, m) {

    py::class_<std::vector<float>>(m, "FloatVector")
    .def(py::init<>())
    .def("clear", &std::vector<float>::clear)
    .def("push_back", (void (FloatVector::*)(const float &)) &FloatVector::push_back)
    .def("pop_back", &std::vector<float>::pop_back)
    .def("__len__", [](const std::vector<float> &v) { return v.size(); })
    .def("__iter__", [](std::vector<float> &v) {
       return py::make_iterator(v.begin(), v.end());
    }, py::keep_alive<0, 1>());

    py::class_<std::vector<double>>(m, "DoubleVector")
    .def(py::init<>())
    .def("clear", &std::vector<double>::clear)
    .def("push_back", (void (DoubleVector::*)(const double &)) &DoubleVector::push_back)
    .def("pop_back", &std::vector<double>::pop_back)
    .def("__len__", [](const std::vector<double> &v) { return v.size(); })
    .def("__iter__", [](std::vector<double> &v) {
       return py::make_iterator(v.begin(), v.end());
    }, py::keep_alive<0, 1>());

    py::class_<std::vector<complex<double>>>(m, "ComplexVector")
    .def(py::init<>())
    .def("clear", &std::vector<complex<double>>::clear)
    .def("push_back", (void (ComplexVector::*)(const complex<double> &)) &ComplexVector::push_back)
    .def("pop_back", &std::vector<complex<double>>::pop_back)
    .def("__len__", [](const std::vector<complex<double>> &v) { return v.size(); })
    .def("__iter__", [](std::vector<complex<double>> &v) {
       return py::make_iterator(v.begin(), v.end());
    }, py::keep_alive<0, 1>());


    py::class_<std::vector<int>>(m, "IntVector")
    .def(py::init<>())
    .def("clear", &std::vector<int>::clear)
    .def("pop_back", &std::vector<int>::pop_back)
    .def("push_back", (void (IntVector::*)(const int &)) &IntVector::push_back)
    .def("__len__", [](const std::vector<int> &v) { return v.size(); })
    .def("__iter__", [](std::vector<int> &v) {
       return py::make_iterator(v.begin(), v.end());
    }, py::keep_alive<0, 1>()); /* Keep vector alive while iterator is used */



    py::class_<StringList>(m, "StringList")
        .def(py::init<>())
        .def("pop_back", &StringList::pop_back)
        // There are multiple versions of push_back(), etc. Select the right ones. 
        .def("push_back", (void (StringList::*)(const std::string &)) &StringList::push_back)
        .def("back", (std::string &(StringList::*)()) &StringList::back)
        .def("__len__", [](const StringList &v) { return v.size(); })
        .def("__iter__", [](StringList &v) {
           return py::make_iterator(v.begin(), v.end());
        }, py::keep_alive<0, 1>());


    py::class_<VecVecDouble>(m, "VecVecDouble")
        .def(py::init<>())
        .def("pop_back", &VecVecDouble::pop_back)
        /* There are multiple versions of push_back(), etc. Select the right ones. */
        .def("push_back", (void (VecVecDouble::*)(const vector<double> &)) &VecVecDouble::push_back)
        .def("back", (vector<double> &(VecVecDouble::*)()) &VecVecDouble::back)
        .def("__len__", [](const VecVecDouble &v) { return v.size(); })
        .def("__iter__", [](VecVecDouble &v) {
           return py::make_iterator(v.begin(), v.end());
        }, py::keep_alive<0, 1>());


    py::class_<VecVecComplex>(m, "VecVecComplex")
        .def(py::init<>())
        .def("pop_back", &VecVecComplex::pop_back)
        // There are multiple versions of push_back(), etc. Select the right ones. 
        .def("push_back", (void (VecVecComplex::*)(const vector<complex<double>> &)) &VecVecComplex::push_back)
        .def("back", (vector<complex<double>> &(VecVecComplex::*)()) &VecVecComplex::back)
        .def("__len__", [](const VecVecComplex &v) { return v.size(); })
        .def("__iter__", [](VecVecComplex &v) {
           return py::make_iterator(v.begin(), v.end());
        }, py::keep_alive<0, 1>());


    m.doc() = R"pbdoc(
        Pybind11 example plugin
        -----------------------
        .. currentmodule:: cmake_example
        .. autosummary::
           :toctree: _generate
    )pbdoc";

    m.def("genCryptoContextAndKeyGen", &genCryptoContextAndKeyGen, R"pbdoc(
        Add two numbers
    )pbdoc");


    m.def("encryption", &encryption, R"pbdoc(
        Encrypts a list of list containing model params
    )pbdoc");

    m.def("decryption", &decryption, R"pbdoc(
        Decrypts a list of list containing model params
    )pbdoc");



     m.def("computeWeightedAverage", &computeWeightedAverage, R"pbdoc(
        compute Weighted Average
    )pbdoc");


   

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}






