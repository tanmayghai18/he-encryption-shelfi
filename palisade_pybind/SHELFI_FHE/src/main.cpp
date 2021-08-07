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

#include <pybind11/numpy.h>

using namespace std;
using namespace lbcrypto;
//using namespace std::chrono;


//CEREAL_REGISTER_TYPE(lbcrypto::CryptoContextImpl<lbcrypto::DCRTPoly>);

//lbcrypto::CryptoContextImpl<lbcrypto::DCRTPolyImpl

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)



namespace py = pybind11;




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






class FHE_Helper{

	private:

	const std::string DATAFOLDER = "CryptoParams";
	
	string scheme;
	usint batchSize;
	usint scaleFactorBits;

	CryptoContext<DCRTPoly> cc;
	LPPublicKey<DCRTPoly> pk;
	LPPrivateKey<DCRTPoly> sk;


	public:
	

	FHE_Helper(string scheme, usint batchSize, usint scaleFactorBits){
	
		this->scheme = scheme;
		this->batchSize = batchSize;
		this->scaleFactorBits = scaleFactorBits;
		
		
	}
	
	
	void load_cyrpto_params(){
	
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
		cryptoContext =
		  CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
		      depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV,
		      0, 0, 0, 0, 0,batchSize);

		std::cout << "\nThe cryptocontext has been generated.\n" << std::endl;

	    } else if (scheme == "ckks") {

		usint multDepth = 2;

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
	
	
	py::bytes encrypt(py::array_t<double> data_array) {


		auto size = data_array.size();

		auto learner_Data = data_array.data();


		//double elapsed_time = 0.0;


		vector<Ciphertext<DCRTPoly>> ciphertext_data((int)((size + batchSize) / batchSize));

		//ciphertext_data.reserve((int)((size + batchSize) / batchSize));



		if (scheme == "ckks") {


			if(size>(long unsigned int)batchSize){

			    int j=0;

			    for(long unsigned int i = 0; i < size; i += batchSize) {

					auto last = std::min((long)size, (long)i + batchSize);

					vector<double> batch;
					batch.reserve(last-i+1);

					for(long unsigned int j=i; j<last; j++){

						batch.push_back(learner_Data[j]);

					}


					//auto start = std::chrono::system_clock::now();
					 
					Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(batch);
					ciphertext_data[j++] = cc->Encrypt(pk, plaintext_data);
					
					//auto end = std::chrono::system_clock::now();
					
					//elapsed_time+=std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
					

					batch.clear();


			    }

			}

			else{

				vector<double> batch;

				batch.reserve(size);

				for(long unsigned int i = 0; i < size; i++) {

					//float dat = py::float_(learner_Data[i]);
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
		// elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		//std::cout <<"Encryption: "<< elapsed_time << " milliseconds"<<'\n';




		//auto start = std::chrono::system_clock::now();

		stringstream s;
		const SerType::SERBINARY st;
		Serial::Serialize(ciphertext_data, s, st);

		//ciphertext_data.clear();

		py::bytes res(s.str());


		//auto end = std::chrono::system_clock::now();
		//auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		//std::cout <<"Serialization: "<< elapsed.count() << " milliseconds"<<'\n';


		return res;


	}


	py::bytes computeWeightedAverage(py::list learners_Data, py::list scalingFactors) {


	    if(scheme!= "ckks"){
	        std::cout<<"Not supported!"<<std::endl;
	    }


	    if(learners_Data.size() != scalingFactors.size()){
	        cout<<"Error: learners_Data and scalingFactors size mismatch"<<endl;
	        return "";
	    }


	    const SerType::SERBINARY st;

	    vector<Ciphertext<DCRTPoly>> result_ciphertext;



	     for(unsigned long int i=0; i<learners_Data.size(); i++){

	     	string dat = std::string(py::str(learners_Data[i]));

	        stringstream ss(dat);
	        vector<Ciphertext<DCRTPoly>> learner_ciphertext;

	        Serial::Deserialize(learner_ciphertext, ss, st);


	        for(unsigned long int j=0; j<learner_ciphertext.size(); j++){

	            float sc = py::float_(scalingFactors[i]);

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

	        learner_ciphertext.clear();


	    }


	    stringstream ss;
	    Serial::Serialize(result_ciphertext, ss, st);

	    result_ciphertext.clear();

	    return py::bytes(ss.str());


	}



	py::array_t<double> decrypt(string learner_Data, unsigned long int data_dimesions) {


	    const SerType::SERBINARY st;
	    stringstream ss(learner_Data);
	    
	    vector<Ciphertext<DCRTPoly>> learner_ciphertext;
	    Serial::Deserialize(learner_ciphertext, ss, st);


	    //py::array_t<double> result(data_dimesions);

	    auto result = py::array_t<double>(data_dimesions);

	    py::buffer_info buf3 = result.request();

	    double *ptr3 = static_cast<double *>(buf3.ptr);

	    //result.reserve(data_dimesions);

	    size_t m = 0;


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

	        vector<double> layer_data = pt->GetRealPackedValue();

	        for(int j=0; j<layer_data.size(); j++){

	        	ptr3[m++] =  layer_data[j];

	        }

	        //cout<<endl;


	        //result.insert(result.end(), layer_data.begin(), layer_data.end());

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
        .def("decrypt", &FHE_Helper::decrypt)
        .def("computeWeightedAverage", &FHE_Helper::computeWeightedAverage)
        .def("genCryptoContextAndKeyGen", &FHE_Helper::genCryptoContextAndKeyGen);

	

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
        .def("clear", &StringList::clear)
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
        .def("clear", &VecVecDouble::clear)
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
        .def("clear", &VecVecComplex::clear)

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

    /*m.def("genCryptoContextAndKeyGen", &genCryptoContextAndKeyGen, R"pbdoc(
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
*/

   

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}






