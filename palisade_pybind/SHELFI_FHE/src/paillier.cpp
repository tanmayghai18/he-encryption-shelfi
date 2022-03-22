#include <pybind11/complex.h>
#include <pybind11/pybind11.h>
#include <pybind11/pytypes.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <omp.h>

#include "PaillierUtils.h"

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)
namespace py = pybind11;

class Paillier : public Scheme {

private:
	string scheme;
	int learners; 
	
	int modulus_bits;
	int num_bits;
	int precision_bits;
	string cryptodir;
	string randomnessdir;

	// PaillierUtils* pailler_utils = nullptr;

public:
	Paillier(string scheme, int learners, int modulus_bits, int num_bits, int precision_bits, string cryptodir, string randomnessdir) : Scheme(scheme, learners) {
		this->modulus_bits = modulus_bits;
		this->num_bits = num_bits;
		this->precision_bits = precision_bits;
		this->cryptodir = cryptodir;
		this->randomnessdir = randomnessdir;
	}

	// py::bytes genPaillierRandOffline( unsigned long int params, unsigned int iteration) {
	// 	string result = "";
	// 	paillier_utils->getEncryptedRandomness(this->randomnessdir, params, iteration, result);
	// 	return py::bytes(result);
	// }

	// py::bytes addPaillierRandOffline(py::list encrypted_rand_learners) {  
	//     string result;
	//     vector<string> data;
	//     data.reserve(encrypted_rand_learners.size());
	//     for (unsigned long int i = 0; i < encrypted_rand_learners.size(); i++) {
	//     	data.push_back(std::string(py::str(encrypted_rand_learners[i])));
	//     }

	//     paillier_utils->addEncryptedRandomness(data, result);
	//     return py::bytes(result);

 //  }


	// void loadCryptoParams() override {
	// 	if (paillier_utils == nullptr) {
	// 		paillier_utils = new PaillierUtils(totalLearners, cryptodir, modulus_bits, num_bits, precision_bits);
	// 	}
	// }

	// void genCryptoContextAndKeyGen() override {
	//  	if (paillier_utils == nullptr) {
	//  		paillier_utils = new PaillierUtils(totalLearners, cryptodir, modulus_bits, num_bits, precision_bits);
	//  	} 
	//  	paillier_utils->genKeys(this->cryptodir);
	//  	return 1;
	// }

	// py::bytes encrypt(py::array_t<double> data_array, unsigned int iteration) override {

	// 	unsigned long int size = data_array.size();
 //    	auto learner_Data = data_array.data();

 //    	vector<double> data;
 //      	data.reserve(size);

 //      	for (unsigned int i=0; i<size; i++) {
 //      		data.push_back(learner_Data[i]);
 //      	}

 //      	string enc_data;
 //      	paillier_utils->maskParams(data, this->randomnessdir, iteration, enc_data);
 //      	return py::bytes(enc_data);
	// }

	// py::array_t<double> decrypt(string learner_Data, unsigned long int data_dimesions, unsigned int iteration) override {
	// 	vector<double> dec_res;
	// 	paillier_utils->unmaskParams(learner_Data, data_dimesions, this->randomnessdir, iteration, dec_res);

	// 	auto result = py::array_t<double>(data_dimesions);
	// 	py::buffer_info buf3 = result.request();
	// 	double *ptr3 = static_cast<double *>(buf3.ptr);
	// 	for (unsigned long int j = 0; j < dec_res.size(); j++) {
	// 		ptr3[j] = dec_res[j];
	// 	}
	// 	return result;
	// }

	// py::bytes computeWeightedAverage(py::list learners_Data, py::list scalingFactors, int params) override {
	// 	if (learners_Data.size() != scalingFactors.size()) {
	// 		cout << "Error: learners_Data and scalingFactors size mismatch" << endl;
	// 		return "";
	// 	}

	// 	vector<float> scaling_factors;
	// 	vector<string> data;
	// 	//data.reserve(learners_Data.size());

	// 	for (unsigned long int i=0; i<scalingFactors.size(); i++){
	// 		float sc = py::float_(scalingFactors[i]);
	// 		scaling_factors.push_back(sc);
	// 	}


	// 	for (unsigned long int i = 0; i < learners_Data.size(); i++) {
	// 		data.push_back(std::string(py::str(learners_Data[i])) );
	// 	}

	// 	string result;
	// 	paillier_utils->sumMaskedParams(data, params, result);
	// 	return py::bytes(result);
	// }
};