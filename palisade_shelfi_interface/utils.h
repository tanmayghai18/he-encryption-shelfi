#include "palisade.h"
#include "ciphertext-ser.h"
#include "pubkeylp-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include <string>

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

const std::string DATAFOLDER = "../CryptoParams";


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
		usint batchSize = 8192;

		// Instantiate the crypto context
		cryptoContext =
	      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
	          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV,
	          0, 0, 0, 0, 0,batchSize);

	    std::cout << "\nThe cryptocontext has been generated.\n" << std::endl;

	} else if (scheme == "ckks") {

		usint multDepth = 2;
  		usint scaleFactorBits = 40;
  		usint batchSize = 8192;

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
              return 1;
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
	return 1;
	}
	std::cout << "The public key has been serialized." << std::endl;

	// Serialize the secret key
	if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt",
	                           keyPair.secretKey, SerType::BINARY)) {
	std::cerr << "Error writing serialization of private key to key-private.txt"
	          << std::endl;
	return 1;
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
	  return 1;
	}
	std::cout << "The eval mult keys have been serialized." << std::endl;

	emkeyfile.close();
	} else {
	std::cerr << "Error serializing eval mult keys" << std::endl;
		return 1;
	}
	return 0;

}

/**
 * input: (string) cryptoscheme to use, (vector<vector<double>>) learner weights
 * encrypts all model weights and serializes them into a string
 **/

string encryption(string scheme, vector<vector<double>> learner_Data) {


	CryptoContext<DCRTPoly> cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
                                   SerType::BINARY)) {
    std::cerr << "Could not read serialization from "
              << DATAFOLDER + "/cryptocontext.txt" << std::endl;
    }

    LPPublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read public key" << std::endl;
    }


    vector<Ciphertext<DCRTPoly>> ciphertext_data;


    if (scheme == "ckks") {

    	for(int i=0; i<learner_Data.size(); i++){

	        vector<complex<double>> row(learner_Data[i].begin(), learner_Data[i].end());
	        Plaintext plaintext_data = cc->MakeCKKSPackedPlaintext(row);
	        ciphertext_data.push_back(cc->Encrypt(pk, plaintext_data));

    	}



    }
    else if(scheme == "bgvrns"){


    	/*for(int i=0; i<learner_Data.size(); i++){

	        vector<int> row(learner_Data[i].begin(), learner_Data[i].end());
	        Plaintext plaintext_data = cc->MakePackedPlaintext(row);
	        ciphertext_data.push_back(cc->Encrypt(pk, plaintext_data));

    	}*/



    }


    


    stringstream s;
    const SerType::SERBINARY st;
    Serial::Serialize(ciphertext_data, s, st);

    return s.str();

}


/**
 * input: (string) scheme, (vector<string>) learners_Data a vector of binary ciphertext of all learners,
 * (vector<float>) scalingFactors is a vector with scaling factor for each learner
 * computes private weighted average over all learner data returns binary ciphertext of result
 **/

string computeWeightedAverage(string scheme, vector<string> learners_Data, vector<float> scalingFactors) {

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



	for(int i=0; i<learners_Data.size(); i++){

		stringstream ss(learners_Data[i]);
		vector<Ciphertext<DCRTPoly>> learner_ciphertext;

		Serial::Deserialize(learner_ciphertext, ss, st);


		for(int j=0; j<learner_ciphertext.size(); j++){

			learner_ciphertext[j] = cc->EvalMult(learner_ciphertext[j], scalingFactors[i]);

		}


		if(result_ciphertext.size() == 0){

			result_ciphertext = learner_ciphertext;
		}

		else{

			for(int j=0; j<learner_ciphertext.size(); j++){

				result_ciphertext[j] = cc->EvalAdd(result_ciphertext[j], learner_ciphertext[j]);

			}

		}


	}


	stringstream ss;
    Serial::Serialize(result_ciphertext, ss, st);

    return ss.str();


}


/**
 * data_dimesions is a list containing number of parameters in each layer 
 **/
vector<vector<double>> decryption(string scheme, string learner_Data, vector<int> data_dimesions) {



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


	vector<vector<double>> result;



	for(int i=0; i<learner_ciphertext.size(); i++){

		Plaintext pt;
    	cc->Decrypt(sk, learner_ciphertext[i], &pt);

    	pt->SetLength(data_dimesions[i]);

    	//cout<<pt<<endl<<endl<<endl;

    	vector<complex<double>> layer_complex = pt->GetCKKSPackedValue();
    	

    	vector<double> layer_real;

    	for(int j=0; j<layer_complex.size(); j++){

    		layer_real.push_back(layer_complex[j].real());

    	}

    	result.push_back(layer_real);


	}


	return result;

    
  	

}
