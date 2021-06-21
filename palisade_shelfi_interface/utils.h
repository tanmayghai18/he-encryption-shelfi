#include "palisade.h"
#include "cnpy.h"
#include "cnpy.cpp"
#include "ciphertext-ser.h"
#include "pubkeylp-ser.h"

#include "cryptocontext-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"

#include "cryptocontext-ser.h"
#include "scheme/ckks/ckks-ser.h"


using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

const std::string DATAFOLDER = "demoData";

/**
 * input: (int) number of learners to load from .npz format, (string) path to ith learner file
 * output: (vector<cnpy::npz_t>) vector of cnpy::npz_t objects to be read
 * assumes that all learner data is located under a common directory, with the ith file stored as
 * ../learners/learner_{i} and that learner data is in the form of a flattened array
 **/
vector<cnpy::npz_t> loadLearners(int numLearners, string learner_file) {
	vector<cnpy::npz_t> learners;
	for (int i = 0; i < numLearners; i++) {
		cout << "loading in learner " << i << endl;
		cnpy::npz_t l = cnpy::npz_load(learner_file + std::to_string(i) + ".npz");
		learners.push_back(l);
	}
	return learners;
}

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
	          depth, plaintextModulus, securityLevel, sigma, depth, OPTIMIZED, BV);

	    std::cout << "\nThe cryptocontext has been generated." << std::endl;

	} else if (scheme == "ckks") {
		usint multDepth = 2;
  		usint scaleFactorBits = 40;
  		usint batchSize = 8;

		cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          multDepth, scaleFactorBits, batchSize);
	}

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);
	cryptoContext->Enable(LEVELEDSHE);

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
 * input: (string) cryptoscheme to use, (vector<cnpy::npz_t>) learners, (vector<string>) arrays parameters to use per learner
 * encrypts all model weights and serializes them into a file titled `ciphertexts` in the `demoData` folder
 **/
void encryption(string scheme, vector<cnpy::npz_t> learners , vector<string> arrays) {
	vector<map<string, Plaintext>> maps;
	// Deserialize the crypto context
	CryptoContext<DCRTPoly> cc;
	if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
	                               SerType::BINARY)) {
	std::cerr << "I cannot read serialization from "
	          << DATAFOLDER + "/cryptocontext.txt" << std::endl;
	}
	std::cout << "The cryptocontext has been deserialized." << std::endl;

	LPPublicKey<DCRTPoly> pk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
	                              SerType::BINARY) == false) {
	std::cerr << "Could not read public key" << std::endl;
	}
	std::cout << "The public key has been deserialized." << std::endl;

	if (scheme == "bgvrns") {
		for (cnpy::npz_t learner : learners) {
    		map<string, Plaintext> mappings;

		    for (string idx : arrays) {
		      cnpy::NpyArray arr = learner[idx];

		      // cout << idx << ", " << arr.shape << endl;

		      float* loaded_data = arr.data<float>();

		      vector<float> curr;

		      for (int i = 0; i < arr.shape[0]; i++) {
		        curr.push_back(loaded_data[i]);
		      }

		      vector<int64_t> curr2;
		      for (int i = 0; i < curr.size(); i++) {
		        curr2[i] = (int64_t)curr[i];
		      }

		      Plaintext p = cc->MakePackedPlaintext(curr2);

		      mappings[idx] = p;
		    }
    	maps.push_back(mappings);
  		}
	} else {
		for (cnpy::npz_t learner : learners) {
		    map<string, Plaintext> mappings;

		    for (string idx : arrays) {
		      cnpy::NpyArray arr = learner[idx];

		      float* loaded_data = arr.data<float>();

		      vector<float> curr;

		      for (int i = 0; i < arr.shape[0]; i++) {
		        curr.push_back(loaded_data[i]);
		      }

		      vector<complex<double>> curr2(curr.begin(), curr.end());

		      Plaintext p = cc->MakeCKKSPackedPlaintext(curr2);
		      mappings[idx] = p;
		    }

		    maps.push_back(mappings);
		}

	}



  	map<int, vector<Ciphertext<DCRTPoly>>> ciphertexts;

	for (int i = 0; i < maps.size(); i++) {
		map<string, Plaintext> m = maps[i];
		map<string, Plaintext>::iterator it;

		vector<Ciphertext<DCRTPoly>> curr;

		for (it = m.begin(); it != m.end(); it++) {
		  Ciphertext<DCRTPoly> ciphertext = cc->Encrypt(pk, it->second);
		  curr.push_back(ciphertext);
		}
		ciphertexts[i] = curr;
	}

	if (!Serial::SerializeToFile(DATAFOLDER + "/ciphertexts.txt",
	                           ciphertexts, SerType::BINARY)) {
	std::cerr << "Error writing serialization of ciphertexts"
	          << std::endl;
	}
	std::cout << "The ciphertexts have been serialized." << std::endl;
}


/**
 * input: (string) scheme, (float) # of training samples, learners, arrays
 * computes private weighted average over all learner data and serializes it to `pwa.txt` in `demoData`
 **/
void computeWeightedAverage(string scheme, float training_samples, vector<cnpy::npz_t> learners, vector<string> arrays) {
	map<int, vector<Ciphertext<DCRTPoly>>> ciphertexts;
	if (!Serial::DeserializeFromFile(DATAFOLDER + "/ciphertexts.txt", ciphertexts,
	                               SerType::BINARY)) {
	std::cerr << "I cannot read serialization from "
	          << DATAFOLDER + "/ciphertexts.txt" << std::endl;
	}
	std::cout << "The ciphertexts have been deserialized." << std::endl;

	std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt",
	                   std::ios::in | std::ios::binary);

	CryptoContext<DCRTPoly> cc;
	if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
	                               SerType::BINARY)) {
	std::cerr << "I cannot read serialization from "
	          << DATAFOLDER + "/cryptocontext.txt" << std::endl;
	}
	std::cout << "The cryptocontext has been deserialized." << std::endl;

	LPPublicKey<DCRTPoly> pk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
	                              SerType::BINARY) == false) {
	std::cerr << "Could not read public key" << std::endl;
	}
	std::cout << "The public key has been deserialized." << std::endl;

	if (!emkeys.is_open()) {
	std::cerr << "I cannot read serialization from "
	          << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
	}
	if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
	std::cerr << "Could not deserialize the eval mult key file" << std::endl;

	}
	std::cout << "Deserialized the eval mult keys." << std::endl;



	long weight = training_samples / (learners.size() * training_samples);
	vector<int64_t> weights(training_samples);
  	std::fill(weights.begin(), weights.end(), weight);
  	auto pw = cc->MakePackedPlaintext(weights);

	vector<Ciphertext<DCRTPoly>> c0 = ciphertexts[0];
	auto pwa = cc->EvalMult(pw, c0[0]);

	if (scheme == "bgvrns") {

	    for (int i = 0; i < arrays.size(); i++) {
	        for (int j = 0; j < learners.size(); j++) {
	          if (i == 0 && j == 0) {
	        } else {
	        // cout << i << ", " << j << endl;
	        vector<Ciphertext<DCRTPoly>> c = ciphertexts[j];
	        cc->EvalAdd(pwa, cc->EvalMult(pw, c[i]));
	        }
	      }
	    } 

	} else {
  		for (int i = 0; i < arrays.size(); i++) {
    		for (int j = 0; j < learners.size(); j++) {
      			if (i == 0 && j == 0) {
      			} else {
        		//cout << i << ", " << j << endl;
        		vector<Ciphertext<DCRTPoly>> c = ciphertexts[j];
        		cc->EvalAdd(pwa, cc->EvalMult(c[i], weight));
      			}
    		}
  		}
	}

	if (!Serial::SerializeToFile(DATAFOLDER + "/pwa.txt",
	                           pwa, SerType::BINARY)) {
	std::cerr << "Error writing serialization of private weighted average"
	          << std::endl;
	}
	std::cout << "pwa been serialized." << std::endl;

}


/**
 * decrypts pwa
 **/
Plaintext decryption() {
	Ciphertext<DCRTPoly> pwa;

	CryptoContext<DCRTPoly> cc;
	if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cc,
	                               SerType::BINARY)) {
	std::cerr << "I cannot read serialization from "
	          << DATAFOLDER + "/cryptocontext.txt" << std::endl;
	}
	std::cout << "The cryptocontext has been deserialized." << std::endl;

	LPPrivateKey<DCRTPoly> sk;
	if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", sk,
	                              SerType::BINARY) == false) {
	std::cerr << "Could not read secret key" << std::endl;
	}
	std::cout << "The secret key has been deserialized." << std::endl;

	if (!Serial::DeserializeFromFile(DATAFOLDER + "/pwa.txt", pwa,
	                               SerType::BINARY)) {
	std::cerr << "I cannot read serialization from "
	          << DATAFOLDER + "/pwa.txt" << std::endl;
	}
	std::cout << "pwa has been deserialized." << std::endl;

	Plaintext decryptResult;
  	cc->Decrypt(sk, pwa, &decryptResult);

  	return decryptResult;
  	

}
