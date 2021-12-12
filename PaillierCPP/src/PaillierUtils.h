#pragma once

#include "gmp.h"
#include "paillier.h"
#include <string>
#include <sstream>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <bitset>
#include <math.h> 
#include <sstream>
#include <limits.h>
#include <vector>
#include <stdio.h>
#include <string.h>

#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include <cryptopp/rdrand.h>

//using namespace CryptoPP;
using namespace std;


class PaillierUtils{

private:

	int modulusbits;
	int num_rep_bits;
	int precision_bits;

	int totalLearners;

	const paillier_get_rand_t get_rand = &paillier_get_rand_devrandom;

	paillier_pubkey_t* public_key;
	paillier_prvkey_t* private_key; 

	void scaleUpParams(const vector<double>& params, vector<unsigned long int>& scaled_params);
	void scaleDownParams(vector<unsigned long int>& scaled_params, vector<double>& params);
	void clip(std::vector<unsigned long int>& params, unsigned long int threshold);
	void pack_params(const std::vector<unsigned long int>& params, std::vector<std::string>& packed_params);
	void unpack_params(std::vector<std::string>& packed_params, std::vector<unsigned long int>& params);

	void load_keys(string keys_path);




public:

	void genKeys(string keys_path);

	PaillierUtils(int learners, string keys_path = "", int mod_bits = 2048, int num_bits = 17, int prec_bits = 13){

		totalLearners = learners;
		modulusbits = mod_bits;
		num_rep_bits = num_bits;
		precision_bits = prec_bits;

		load_keys(keys_path);

	}

	string encryptParams(const std::vector<double>& params);
	std::vector<double> decryptParams(string ciphertext_arr, int params);
	string calculate_homomorphic_sum(std::vector<string>& learner_params);



};
