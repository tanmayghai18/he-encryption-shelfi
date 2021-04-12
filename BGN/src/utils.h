#pragma once

#include "gmp.h"
#include <string>
#include <sstream>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <bitset>
#include <math.h> 
#include <limits.h>
#include <vector>
#include <fstream>

#include "BGN.h"
#include "PublicKey.h"


extern "C" {
#include <pbc/pbc.h>
}



const int securityBits = 256;
const int noOfParams = 100;
const int totalLearners = 5;


const int num_rep_bits = 32; //number of bits used to represent numbers
const int nums_to_pack = 64; //numbers packed in 1 plaintext



mpz_t* paramsArrayfromVector(std::vector<std::string> params);
mpz_t* paramsArrayfromVector(std::vector<unsigned int> params);

element_t* encryptParams(mpz_t* plaintext_arr, int size, BGN* b, PublicKey* PK);

mpz_t* decryptParams(element_t* ciphertext_arr, int size, BGN* b, PublicKey* PK);
mpz_t* decryptParamsMul(element_t* ciphertext_arr, int size, BGN* b, PublicKey* PK);


void calculate_homomorphic_sum(element_t* ciphertext_result, element_t** ciphertext_arr, int size, int noOfLearners, BGN* b, PublicKey* PK);
void calculate_homomorphic_multiplication(element_t* ciphertext_result, element_t** ciphertext_arr, element_t** scaling_factors, int size, int noOfLearners, BGN* b, PublicKey* PK);

//void calculate_weighted_average(element_t* ciphertext_result, element_t** ciphertext_arr, element_t** scaling_factors, int size, int noOfLearners, BGN* b, PublicKey* PK);







std::vector<std::string> pack_params(const std::vector<unsigned int>& params);
std::vector<unsigned int> unpack_params(std::vector<std::string>& packed_params);


