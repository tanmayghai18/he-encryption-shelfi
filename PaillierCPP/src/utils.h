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

using namespace std;


extern int modulusbits;
extern int num_rep_bits;
extern int precision_bits;

extern int noOfParams;
extern int totalLearners;




//const int noOfParams = 1000;
//const int totalLearners = 5;

//number of bits used to represent numbers
// 13 bits for precision, 3 bits for range, 1 bit for sign
//const int num_rep_bits = 17; 
//const int precision_bits = 13;
//const int nums_to_pack = 64; //numbers packed in 1 plaintext

//const int pad_zeros = totalLearners - 1;


void init_params(int learners, int mod_bits = 2048, int num_bits = 17, int prec_bits = 13);


const paillier_get_rand_t get_rand = &paillier_get_rand_devrandom;

void scaleUpParams(const vector<double>& params, vector<unsigned long int>& scaled_params);
void scaleDownParams(vector<unsigned long int>& scaled_params, vector<double>& params);
void clip(std::vector<unsigned long int>& params, unsigned long int threshold);
void pack_params(const std::vector<unsigned long int>& params, std::vector<std::string>& packed_params);
void unpack_params(std::vector<std::string>& packed_params, std::vector<unsigned long int>& params);


string encryptParams(const std::vector<double>& params, paillier_pubkey_t* public_key);
std::vector<double> decryptParams(string ciphertext_arr, paillier_pubkey_t* public_key, paillier_prvkey_t* private_key, int params);
string calculate_homomorphic_sum(std::vector<string>& learner_params, paillier_pubkey_t* public_key, paillier_prvkey_t* private_key);
