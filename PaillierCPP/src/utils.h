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


const int modulusbits = 3072;
const int noOfParams = 1000000;
const int totalLearners = 5;

const int num_rep_bits = 32; //number of bits used to represent numbers
const int nums_to_pack = 64; //numbers packed in 1 plaintext


//std::string learner_params_folder = "enigma_dataset/learners_flattened/";
//std::string learner_params_files[totalLearners] = {"l1.npz", "l2.npz", "l3.npz", "l4.npz", "l5.npz", "l6.npz", "l7.npz", "l8.npz" };

const paillier_get_rand_t get_rand = &paillier_get_rand_devrandom;


paillier_plaintext_t** createParamsArray();
paillier_plaintext_t**  paramsArrayfromVector(std::vector<std::string> params);
void initializeLearners(paillier_plaintext_t*** learners_plaintext);

paillier_ciphertext_t** encryptParams(paillier_plaintext_t** plaintext_arr, int size, paillier_pubkey_t* public_key);
paillier_plaintext_t** decryptParams(paillier_ciphertext_t** ciphertext_arr, int size, paillier_pubkey_t* public_key, paillier_prvkey_t* private_key);
void calculate_homomorphic_sum(paillier_ciphertext_t** ciphertext_result, paillier_ciphertext_t*** ciphertext_arr, int size, int noOfLearners, paillier_pubkey_t* public_key);


std::vector<std::string> pack_params(const std::vector<unsigned int>& params);
std::vector<unsigned int> unpack_params(std::vector<std::string>& packed_params);