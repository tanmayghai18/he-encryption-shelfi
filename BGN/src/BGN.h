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
#include <cstring>
#include "PublicKey.h"


extern "C" {
#include <pbc/pbc.h>
}


class BGN{

private:

	/*private PairingParameters param;
    private BigInteger r;
    private BigInteger q; //This is the private key.
    private BigInteger order;
    private SecureRandom rng;*/

    
  	bool pairingPresent;
  	std::string pbc_param;

  	mpz_t r;
  	mpz_t order;
  	mpz_t l;




  	void loadPairingParams(const char *paramFileName, const char *privateKeyFileName);



    

 




public:

	mpz_t q; //private key
	pairing_t pairing;

	BGN();

	void createA1Params(int bits, const char *paramFileName, const char *privateKeyFile);

	

	PublicKey* init(const char *paramFileName, const char *privateKeyFileName);

	void encrypt(PublicKey* PK, mpz_t& plaintxt, element_t& result);
	void decrypt(PublicKey* PK, mpz_t& secretKey, element_t& ciphertxt, mpz_t& result);
	void decryptMul(PublicKey* PK, mpz_t& secretKey, element_t& ciphertxt, mpz_t& result);

	//HE operations

	void add(PublicKey* PK, element_t& A, element_t& B, element_t& result);


	
	void multiply(PublicKey* PK, element_t& A, element_t& B, element_t& result);






};