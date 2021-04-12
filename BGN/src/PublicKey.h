#pragma once
#include <gmp.h>
extern "C" {
#include <pbc/pbc.h>
}
#include <iostream>


class PublicKey{


private:

	pairing_t map;
	
	//mpz_t n;



public:

	element_t P, Q;


	PublicKey(std::string pairing_str, element_t P, element_t Q);

	void doPairing(element_t& A, element_t& B, element_t& result);

	//mpz_t getN();


	~PublicKey();



};