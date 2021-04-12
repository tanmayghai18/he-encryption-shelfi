#include "PublicKey.h"


PublicKey::PublicKey(std::string pairing_str, element_t P, element_t Q){


	pairing_init_set_str(map, pairing_str.c_str());


	element_init_same_as(this->P, P);
	element_init_same_as(this->Q, Q);

	element_set(this->P, P);
	element_set(this->Q, Q);

	//mpz_set(n, order);


}


/*mpz_t PublicKey::getN(){

	return this->n;
}*/


void PublicKey::doPairing(element_t& A, element_t& B, element_t& result){

	//can be updated to add preprocessing in case one of the operands is fixed


	pairing_pp_t pp;
	pairing_pp_init(pp, A, map); // x is some element of G1
	pairing_pp_apply(result, B, pp); // r1 = e(x, y1)
	
	pairing_pp_clear(pp); // don't need pp anymore


}



PublicKey::~PublicKey(){






}