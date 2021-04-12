#include "BGN.h"

BGN::BGN(){
	
}


void BGN::loadPairingParams(const char *paramFileName, const char *privateKeyFileName){

	FILE *sysParamFile = fopen(paramFileName, "r");
	if (sysParamFile == NULL) {
		std::cout<<"Can't open the parameter file " << paramFileName << "\n";
		return;
	}

	char s[8192];
	size_t count = fread(s, 1, 8192, *(FILE **) &sysParamFile);
	pairingPresent = false;	  

	if (count){
			if (!pairing_init_set_buf(pairing, s, count)){
				pairingPresent = true;
				pbc_param = std::string(s, count);
			}
		}

	//std::cout << s << std::endl;

	fclose(sysParamFile);

	std::istringstream iss(pbc_param);

	for (std::string line; std::getline(iss, line); )
	{

		/*if(line.at(0) == 'p'){

			std::string p_str = line.substr(2,std::string::npos);
			const char *cstr = p_str.c_str();
			mpz_set_str(p, cstr, 10);
		}*/


		if (line.at(0) == 'n'){

			std::string n_str = line.substr(2,std::string::npos);
			const char *cstr = n_str.c_str();
			mpz_set_str(order, cstr, 10);


		}
		else if(line.at(0) == 'l'){

			std::string l_str = line.substr(2,std::string::npos);
			const char *cstr = l_str.c_str();
			mpz_set_str(l, cstr, 10);

		}
	}



	//reading private key

	std::ifstream privateKeyFile(privateKeyFileName);

	std::string param_name, param_val;

	while (privateKeyFile >> param_name >> param_val)
	{
		if(param_name == "n0"){
			mpz_set_str(r, param_val.c_str(), 10);
		}
		else if(param_name == "n1"){

			mpz_set_str(q, param_val.c_str(), 10);
		}

	}


	privateKeyFile.close();
	
	//std::cout<<pbc_param<<std::endl;

}


PublicKey* BGN::init(const char *paramFileName, const char *privateKeyFileName){


	loadPairingParams(paramFileName, privateKeyFileName);
	
	element_t P, Q;
	element_init_G1(P, pairing);
	element_random(P);
	element_mul_mpz(P, P, l);

	element_init_G1(Q, pairing);
	element_set(Q, P);
	element_mul_mpz(Q, Q, r);


	PublicKey* PK = new PublicKey(pbc_param, P, Q);

	element_clear(P);
	element_clear(Q);


	return PK;

}


void BGN::createA1Params(int bits, const char *paramFileName, const char *privateKeyFileName){

	mpz_t p, q, N;

    mpz_init(p);
    mpz_init(q);
    mpz_init(N);

    FILE * paramFile;
    FILE * privateKeyFile;
    paramFile = fopen(paramFileName, "w");
	privateKeyFile = fopen(privateKeyFileName, "w");


    if (paramFile==NULL || privateKeyFile==NULL)
  	{
    	std::cout<<"Error opening files"<<std::endl;
    	return;
  	}

  	std::cout<<"Files created"<<std::endl;
    	

    pbc_mpz_randomb(p, bits);
    pbc_mpz_randomb(q, bits);

    mpz_nextprime(p, p);
    mpz_nextprime(q, q);
    mpz_mul(N, p, q);

    pbc_param_t param;
    pbc_param_init_a1_gen(param, N);
    pbc_param_out_str(paramFile, param); 


    //writing private key in file


	char * n0 = mpz_get_str(NULL, 10, p);
	std::string n0_str(n0); 
	n0_str = "n0 " + n0_str + "\n";

	fputs(n0_str.c_str(), privateKeyFile);

	char * n1 = mpz_get_str(NULL, 10, q);
	std::string n1_str(n1); 
	n1_str = "n1 " + n1_str + "\n";

	fputs(n1_str.c_str(), privateKeyFile);


	void (*freefunc)(void *, size_t);
	mp_get_memory_functions (NULL, NULL, &freefunc);
	freefunc(n0, strlen(n0) + 1);
	freefunc(n1, strlen(n1) + 1);


    fclose(paramFile);
    fclose(privateKeyFile);
    
    pbc_param_clear(param);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(N);

}


void BGN::encrypt(PublicKey* PK, mpz_t& plaintxt, element_t& result){


	mpz_t t;
	mpz_init(t);
	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);


	mpz_urandomm(t, rstate, order);

	element_t A, B, C;

	element_init_G1(A, pairing);
	element_init_G1(B, pairing);
	element_init_G1(C, pairing);

	element_set(A, PK->P);
	element_mul_mpz(A, A, plaintxt);


	element_set(B, PK->Q);
	element_mul_mpz(B, B, t);


	element_set(C, A);
	element_add(C, C, B);


	element_init_same_as(result, C);
	element_set(result, C);


	mpz_clear(t);
	element_clear(A);
	element_clear(B);
	element_clear(C);

}



void BGN::decrypt(PublicKey* PK, mpz_t& secretKey, element_t& ciphertxt, mpz_t& result){


	element_t T, K, aux;

	element_init_G1(T, pairing);
	element_init_G1(K, pairing);
	element_init_G1(aux, pairing);


	element_set(T, PK->P);
	element_mul_mpz(T, T, secretKey);


	element_set(K, ciphertxt);
	element_mul_mpz(K, K, secretKey);


	element_set(aux, T);

	//std::cout<<"inside"<<std::endl;

	//element_printf("%B\n", ciphertxt);



	mpz_init_set_str(result, "1", 10);

	while(element_cmp(aux, K) != 0){

		//std::cout<<"hee"<<std::endl;

		//This is a brute force implementation of finding the discrete logarithm.
        //Performance may be improved using algorithms such as Pollard's Kangaroo.

        element_add(aux, aux, T);
        mpz_add_ui (result, result, 1);

	}


	element_clear(T);
	element_clear(K);
	element_clear(aux);

}


void BGN::decryptMul(PublicKey* PK, mpz_t& secretKey, element_t& ciphertxt, mpz_t& result){


	element_t PSK, CSK, aux;

	element_init_GT(PSK, pairing);


	PK->doPairing(PK->P, PK->P, PSK);
	element_pow_mpz(PSK, PSK, secretKey);


	element_init_same_as(CSK, ciphertxt);
	element_set(CSK, ciphertxt);


	element_pow_mpz(CSK, CSK, secretKey);



	//gmp_printf("%s is an mpz %Zd\n", "here", secretKey);

	//element_printf("%B\n", res_pow);



	element_init_same_as(aux, PSK);
	element_set(aux, PSK);


	mpz_init_set_str(result, "1", 10);


	while(element_cmp(aux, CSK) != 0){


        element_mul(aux, aux, PSK);
        mpz_add_ui(result, result, 1);

	}


}



void BGN::add(PublicKey* PK, element_t& A, element_t& B, element_t& result){

	mpz_t t;
	mpz_init(t);
	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	mpz_urandomm(t, rstate, order);


	element_t aux, output;

	element_init_G1(output, pairing);
	element_init_G1(aux, pairing);

	element_set(aux, PK->Q);
	element_mul_mpz(aux, aux, t);

	element_set(output, A);
	element_add(output, output, B);
	element_add(output, output, aux);


	element_init_G1(result, pairing);
	element_set(result, output);


	mpz_clear(t);
	element_clear(aux);
	element_clear(output);


}




void BGN::multiply(PublicKey* PK, element_t& A, element_t& B, element_t& result){



	mpz_t t;
	mpz_init(t);
	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	mpz_urandomm(t, rstate, order);

	element_init_GT(result, pairing);
	PK->doPairing(A, B, result);


	element_t K;
	element_init_GT(K, pairing);
	PK->doPairing(PK->Q, PK->Q, K);

	element_pow_mpz(K, K, t);

	element_mul(result, result, K);


	mpz_clear(t);
	element_clear(K);


}




