#include "utils.h"

#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
#include <cryptopp/rdrand.h>
using namespace CryptoPP;


int modulusbits;
int num_rep_bits;
int precision_bits;

int noOfParams;
int totalLearners;



void init_params(int learners, int mod_bits, int num_bits, int prec_bits){

	modulusbits = mod_bits;
	num_rep_bits = num_bits;
	precision_bits = prec_bits;
	
	totalLearners = learners;
	

}



void scaleUpParams(const vector<double>& params, vector<unsigned long int>& scaled_params){

	unsigned long int scale = pow(2, precision_bits);
	unsigned long int threshold = pow(2,num_rep_bits-1); 

	scaled_params.reserve(params.size());


	//scale up to keep precision bits
	for(int i=0; i<params.size(); i++){

		scaled_params.push_back((unsigned long int) (params[i] * scale) );

	}


	clip(scaled_params, threshold);


	for(int i=0; i<params.size(); i++){

		//changes all numbers to positive in the range 0-2^(num_rep_bits) - 1
		scaled_params[i] = scaled_params[i]+threshold;

	}


}


void scaleDownParams(vector<unsigned long int>& scaled_params, vector<double>& params){

	params.reserve(scaled_params.size());

	double threshold = pow(2,num_rep_bits-1);
	double scale = pow(2, precision_bits);


	for(int i=0; i<scaled_params.size(); i++){

		params.push_back(scaled_params[i]);

		params[i] = (params[i] - (totalLearners*threshold))/scale;


	}


}



void pack_params(const std::vector<unsigned long int>& params, std::vector<std::string>& packed_params){


	int pad_zeros = totalLearners - 1;

	

	const unsigned int params_size =  params.size();

	int bytes_to_rep_num = PAILLIER_BITS_TO_BYTES(num_rep_bits); 

	//determining how many zero bytes to pad to account for overflow during sum
	int extra_padding_bits = pad_zeros - ((bytes_to_rep_num*8) - num_rep_bits);
	int extra_bytes_to_pad = 0;
	if(extra_padding_bits > 0){

		extra_bytes_to_pad = PAILLIER_BITS_TO_BYTES(extra_padding_bits);
	} 


	int total_size_num = bytes_to_rep_num + extra_bytes_to_pad;
	int nums_to_pack = (modulusbits/8)/total_size_num;
	int packed_params_size = ceil((float)params_size/(float)nums_to_pack);
	packed_params.resize(packed_params_size, "");


	int count_params = 0;

	//starting byte index to copy the number from
	int num_start_byte = bytes_to_rep_num -1;
	if(num_start_byte> sizeof(unsigned long int)-1){
		cout<<"Error: Number representation greater than unsigned long int."<<endl;
		return;
	}

	unsigned long int zero_rep = 0;
	char* num_ptr;


	for(int i=0; i<packed_params_size; i++){

		packed_params[i].reserve(modulusbits/8);

		for(int j=0; j<nums_to_pack; j++){


			for(int k=0; k<extra_bytes_to_pad; k++){

				packed_params[i]+= (char) 0;
				
			}


			if(count_params<params.size()){

				num_ptr = (char*)& params[count_params++];

			}
			else{

				num_ptr = (char*)& zero_rep;
			}


			int start_index = num_start_byte;

			while(start_index>=0){

				packed_params[i]+= num_ptr[start_index--];
			}


		}


	}


}


void unpack_params(std::vector<std::string>& packed_params, std::vector<unsigned long int>& params){


	int pad_zeros = totalLearners - 1;


	int packed_params_size = packed_params.size();

	int bytes_to_rep_num = PAILLIER_BITS_TO_BYTES(num_rep_bits); 


	//determining how many zero bytes to pad to account for overflow during sum
	int extra_padding_bits = pad_zeros - ((bytes_to_rep_num*8) - num_rep_bits);
	int extra_bytes_to_pad = 0;
	if(extra_padding_bits > 0){

		extra_bytes_to_pad = PAILLIER_BITS_TO_BYTES(extra_padding_bits);
	} 

	int total_size_num = bytes_to_rep_num + extra_bytes_to_pad;

	if(total_size_num > sizeof(unsigned long int)){
		cout<<"Error: Number representation greater than unsigned long int."<<endl;
		return;
	}


	params.reserve(noOfParams);


	for(int i=0; i<packed_params_size; i++){

		for(int j=0; j<packed_params[i].size(); j+=total_size_num){

			if(j+total_size_num > packed_params[i].size()){

				break;
			}

			unsigned int long num = 0;
			char* a_ptr = (char*)& num;


			for(int k=0; k<total_size_num; k++)
			{

				a_ptr[total_size_num-1-k] = packed_params[i][j+k];

			}

			params.push_back(num);

			
		}


	}


}




void clip(std::vector<unsigned long int>& params, unsigned long int threshold){

	int param_size = params.size();
	//2^63
	unsigned long int negativeNumCheck = 9223372036854775808U;

	for(int i=0; i<param_size; i++){

		//if number is negative and ..

		if(((params[i] & negativeNumCheck) != 0) &&  (params[i] < ((unsigned long int) (-1*threshold)))   ){

			params[i] = (unsigned long int) (-1*threshold);

		}

		//if number is positive and ..

		else if( ((params[i] & negativeNumCheck) == 0)  &&  (params[i] > (threshold-1)) ){

			params[i] = threshold-1;

		}

	}


}



string encryptParams(const std::vector<double>& params, paillier_pubkey_t* public_key){

	
	vector<unsigned long int> scaled_params;
	vector<string> packed_params;


	scaleUpParams(params, scaled_params);
	pack_params(scaled_params, packed_params);

	scaled_params.clear();



	string result="";
	result.reserve(PAILLIER_BITS_TO_BYTES(public_key->bits) * 2 * packed_params.size());


	//#pragma omp parallel for
	for(int i=0; i<packed_params.size(); i++){


		RDRAND prng;

		//void* buf;

		//GenerateBlock((byte*) buf, public_key->bits/8 + 1);


		paillier_plaintext_t* pt1 = paillier_plaintext_from_bytes((void*)packed_params[i].c_str(), PAILLIER_BITS_TO_BYTES(public_key->bits));
		paillier_ciphertext_t* ct1 = paillier_enc(NULL, public_key, pt1, get_rand);


		//debugging /////////////////////////////////////////////////


		/*char* print_bytes = (char*) paillier_plaintext_to_bytes( PAILLIER_BITS_TO_BYTES(public_key->bits), pt1);

		for(int j=0; j<PAILLIER_BITS_TO_BYTES(public_key->bits); j++){

			std::bitset<8> b(print_bytes[j]);
			cout<<b; 
		}

		cout<<endl;*/


		//debugging ///////////////////////////////////////////////////





	    char* byteCt1 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(public_key->bits)*2, ct1);

	    result.append(byteCt1, PAILLIER_BITS_TO_BYTES(public_key->bits)*2);

    	paillier_freeplaintext(pt1);
    	paillier_freeciphertext(ct1);
    	free(byteCt1);


	}



	return result;

}


std::vector<double> decryptParams(string ciphertext_arr, paillier_pubkey_t* public_key, paillier_prvkey_t* private_key, int total_params){


	noOfParams = total_params;


	const char* ct_arr = ciphertext_arr.c_str();

	vector<string> packed_params;

	packed_params.reserve(ciphertext_arr.size()/(PAILLIER_BITS_TO_BYTES(public_key->bits*2)));


	//#pragma omp parallel for
	for(int i=0; i<ciphertext_arr.size(); i+=(PAILLIER_BITS_TO_BYTES(public_key->bits))*2){



	    paillier_ciphertext_t* ct1 = paillier_ciphertext_from_bytes((void*)(ct_arr+i), PAILLIER_BITS_TO_BYTES(public_key->bits)*2);

    	paillier_plaintext_t* dec_pt = paillier_dec(NULL, public_key, private_key, ct1); 

		char* res_plain_ans = (char*) paillier_plaintext_to_bytes( PAILLIER_BITS_TO_BYTES(public_key->bits), dec_pt );


		/*cout<<"Dec"<<endl;



			for(int j=0; j<PAILLIER_BITS_TO_BYTES(public_key->bits); j++){

				std::bitset<8> b(res_plain_ans[j]);
				cout<<b; 
			}

			cout<<endl;*/



		packed_params.push_back(string(res_plain_ans, PAILLIER_BITS_TO_BYTES(public_key->bits)));

		paillier_freeplaintext(dec_pt);
    	paillier_freeciphertext(ct1);
    	free(res_plain_ans);

	}

	std::vector<unsigned long int> params;
	std::vector<double> result_params;


	unpack_params(packed_params,  params);
	scaleDownParams(params, result_params);


	return result_params;


}


string calculate_homomorphic_sum(std::vector<string>& learner_params, paillier_pubkey_t* public_key, paillier_prvkey_t* private_key){

	string result;
	result.resize(learner_params[0].size());
	//const char* result_str = result.c_str();

	//cout<<"Inside HE SUM"<<endl;



	#pragma omp parallel for 
	for(int i=0; i<learner_params[0].size(); i+= (PAILLIER_BITS_TO_BYTES(public_key->bits*2))){


		//paillier_ciphertext_t* encrypted_sum = paillier_create_enc_zero();


		const char* L1 = learner_params[0].c_str();
	    paillier_ciphertext_t* ct1 = paillier_ciphertext_from_bytes((void*)(L1+i), PAILLIER_BITS_TO_BYTES(public_key->bits)*2);


		for(int j=1; j<learner_params.size(); j++){

			const char* Ln = learner_params[j].c_str();
	    	paillier_ciphertext_t* ctn = paillier_ciphertext_from_bytes((void*)(Ln+i), PAILLIER_BITS_TO_BYTES(public_key->bits)*2);
			paillier_mul(public_key, ct1, ct1, ctn);


			//debugging /////////////////////////////////////////////////

			/*cout<<"CN"<<endl;
	    	paillier_plaintext_t* dec_pt = paillier_dec(NULL, public_key, private_key, ctn); 

			char* print_bytes = (char*) paillier_plaintext_to_bytes( PAILLIER_BITS_TO_BYTES(public_key->bits), dec_pt);

			for(int j=0; j<PAILLIER_BITS_TO_BYTES(public_key->bits); j++){

				std::bitset<8> b(print_bytes[j]);
				cout<<b; 
			}

			cout<<endl;*/

			/*cout<<"SUM"<<endl;

			paillier_plaintext_t* dec_pt1 = paillier_dec(NULL, public_key, private_key, encrypted_sum); 

			char* print_bytess = (char*) paillier_plaintext_to_bytes( PAILLIER_BITS_TO_BYTES(public_key->bits), dec_pt1);

			for(int k=0; k<PAILLIER_BITS_TO_BYTES(public_key->bits); k++){

				std::bitset<8> b(print_bytess[k]);
				cout<<b; 
			}

			cout<<endl;*/




			//debugging /////////////////////////////////////////////////


			paillier_freeciphertext(ctn);

		}

	    char* byteCt = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(public_key->bits)*2, ct1);


	    /*cout<<"CT bytes"<<endl;

	    for(int k=0; k<PAILLIER_BITS_TO_BYTES(public_key->bits)*2; k++){

			std::bitset<8> b(byteCt[k]);
				cout<<b; 

		}

		cout<<endl;*/

		/*cout<<"Sum bytes"<<endl;

    	paillier_ciphertext_t* ctn = paillier_ciphertext_from_bytes((void*)(byteCt), PAILLIER_BITS_TO_BYTES(public_key->bits)*2);
	    paillier_plaintext_t* dec_pt1 = paillier_dec(NULL, public_key, private_key, ctn); 

		char* print_bytess = (char*) paillier_plaintext_to_bytes( PAILLIER_BITS_TO_BYTES(public_key->bits), dec_pt1);

		for(int k=0; k<PAILLIER_BITS_TO_BYTES(public_key->bits); k++){

			std::bitset<8> b(print_bytess[k]);
			cout<<b; 
		}

		cout<<endl;*/





		int count_ct=0;


		for(int k =i; k<i+PAILLIER_BITS_TO_BYTES(public_key->bits)*2; k++){


			result[k] = byteCt[count_ct++];
		}



		//strncpy((char*)(result_str + i), byteCt, PAILLIER_BITS_TO_BYTES(public_key->bits)*2 );


		/*cout<<"String"<<endl;

		for(int k=0; k<result.size(); k++){

			std::bitset<8> b(result[k]);
				cout<<b; 

		}

		cout<<endl;*/


		paillier_freeciphertext(ct1);
		free(byteCt);

	}


	return result;

}




