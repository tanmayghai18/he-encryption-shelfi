#include "FHE_Helper.hpp"

FHE_Helper::FHE_Helper(string scheme, uint batchSize, uint scaleFactorBits, string cryptodir) {

    this->scheme = scheme;
    this->batchSize = batchSize;
    this->scaleFactorBits = scaleFactorBits;
    this->cryptodir = cryptodir;
}



void FHE_Helper::load_crypto_params() {


	if (scheme == "ckks") {

		EncryptionParameters parms;

		std::ifstream file( cryptodir + "cryptocontext.txt" );
		if(file){
			parms.load(file);
			file.close();
		}
		else{
			std::cout << "Could not read cryptocontext"<< std::endl;
			return;
		}

		this->context = new SEALContext(parms);


		std::ifstream file_sk( cryptodir + "key-private.txt" );
		if(file_sk){
			secret_key.load(*(this->context), file_sk);
			file_sk.close();
		}
		else{
			std::cout << "Could not read key-private"<< std::endl;
		}

		std::ifstream file_pk( cryptodir + "key-public.txt" );
		if(file_pk){
			public_key.load(*(this->context), file_pk);
			file_pk.close();
		}
		else{
			std::cout << "Could not read key-public"<< std::endl;
		}
		
	}


}


int FHE_Helper::genCryptoContextAndKeys() {



    if (scheme == "ckks") {

    	EncryptionParameters parms(scheme_type::ckks);
    	size_t poly_modulus_degree = batchSize*2;
    	parms.set_poly_modulus_degree(poly_modulus_degree);
    	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 60 }));

    	this->context = new SEALContext(parms);
    	KeyGenerator keygen(*(this->context));
    	this->secret_key = keygen.secret_key();
    	keygen.create_public_key(this->public_key);


    	std::ofstream outFile;
    	outFile.open(cryptodir + "cryptocontext.txt");
    	parms.save(outFile);
		outFile.close();


		std::ofstream outFile_secret_key;
    	outFile_secret_key.open(cryptodir + "key-private.txt");
    	this->secret_key.save(outFile_secret_key);
		outFile_secret_key.close();


		std::ofstream outFile_public_key;
    	outFile_public_key.open(cryptodir + "key-public.txt");
    	this->public_key.save(outFile_public_key);
		outFile_public_key.close();


		return 1;

      
    }

   
    return 0;
    

}


void FHE_Helper::encrypt(vector<double>& learner_Data, vector<string>& result) {


	double scale = pow(2.0, scaleFactorBits);

	unsigned long int size = learner_Data.size();


	result.resize((int)((size + batchSize) / batchSize));


    //vector<Ciphertext> ciphertext_data((int)((size + batchSize) / batchSize));

    if(scheme == "ckks"){

      if (size > (unsigned long int)batchSize) {


          #pragma omp parallel for
          for (unsigned long int i = 0; i < size; i += batchSize) {
          

            unsigned long int last = std::min((long)size, (long)i + batchSize);

            vector<double> batch;
            batch.reserve(last - i + 1);

            for (unsigned long int j = i; j < last; j++) {

              batch.push_back(learner_Data[j]);
            }

            CKKSEncoder encoder(*(this->context));
            Plaintext plaintext_data;
            encoder.encode(batch, scale, plaintext_data);

            Ciphertext ciphertext_data;
            Encryptor encryptor(*(this->context), this->public_key);
            encryptor.encrypt(plaintext_data, ciphertext_data);

            stringstream enc_data;
            ciphertext_data.save(enc_data);
            result[i/batchSize] = enc_data.str();


          }

        }

        else {

			vector<double> batch;
			batch.reserve(size);

			for (unsigned long int i = 0; i < size; i++) {

			batch.push_back(learner_Data[i]);
			}


			CKKSEncoder encoder(*(this->context));
			Plaintext plaintext_data;
			encoder.encode(batch, scale, plaintext_data);

			Ciphertext ciphertext_data;
			Encryptor encryptor(*(this->context), this->public_key);
			encryptor.encrypt(plaintext_data, ciphertext_data);

			stringstream enc_data;
            ciphertext_data.save(enc_data);
            result[0] = enc_data.str();


        }



    }

    else{

      std::cout << "Not supported!" << std::endl;
      

    }


   
}


void FHE_Helper::computeWeightedAverage(vector<vector<string>>& learners_Data, vector<float>& scalingFactors, vector<string>& result){


  if (learners_Data.size() != scalingFactors.size()) {
      cout << "Error: learners_Data and scalingFactors size mismatch" << endl;
      
  }

  if(scheme == "ckks"){

  	Evaluator evaluator(*(this->context));
  	CKKSEncoder encoder(*(this->context));
  	double scale = pow(2.0, scaleFactorBits);

    vector<Ciphertext> result_ciphertext;

    for (unsigned int i = 0; i < learners_Data.size(); i++) {

    	Plaintext plain_sc;
    	float sc = scalingFactors[i];
		encoder.encode(sc, scale, plain_sc);

    	vector<Ciphertext> learner_ciphertext;
    	for(unsigned int j = 0; j < learners_Data[i].size(); j++){

    		stringstream stream(learners_Data[i][j]);
    		Ciphertext cipher_data;
    		cipher_data.load(*(this->context), stream);

    		Ciphertext res;

    		evaluator.multiply_plain(cipher_data, plain_sc, res);

    		learner_ciphertext.push_back(res);

    	}


		if (result_ciphertext.size() == 0) {

			result_ciphertext = learner_ciphertext;
		}

		else {

			for (unsigned int j = 0; j < learner_ciphertext.size(); j++) {

				evaluator.add_inplace(result_ciphertext[j], learner_ciphertext[j]);

			}
		}


	}


	result.resize(learners_Data[0].size());
	for(unsigned int i=0; i<result.size(); i++){

		stringstream ss;
		result_ciphertext[i].save(ss); 
        result[i] = ss.str();

	}

  }

  else {

    std::cout << "Not supported!" << std::endl;

  }


    
}



void FHE_Helper::decrypt(vector<string>& learner_Data, unsigned long int data_dimesions, vector<double>& result){

	result.resize(batchSize*learner_Data.size());


	#pragma omp parallel for
	for(unsigned int i =0; i<learner_Data.size(); i++){

		Ciphertext cipher_data;
		Plaintext plain_data;
		stringstream stream(learner_Data[i]);
		Decryptor decryptor(*(this->context), this->secret_key);
		CKKSEncoder encoder(*(this->context));
		vector<double> res_dec;

		cipher_data.load(*(this->context), stream);
		decryptor.decrypt(cipher_data, plain_data);
		encoder.decode(plain_data, res_dec);


		for(unsigned int j=0; j<res_dec.size(); j++){

			result[i*batchSize + j]= res_dec[j];
		}


	}


	result.resize(data_dimesions);



}
