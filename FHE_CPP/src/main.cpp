#include "FHE_Helper.hpp"


void generateRandomData(vector<double>& learner_Data, int rows){

    double lower_bound = 0;
    double upper_bound = 100;

    std::uniform_real_distribution<double> unif(lower_bound,upper_bound);
    std::default_random_engine re;

    for(int i=0; i<rows; i++){

        learner_Data.push_back(unif(re));

    }


}


int main() {

    string cryptodir = "../CryptoParams/";
	string scheme = "ckks";
    usint batchsize = 8192;
    usint scalingfactorbits = 52;

    FHE_Helper fhe_helper(scheme, batchsize, scalingfactorbits, cryptodir);
    //fhe_helper.genCryptoContextAndKeys();
    fhe_helper.load_crypto_params();


    //geneting random data for testing.
    vector<double> learner_Data;
    generateRandomData(learner_Data, 100000);

    cout<<"Learner Data: "<<endl;
    cout<<learner_Data<<endl<<endl<<endl;

    cout<<"Encrypting"<<endl;

    string enc_result = fhe_helper.encrypt(learner_Data);


    vector<string> learners_Data;

    
    learners_Data.push_back(enc_result);
    learners_Data.push_back(enc_result);
    learners_Data.push_back(enc_result);

    vector<float> scalingFactors;

    scalingFactors.push_back(0.5);
    scalingFactors.push_back(0.3);
    scalingFactors.push_back(0.5);

    cout<<"Computing 0.5*L + 0.3*L + 0.5*L"<<endl;


    string pwa_result = fhe_helper.computeWeightedAverage(learners_Data, scalingFactors);

    unsigned long int data_dimensions = learner_Data.size();

    cout<<"Decrypting"<<endl;

    vector<double> pwa_res_pt = fhe_helper.decrypt(pwa_result, data_dimensions);


    cout<<"Result:"<<endl;

    cout<<pwa_res_pt<<endl<<endl<<endl<<endl;




}