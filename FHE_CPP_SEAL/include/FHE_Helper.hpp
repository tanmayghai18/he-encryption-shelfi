#include <seal/seal.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <omp.h>


using namespace seal;
using namespace std;

class FHE_Helper{

    private:

      string scheme;
      uint batchSize;
      uint scaleFactorBits;
      std::string cryptodir;


      SEALContext* context;
      PublicKey public_key;
      SecretKey secret_key;


    public:

      FHE_Helper(string scheme, uint batchSize, uint scaleFactorBits, string cryptodir);

      int genCryptoContextAndKeys();
      void load_crypto_params();

      void encrypt(vector<double>& data_array, string& result); 
      void computeWeightedAverage(vector<string>& learners_Data, vector<float>& scalingFactors, string& result);
      void decrypt(string& learner_Data, unsigned long int data_dimesions, vector<double>& result);





};
