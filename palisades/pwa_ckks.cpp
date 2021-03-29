
#include "palisade.h"
#include <iostream>
#include <fstream>
#include <map>
#include <time.h>
#include <stdlib.h>
#include "csvstream.h"
#include "../cnpy.h"
#include "pwa_utils.h"
#include <sstream>
#include <chrono>

using namespace std;
using namespace lbcrypto;
using namespace std::chrono;

int main() {

  usint init_size = 4;
  usint dcrtBits = 40;
  usint batchSize = 4096;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          init_size - 1, dcrtBits, batchSize, HEStd_128_classic,
          0,                    /*ringDimension*/
          EXACTRESCALE, BV, 2, /*numLargeDigits*/
          2,                    /*maxDepth*/
          60,                   /*firstMod*/
          5, OPTIMIZED);

  // enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> kp1;

  LPKeyPair<DCRTPoly> kpMultiparty;

  kp1 = cc->KeyGen();
  cc->EvalMultKeyGen(kp1.secretKey);

  int numLearners = 10;
  float training_samples = 1000;

  cout << "Benchmarking CKKS.." << endl;

  vector<cnpy::npz_t> learners = loadLearners(numLearners);
  vector<map<string, Plaintext>> maps;
  //{"arr_0",  "arr_1",  "arr_2",  "arr_3", "arr_4",
  //      "arr_5",  "arr_6",  "arr_7",  "arr_8", "arr_9",
  //      "arr_10", "arr_11", "arr_12", "arr_13"}
  vector<string> arrays = {"arr_0",  "arr_1",  "arr_2",  "arr_3", "arr_4",
                           "arr_5",  "arr_6"}; //determines how many parameters


  for (cnpy::npz_t learner : learners) {
    map<string, Plaintext> mappings;

    for (string idx : arrays) {
      cnpy::NpyArray arr = learner[idx];

      float* loaded_data = arr.data<float>();

      vector<float> curr;

      for (int i = 0; i < arr.shape[0]; i++) {
        curr.push_back(loaded_data[i]);
      }

      vector<complex<double>> curr2(curr.begin(), curr.end());

      Plaintext p = cc->MakeCKKSPackedPlaintext(curr2);

      mappings[idx] = p;
    }
    maps.push_back(mappings);
  }

  cout << "Encrypting.." << endl;

  auto start = high_resolution_clock::now();

  map<int, vector<Ciphertext<DCRTPoly>>> ciphertexts = encryptLearnerData(cc, kp1, maps);

  auto stop = high_resolution_clock::now();
  std::chrono::duration<double, std::milli> duration = stop - start;
  cout << "Time taken by a learner to encrypt parameters: " << duration.count() / learners.size() << " milliseconds" << endl;

  cout << "Weighted Average.." << endl;

  start = high_resolution_clock::now();

  float weight = training_samples / (learners.size() * training_samples);

  vector<Ciphertext<DCRTPoly>> c0 = ciphertexts[0];

  auto pwa = cc->EvalMult(c0[0], weight);

  for (int i = 0; i < arrays.size(); i++) {
    for (int j = 0; j < learners.size(); j++) {
      if (i == 0 && j == 0) {
      } else {
        //cout << i << ", " << j << endl;
        vector<Ciphertext<DCRTPoly>> c = ciphertexts[j];
        cc->EvalAdd(pwa, cc->EvalMult(c[i], weight));
      }
    }
  }

  stop = high_resolution_clock::now();
  duration = stop - start;
  cout << "Time taken to compute weighted average of parameters of " << learners.size() <<  " learners: " << duration.count() << " milliseconds" << endl;

  cout << "(4) Decrypting.." << endl;

  start = high_resolution_clock::now();

  Plaintext decryptResult = decryptPwa(cc, kp1, pwa);

  duration = start - stop;
  cout << "time taken (s): " << duration.count() * 10 << " milliseconds" << endl;

}