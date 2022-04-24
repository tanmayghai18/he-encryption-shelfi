//
//  main.cpp
//  SecureComputation
//
//  Created by Hamza Saleem on 12/10/2019.
//  Copyright © 2019 Hamza Saleem. All rights reserved.
//

#include "FHE_Helper.hpp"
#include <iomanip>

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

/*
Helper function: Prints a matrix of values.
*/
template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 5;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}

/*
Helper function: Print line number.
*/
inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}


int main(int argc, const char * argv[]) {

    unsigned int batch_size = 8192;
    unsigned int scalingBits = 40;
    string enc_scheme = "ckks";
    string crypto_params_dir = "CryptoParams/";
    unsigned int total_params = 1000000;

    FHE_Helper* fhe_helper = new FHE_Helper(enc_scheme, batch_size, scalingBits, crypto_params_dir);

    //fhe_helper->genCryptoContextAndKeys();

    fhe_helper->load_crypto_params();

    //Learner 1 Data
    vector<double> data1;
    for(unsigned int i=0; i<total_params; i++){

        data1.push_back(0.01);

    }
    
    cout<<"Learner 1:"<<endl;
    print_vector(data1);

    //Learner 2 Data
    vector<double> data2;
    for(unsigned int i=0; i<total_params; i++){

        data2.push_back(0.5);

    }
    
    cout<<"Learner 2:"<<endl;
    print_vector(data2);

    //Learner 3 Data
    vector<double> data3;
    for(unsigned int i=0; i<total_params; i++){

        data3.push_back(-1.2);

    }
    
    cout<<"Learner 3:"<<endl;
    print_vector(data3);

    vector<string> learners_Data;

    // encrypt data vector
    string result1;
    string result2;
    string result3;

    cout<<"Starting Encryption"<<endl;
    
    fhe_helper->encrypt(data1, result1);
    cout<<"Encryption 1 done"<<endl;
    fhe_helper->encrypt(data2, result2);
    cout<<"Encryption 2 done"<<endl;
    fhe_helper->encrypt(data3, result3);
    cout<<"Encryption 3 done"<<endl;


    learners_Data.push_back(result1);
    learners_Data.push_back(result2);
    learners_Data.push_back(result3);


    // scaling factors of 3 learners
    vector<float> scalingFactors;
    scalingFactors.push_back(0.5);
    scalingFactors.push_back(0.2);
    scalingFactors.push_back(0.3);

    //compute PWA of 3 learners 0.5 * L1_data + 0.2 * L2_data + 0.3 * L3_data
    string he_result;
    fhe_helper->computeWeightedAverage(learners_Data, scalingFactors, he_result);

    cout<<"PWA Done"<<endl;


    vector<double> dec_result;
    fhe_helper->decrypt(he_result, total_params, dec_result);

    cout<<"Decrypt done"<<endl;


    cout<<"Result: 0.5 * L1_data + 0.2 * L2_data + 0.3 * L3_data"<<endl;
    
    
    print_vector(dec_result);
    
    cout<<"result size: "<<dec_result.size()<<endl;
    


    return 0;

}