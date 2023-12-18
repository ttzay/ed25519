//******************************************************************************
// ttzay@github.com
// test code for this ed25519 
//
//------------------------------------------------------------------------------

#include <iostream>
#include <string>
#include "ed25519.h"
#include "sha3.h"
#include "Keys.hpp"
#include "ge.h"
#include "fixedint.h"
#include "fe.h"
#include "sc.h"
#include "precomp_data.h"


//使用openssl的base64编码显示输出
#include <openssl/bio.h>
#include <openssl/evp.h>


using std::string,std::cout,std::cin;
using std::endl;

//to base64 
std::string to_base64(const unsigned char* data, size_t length) {
    // Create a memory BIO that will hold the Base64 data
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines
    BIO_push(b64, mem);

    // Write data to the BIO
    BIO_write(b64, data, length);
    BIO_flush(b64);

    // Now get the data from the memory BIO
    char* base64_data;
    long base64_length = BIO_get_mem_data(mem, &base64_data);
    std::string base64_string(base64_data, base64_length);

    // Clean up
    BIO_free_all(b64);

    return base64_string;
}






int 
main()
{
    //init
    unsigned char publicKey[32];
    unsigned char secretKey[64];
    unsigned char signature[64];
    unsigned char seed[32];

    //creat new keypair
    ed25519_create_keypair(publicKey, secretKey,seed);

    string PublicKey = to_base64(publicKey,32);
    string SecretKey = to_base64(secretKey,64);
    cout << " 产生的密钥对：" << std::endl;
    cout << "Public Key: " << PublicKey << std::endl;
    cout << "Secret Key: " << SecretKey << std::endl;



    //Sign a message
    //unsigned char* message = "hello world!"
    const unsigned char* message = (const unsigned char*)"hello world!";
    cout <<"签名前的信息："  << message << endl;
    ed25519_sign(signature, message, 13,publicKey, secretKey);
    string Signature = to_base64(signature,64); 
    cout << " 签名后的信息：" << Signature << std::endl;

    // Verify the signature
    if(ed25519_verify(signature, message,13,publicKey)) 
        cout << "this is the owner of this message" << endl;
    else 
        
    return 0;
}