/**********************************************************************************
* FourQlib: a high-performance crypto library based on the elliptic curve FourQ
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
* Abstract: digital signature SchnorrQ
*
* See "SchnorrQ: Schnorr signatures on FourQ" by Craig Costello and Patrick Longa,
* MSR Technical Report, 2016. Available at: 
* https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/SchnorrQ.pdf.
***********************************************************************************/ 

#include "FourQ_internal.h"
#include "FourQ_params.h"
#include "../random/random.h"
#include "../sha512/sha512.h"
#include <malloc.h>
#include <string.h>

#define BPV_n 1024
#define BPV_k 16

ECCRYPTO_STATUS SchnorrQ_KeyGeneration(const unsigned char* SecretKey, unsigned char* PublicKey)
{ // SchnorrQ public key generation
  // It produces a public key PublicKey, which is the encoding of P = s*G, where G is the generator and
  // s is the output of hashing SecretKey and taking the least significant 32 bytes of the result.
  // Input:  32-byte SecretKey
  // Output: 32-byte PublicKey
    point_t P;
    unsigned char k[64];
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
  
    if (CryptoHashFunction(SecretKey, 32, k) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
    
    ecc_mul_fixed((digit_t*)k, P);          // Compute public key                                       
	encode(P, PublicKey);                   // Encode public key

    return ECCRYPTO_SUCCESS;

cleanup:
	clear_words((unsigned int*)k, 512/(sizeof(unsigned int)*8));
    clear_words((unsigned int*)PublicKey, 256/(sizeof(unsigned int)*8));

    return Status;
}


ECCRYPTO_STATUS SchnorrQ_FullKeyGeneration(unsigned char* SecretKey, unsigned char* PublicKey)
{ // SchnorrQ keypair generation
  // It produces a private key SecretKey and computes the public key PublicKey, which is the encoding of P = s*G, 
  // where G is the generator and s is the output of hashing SecretKey and taking the least significant 32 bytes of the result.
  // Outputs: 32-byte SecretKey and 32-byte PublicKey
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;

	Status = RandomBytesFunction(SecretKey, 32);
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }
  
    Status = SchnorrQ_KeyGeneration(SecretKey, PublicKey);   
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;
    }

    return ECCRYPTO_SUCCESS;

cleanup:
    clear_words((unsigned int*)SecretKey, 256/(sizeof(unsigned int)*8));
    clear_words((unsigned int*)PublicKey, 256/(sizeof(unsigned int)*8));

    return Status;
}


ECCRYPTO_STATUS SchnorrQ_Sign(const unsigned char* SecretKey, const unsigned char* PublicKey, const unsigned char* Message, const unsigned int SizeMessage, unsigned char* Signature)
{ // SchnorrQ signature generation
  // It produces the signature Signature of a message Message of size SizeMessage in bytes
  // Inputs: 32-byte SecretKey, 32-byte PublicKey, and Message of size SizeMessage in bytes
  // Output: 64-byte Signature 
    point_t R;
    unsigned char k[64], r[64], h[64], *temp = NULL;
	digit_t* H = (digit_t*)h;
    digit_t* S = (digit_t*)(Signature+32);
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
      
    if (CryptoHashFunction(SecretKey, 32, k) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
    
    temp = (unsigned char*)calloc(1, SizeMessage+64);
    if (temp == NULL) {
		Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
    
    memmove(temp+32, k+32, 32);
    memmove(temp+64, Message, SizeMessage);
  
    if (CryptoHashFunction(temp+32, SizeMessage+32, r) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
    
    ecc_mul_fixed((digit_t*)r, R); 
    encode(R, Signature);                   // Encode lowest 32 bytes of signature
    memmove(temp, Signature, 32);
    memmove(temp+32, PublicKey, 32);
  
    if (CryptoHashFunction(temp, SizeMessage+64, h) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
	modulo_order((digit_t*)r, (digit_t*)r);
	modulo_order(H, H);
	to_Montgomery((digit_t*)k, S);          // Converting to Montgomery representation
	to_Montgomery(H, H);                    // Converting to Montgomery representation
	Montgomery_multiply_mod_order(S, H, S);
	from_Montgomery(S, S);                  // Converting back to standard representation
	subtract_mod_order((digit_t*)r, S, S);
	Status = ECCRYPTO_SUCCESS;
    
cleanup:
	if (temp != NULL)
		free(temp);
    clear_words((unsigned int*)k, 512/(sizeof(unsigned int)*8));
	clear_words((unsigned int*)r, 512/(sizeof(unsigned int)*8));
    
    return Status;
}


ECCRYPTO_STATUS SchnorrQ_Verify(const unsigned char* PublicKey, const unsigned char* Message, const unsigned int SizeMessage, const unsigned char* Signature, unsigned int* valid)
{ // SchnorrQ signature verification
  // It verifies the signature Signature of a message Message of size SizeMessage in bytes
  // Inputs: 32-byte PublicKey, 64-byte Signature, and Message of size SizeMessage in bytes
  // Output: true (valid signature) or false (invalid signature)
    point_t A;
    unsigned char *temp, h[64];
    unsigned int i;
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;  

    *valid = false;

	temp = (unsigned char*)calloc(1, SizeMessage+64);
	if (temp == NULL) {
		Status = ECCRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}

    if (((PublicKey[15] & 0x80) != 0) || ((Signature[15] & 0x80) != 0) || (Signature[63] != 0) || ((Signature[62] & 0xC0) != 0)) {  // Are bit128(PublicKey) = bit128(Signature) = 0 and Signature+32 < 2^246?
		Status = ECCRYPTO_ERROR_INVALID_PARAMETER;
		goto cleanup;
    }
    
	Status = decode(PublicKey, A);    // Also verifies that A is on the curve. If it is not, it fails  
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;                            
    }

    memmove(temp, Signature, 32);
    memmove(temp+32, PublicKey, 32);
    memmove(temp+64, Message, SizeMessage);
  
    if (CryptoHashFunction(temp, SizeMessage+64, h) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }

    Status = ecc_mul_double((digit_t*)(Signature+32), A, (digit_t*)h, A);      
    if (Status != ECCRYPTO_SUCCESS) {                                                
        goto cleanup;
    }
	
	encode(A, (unsigned char*)A);

    for (i = 0; i < NWORDS_ORDER; i++) {
        if (((digit_t*)A)[i] != ((digit_t*)Signature)[i]) {
            goto cleanup;   
        }
    }
    *valid = true;

cleanup:
	if (temp != NULL)
		free(temp);
    
    return Status;
}


ECCRYPTO_STATUS BPVOnline(const unsigned char* SecretKey, const unsigned char* PublicKey, unsigned char* lastSecret, unsigned char* lastPublic)
{
	ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
	digit_t* S = (digit_t*)(lastSecret);
	unsigned char* index;
	unsigned char secretTemp[32], publicTemp[64];
	unsigned char secretTemp2[32];
	int k;
	//point_t Temp;
	point_t Added;
	point_extproj_t AddedExtproj;
	point_extproj_t TempExtproj;
	point_extproj_precomp_t TempExtprojPre;
	
	Status = RandomBytesFunction(index, BPV_n);
	if (Status != ECCRYPTO_SUCCESS) {
		goto cleanup;
	}
	index[0] = BPV_n*index[0]/256;
	memmove(secretTemp,SecretKey +32*index[0],32);
	memmove(publicTemp,PublicKey +64*index[0],64);
	
	point_setup((point_affine*)publicTemp, AddedExtproj);
	
	index[1] = BPV_n*index[1]/256;
	memmove(secretTemp2,SecretKey +32*index[1],32);
	memmove(publicTemp,PublicKey +64*index[1],64);
	
	point_setup((point_affine*)publicTemp, TempExtproj);
	R1_to_R3(TempExtproj, TempExtprojPre);
	
	eccadd(TempExtprojPre, AddedExtproj);
	add_mod_order((digit_t*)secretTemp, (digit_t*)secretTemp2, S);
	
	for(k = 0; k < BPV_k - 2; k++){
		index[k+2] = BPV_n*index[k+2]/256;
		memmove(secretTemp,SecretKey +32*index[k+2],32);
		memmove(publicTemp,PublicKey +64*index[k+2],64);

		point_setup((point_affine*)publicTemp, TempExtproj);
		R1_to_R3(TempExtproj, TempExtprojPre);
		
		eccadd(TempExtprojPre, AddedExtproj);
		add_mod_order((digit_t*)secretTemp, S, S);
	}
	
	//eccnorm(AddedExtproj, (point_affine*)lastPublic);
	eccnorm(AddedExtproj, Added);
	encode(Added, lastPublic);
	
	return ECCRYPTO_SUCCESS;
	
cleanup:
	return Status;
}



ECCRYPTO_STATUS BPVSchnorr_Sign(const unsigned char* AllSecretKey, const unsigned char* AllPublicKey, const unsigned char* SecretKey, const unsigned char* PublicKey, const unsigned char* Message, const unsigned int SizeMessage, unsigned char* Signature)
{
	ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
	unsigned char k[32], r[32], h[64], *temp = NULL;
	digit_t* H = (digit_t*)h;
    digit_t* S = (digit_t*)(Signature+32);
	
	BPVOnline(AllSecretKey, AllPublicKey, k, r);
	
	temp = (unsigned char*)calloc(1, SizeMessage+32);
    if (temp == NULL) {
		Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }
	
	memmove(temp, r, 32);
	memmove(temp+32, Message, SizeMessage);
  
    if (CryptoHashFunction(temp, SizeMessage+32, h) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
	
	modulo_order(H, H);
	memmove(Signature, h, 32);
	
	to_Montgomery((digit_t*)SecretKey, S);          // Converting to Montgomery representation
	to_Montgomery(H, H);                    // Converting to Montgomery representation
	Montgomery_multiply_mod_order(S, H, S);
	from_Montgomery(S, S);                  // Converting back to standard representation
	subtract_mod_order((digit_t*)r, S, S);
	Status = ECCRYPTO_SUCCESS;
	
	return Status;
	
cleanup:
	return Status;
	
	
}




ECCRYPTO_STATUS BPVSchnorr_Verify(const unsigned char* PublicKey, const unsigned char* Message, const unsigned int SizeMessage, const unsigned char* Signature, unsigned int* valid)
{
	ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
	point_t A;
    unsigned char *temp, h[64], r[32];
	digit_t* H = (digit_t*)h;
    unsigned int i;

    *valid = false;

	temp = (unsigned char*)calloc(1, SizeMessage+32);
	if (temp == NULL) {
		Status = ECCRYPTO_ERROR_NO_MEMORY;
		goto cleanup;
	}
    
	Status = decode(PublicKey, A);    // Also verifies that A is on the curve. If it is not, it fails  
    if (Status != ECCRYPTO_SUCCESS) {
        goto cleanup;                            
    }
	
	memmove(r, Signature, 32);
	
	Status = ecc_mul_double((digit_t*)(Signature+32), A, (digit_t*)r, A);      
    if (Status != ECCRYPTO_SUCCESS) {                                                
        goto cleanup;
    }
	
	encode(A, r);
	
	memmove(temp, r, 32);
	memmove(temp+32, Message, SizeMessage);
  
    if (CryptoHashFunction(temp, SizeMessage+32, h) != 0) {   
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
	modulo_order(H, H);

    for (i = 0; i < NWORDS_ORDER; i++) {
        if (((digit_t*)h)[i] != ((digit_t*)Signature)[i]) {
            goto cleanup;   
        }
    }
    *valid = true;

	return Status;
cleanup:
	return Status;
	
}















