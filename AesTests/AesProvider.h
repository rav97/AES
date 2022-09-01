#pragma once
#include "OpenSslTypes.h"
#include <string>

enum AesModes {
	AES_ECB_128,
	AES_ECB_256,
	AES_CBC_128,
	AES_CBC_256,
	AES_CTR_128,
	AES_CTR_256,
	AES_XTS_128,
	AES_XTS_256
};

//wielkosc bloku danych w bajtach
static const unsigned int BLOCK_SIZE = 16;

//Predefiniowany 512-bitowy klucz
static const std::string CONST_KEY = "u7x!A%D*G-KaPdSgUkXp2s5v8y/B?E(H+MbQeThWmZq3t6w9z$C&F)J@NcRfUjXn";

//Predefiniowany 128-bitowy wektor inicjujacy
static const std::string CONST_IV = "VkYp3s6v9y$B&E(H";

//Zwraca silnik szyfrujcy w danym trybie OpenSSL
const EVP_CIPHER* GetMode(AesModes mode);

//Zwraca rozmiar klucza typowy dla wskazanego trybu pracy
unsigned int GetKeySize(AesModes mode);

//Generuje pseudolosowe parametry (klucz, IV)
void GenParams(AesModes mode, byte *key, byte iv[BLOCK_SIZE]);

//Zwraca podciag predefiniowanych parametrow o dlugosci dla wskazanego typu
void GetParams(AesModes mode, byte *key, byte iv[BLOCK_SIZE]);

//Szyfrowanie AES wskazanym trybem pracy i parametrami (OpenSSL)
void AesEncrypt(AesModes mode, const byte *key, const byte iv[BLOCK_SIZE], const std::string& ptext, std::string& ctext);

//Deszyfrowanie AES wskazanym trybem pracy i parametrami (OpenSSL)
void AesDecrypt(AesModes mode, const byte *key, const byte iv[BLOCK_SIZE], const std::string& ctext, std::string& rtext);

//Uproszczona metoda szyfrujaca AES we wskazanym trybie. Pobiera predefinowane parametry wejsciowe.
std::string DefaultEncrypt(AesModes mode, std::string plaintext);

//Uproszczona metoda deszyfrujaca AES we wskazanym trybie. Pobiera predefinowane parametry wejsciowe.
std::string DefaultDecrypt(AesModes mode, std::string ciphertext);