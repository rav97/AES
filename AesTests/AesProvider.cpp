#include "AesProvider.h"
#include <stdexcept>
#include <openssl/rand.h>

const EVP_CIPHER* GetMode(AesModes mode)
{
	switch (mode)
	{
	case AES_ECB_128: return EVP_aes_128_ecb();
		break;
	case AES_ECB_256: return EVP_aes_256_ecb();
		break;
	case AES_CBC_128: return EVP_aes_128_cbc();
		break;
	case AES_CBC_256: return EVP_aes_256_cbc();
		break;
	case AES_CTR_128: return EVP_aes_128_ctr();
		break;
	case AES_CTR_256: return EVP_aes_256_ctr();
		break;
	case AES_XTS_128: return EVP_aes_128_xts();
		break;
	case AES_XTS_256: return EVP_aes_256_xts();
		break;
	default: throw std::runtime_error("Wskazano nieznany tryb pracy");
		break;
	}
}

unsigned int GetKeySize(AesModes mode)
{
	switch (mode)
	{
	case AES_ECB_128: return 16U;
		break;
	case AES_ECB_256: return 32U;
		break;
	case AES_CBC_128: return 16U;
		break;
	case AES_CBC_256: return 32U;
		break;
	case AES_CTR_128: return 16U;
		break;
	case AES_CTR_256: return 32U;
		break;
	case AES_XTS_128: return 32U;
		break;
	case AES_XTS_256: return 64U;
		break;
	default: throw std::runtime_error("Wskazano nieznany tryb pracy");
		break;
	}
}

void GenParams(AesModes mode, byte* key, byte iv[BLOCK_SIZE])
{
	int keySize = GetKeySize(mode);

	int rc = RAND_bytes(key, keySize);
	if (rc != 1)
		throw std::runtime_error("Blad RAND_bytes dla generowania klucza");

	rc = RAND_bytes(iv, BLOCK_SIZE);
	if (rc != 1)
		throw std::runtime_error("Blad RAND_bytes dla generowania IV");
}

void GetParams(AesModes mode, byte* key, byte iv[BLOCK_SIZE])
{
	int keySize = GetKeySize(mode);

	for (int i = 0; i < keySize; i++)
		key[i] = CONST_KEY[i];

	for (int i = 0; i < BLOCK_SIZE; i++)
		iv[i] = CONST_IV[i];
}

void AesEncrypt(AesModes mode, const byte* key, const byte iv[BLOCK_SIZE], const std::string& ptext, std::string& ctext)
{
	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	int rc = EVP_EncryptInit_ex(ctx.get(), GetMode(mode), NULL, key, iv);
	if (rc != 1)
		throw std::runtime_error("EVP_EncryptInit_ex failed");

	ctext.resize(ptext.size() + BLOCK_SIZE);
	int out_len1 = (int)ctext.size();

	rc = EVP_EncryptUpdate(ctx.get(), (byte*)&ctext[0], &out_len1, (const byte*)&ptext[0], (int)ptext.size());
	if (rc != 1)
		throw std::runtime_error("EVP_EncryptUpdate failed");

	int out_len2 = (int)ctext.size() - out_len1;
	rc = EVP_EncryptFinal_ex(ctx.get(), (byte*)&ctext[0] + out_len1, &out_len2);
	if (rc != 1)
		throw std::runtime_error("EVP_EncryptFinal_ex failed");

	ctext.resize(out_len1 + out_len2);
}

void AesDecrypt(AesModes mode, const byte* key, const byte iv[BLOCK_SIZE], const std::string& ctext, std::string& rtext)
{
	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	int rc = EVP_DecryptInit_ex(ctx.get(), GetMode(mode), NULL, key, iv);
	if (rc != 1)
		throw std::runtime_error("EVP_DecryptInit_ex failed");

	rtext.resize(ctext.size());
	int out_len1 = (int)rtext.size();

	rc = EVP_DecryptUpdate(ctx.get(), (byte*)&rtext[0], &out_len1, (const byte*)&ctext[0], (int)ctext.size());
	if (rc != 1)
		throw std::runtime_error("EVP_DecryptUpdate failed");

	int out_len2 = (int)rtext.size() - out_len1;
	rc = EVP_DecryptFinal_ex(ctx.get(), (byte*)&rtext[0] + out_len1, &out_len2);
	if (rc != 1)
		throw std::runtime_error("EVP_DecryptFinal_ex failed");

	rtext.resize(out_len1 + out_len2);
}

std::string DefaultEncrypt(AesModes mode, std::string plaintext)
{
	EVP_add_cipher(GetMode(mode));
	int keySize = GetKeySize(mode);

	byte* key = new byte[keySize];
	byte iv[BLOCK_SIZE];

	GetParams(mode, key, iv);

	std::string ctext;
	AesEncrypt(mode, key, iv, plaintext, ctext);

	OPENSSL_cleanse(key, keySize);
	OPENSSL_cleanse(iv, BLOCK_SIZE);

	return ctext;
}

std::string DefaultDecrypt(AesModes mode, std::string ciphertext)
{
	EVP_add_cipher(GetMode(mode));
	int keySize = GetKeySize(mode);

	byte* key = new byte[keySize];
	byte iv[BLOCK_SIZE];

	GetParams(mode, key, iv);

	std::string rtext;
	AesDecrypt(mode, key, iv, ciphertext, rtext);

	OPENSSL_cleanse(key, keySize);
	OPENSSL_cleanse(iv, BLOCK_SIZE);

	return rtext;
}
