#include "Utilities.h"
#include "AesProvider.h"
#include <sstream>
#include <bitset>
#include <iomanip>
#include <iostream>

std::string DataBlocksHexStringFormat(std::string input)
{
	std::stringstream result;
	int i = 0;
	for (char b : input)
	{
		i++;
		result << std::setfill('0') << std::setw(2) << std::hex << std::uppercase << std::bitset<8>(b).to_ulong() << " ";

		if (i % BLOCK_SIZE == 0)
			result << std::endl;
	}
	return result.str();
}

std::string AesModeToString(AesModes mode)
{
	switch (mode)
	{
	case AES_ECB_128: return "AES-128-ECB";
		break;
	case AES_ECB_256: return "AES-256-ECB";
		break;
	case AES_CBC_128: return "AES-128-CBC";
		break;
	case AES_CBC_256: return "AES-256-CBC";
		break;
	case AES_CTR_128: return "AES-128-CTR";
		break;
	case AES_CTR_256: return "AES-256-CTR";
		break;
	case AES_XTS_128: return "AES-128-XTS";
		break;
	case AES_XTS_256: return "AES-256-XTS";
		break;
	default: throw std::runtime_error("Wskazano nieznany tryb pracy");
		break;
	}
}

void TestAllEncryption()
{
	using namespace std;
	for (int i = 0; i < 8; i++)
	{
		AesModes mode = (AesModes)i;
		string plainText = "Testowy string do sprawdzenia enkrypcji.";
		string cipherText;
		string recoveredText;

		cout << "Tryb pracy: " << AesModeToString(mode) << endl << endl;

		cout << "Tekst jawny:" << endl << plainText << endl << endl;

		cipherText = DefaultEncrypt(mode, plainText);
		cout << "Szyfrogram: " << endl << DataBlocksHexStringFormat(cipherText) << endl;

		recoveredText = DefaultDecrypt(mode, cipherText);
		cout << "Odszyfrowany tekst: " << endl << recoveredText << endl;

		if (plainText == recoveredText)
			cout << endl << "!!! Odszyfrowanie powiodlo sie !!!";
		else
			throw std::runtime_error("Niezgodnosc tekstu jawnego z tekstem odszyfrowanym");


		cout << endl << "=================================================================" << endl << endl;
	}
}
