#include "MetodyTestowe.h"
#include "Utilities.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <Windows.h>
#include <chrono>

using namespace std;

void Test_WydajnoscCzasowa(AesModes mode, int liczbaPomiarow)
{
	using namespace std::chrono;

	string modeName = AesModeToString(mode);

	cout << "======================================================" << endl;
	cout << "Tryb pracy: " << modeName << endl << endl;

	EVP_add_cipher(GetMode(mode));

#pragma region PlikCSV

	string csvPath = modeName + "\\" + modeName + "_czasy.csv";
	ofstream csvFile;
	csvFile.open(csvPath, ios::out);
	csvFile << "EncryptTime;DecryptTime\n";

#pragma endregion

	for (int j = 0; j < liczbaPomiarow; j++)
	{
		cout << "Pomiar " << j + 1 << endl;

		string ptext = "";
		string ctext;

#pragma region ReadTextFile

		//plik zawiera 2^20 bloków danych w zakresie klucza, czyli 16777216 znaków
		ptext = ReadTextFile("InputData.txt");

#pragma endregion

#pragma region Key + IV init

		int keySize = GetKeySize(mode);
		byte* key = new byte[keySize];
		byte iv[BLOCK_SIZE];

		//pobranie predefiniowanych aby kady pomiar korzystal z tego samego klucza i IV
		GetParams(mode, key, iv);

#pragma endregion

		Sleep(50);

#pragma region Enkrypcja

		auto enc_start = high_resolution_clock::now();

		AesEncrypt(mode, key, iv, ptext, ctext);

		auto enc_stop = high_resolution_clock::now();
		auto enc_duration = duration_cast<microseconds>(enc_stop - enc_start);

		//Wyswietlenie wyniku i zapis do pliku
		cout << "Encryption time: " << enc_duration.count() << " microseconds" << endl;
		csvFile << enc_duration.count() << ";";

#pragma endregion

#pragma region Zapisanie szyfrogramu do pliku

		string fileName = modeName + "\\Encrypted_" + modeName + "_" + to_string(j + 1) + ".enc";
		if (!SaveBinaryFile(fileName, ctext))
			throw std::runtime_error("Saving of encrypted file failed");

#pragma endregion


#pragma region Odczytanie szyfrogramu z pliku

		string read_ctext;
		read_ctext = ReadBinaryFile(fileName);

#pragma endregion

		Sleep(50);

#pragma region Dekrypcja

		string rtext;
		auto dec_start = high_resolution_clock::now();

		AesDecrypt(mode, key, iv, read_ctext, rtext);

		auto dec_stop = high_resolution_clock::now();
		auto dec_duration = duration_cast<microseconds>(dec_stop - dec_start);

		//print and save result
		cout << "Decryption time: " << dec_duration.count() << " microseconds " << endl;
		csvFile << dec_duration.count() << "\n";

#pragma endregion

		OPENSSL_cleanse(key, keySize);
		OPENSSL_cleanse(iv, BLOCK_SIZE);

		cout << endl;
	}

	csvFile.close();
}

void Test_WydajnosciCzasowe()
{
	const int liczbaPomiarow = 250;

	//iterowanie po implementowanych trybach pracy
	for (int i = 0; i < 8; i++)
	{
		AesModes mode = (AesModes)i;
		Test_WydajnoscCzasowa(mode, liczbaPomiarow);
	}
}

void Test_OdpornoscNaZmianeBitu(AesModes mode)
{
	string input = "";
	for (int i = 0; i < 70; i++)
		input += char(0);

	cout << "Tekst jawny:" << endl << DataBlocksHexStringFormat(input) << endl << endl;

	string ctext = DefaultEncrypt(mode, input);

	cout << "Szyfrogram:" << endl << DataBlocksHexStringFormat(ctext) << endl << endl;

	//indeks wskazuje ktory bajt ma zostac zmieniony
	ctext[30] = ctext[30] ^ char(1); // XOR z 0000 0001 -> zamiana ostatniego bitu z 0 na 1 i odwrotnie

	cout << "Zmodyfikowany szyfrogram:" << endl << DataBlocksHexStringFormat(ctext) << endl << endl;

	try {
		string rtext = DefaultDecrypt(mode, ctext);
		cout << "Odszyfrowany szyfrogram:" << endl << DataBlocksHexStringFormat(rtext) << endl << endl;
	}
	catch (...) {
		cout << "Wystapil blad dekrypcji" << endl << endl;
	}
}

void Test_ZmianaIV(AesModes mode)
{
	string ptext = "";
	for (int i = 0; i < 64; i++)
		ptext += char(0);

	cout << "Oryginalny tekst jawny:" << endl << DataBlocksHexStringFormat(ptext) << endl << endl;
	cout << "Przeniesienie szyfrogramu do innego sektora (zmiana IV/Nonce/Tweak)\n\n";
	cout << "Odszyfrowany szyfrogram w innym sektorze:" << endl;

	//Zaszyfrowanie przy uzyciu predefiniowanych parametrow
	string ctext = DefaultEncrypt(mode, ptext);
	string rtext;

#pragma region Generowanie nowego IV

	string newIV = "x!A%D*G-KaPdSgVk";
	byte otherSectorIV[BLOCK_SIZE];

	for (int i = 0; i < BLOCK_SIZE; i++)
		otherSectorIV[i] = (byte)newIV[i];

#pragma endregion

	EVP_add_cipher(GetMode(mode));

	int keySize = GetKeySize(mode);
	byte* key = new byte[keySize];
    byte iv[BLOCK_SIZE];
	//pobranie predefiniowanego klucza
	GetParams(mode, key, iv);

	//dekrypcja przy uzyciu tego samego klucza ale innego IV
	AesDecrypt(mode, key, otherSectorIV, ctext, rtext);

	//clearing vector and key
	OPENSSL_cleanse(key, keySize);
	OPENSSL_cleanse(iv, BLOCK_SIZE);
	OPENSSL_cleanse(otherSectorIV, BLOCK_SIZE);

	cout << DataBlocksHexStringFormat(rtext);
	cout << endl << endl;
}

void Test_DlugoscSzyfrogramow(AesModes mode)
{
	const string ptext_32 = "Ten tekst ma dokladnie 32 znaki."; // 32B = 256b ==> 256 % 128 = 0 <-- pelna liczba bitow
	const string ptext_35 = "Ten tekst ma dokladnie 35 znakow!!!"; // 35B = 280b ==> 280 % 128 = 24 <-- niepelna liczba bitow
	const string ptext_48 = "Ten tekst ma dokladnie 48 znakow - modulo 128b!!"; // 35B = 280b ==> 280 % 128 = 24 <-- niepelna liczba bitow

	string ptext;
	string ctext;

	for (int i = 0; i < 3; i++)
	{
		switch (i)
		{
		case 0: ptext = ptext_32; break;
		case 1: ptext = ptext_35; break;
		case 2: ptext = ptext_48; break;
		default: throw runtime_error("Nieprawidlowa dlugosc tekstu");
			break;
		}

		cout << "Tryb " << AesModeToString(mode) << endl;

		cout << endl << "Dane wejsciowe (" << ptext.length() << " B):" << endl << DataBlocksHexStringFormat(ptext) << endl << endl;

		ctext = DefaultEncrypt(mode, ptext);
		cout << "Dane wyjsciowe (" << ctext.length() << " B):" << endl << DataBlocksHexStringFormat(ctext) << endl << endl;

		string rtext = DefaultDecrypt(mode, ctext);
		if (ptext != rtext)
			throw runtime_error("Tekst jawny niezgodny z tekstem odszyfrowanym");
	}
}
