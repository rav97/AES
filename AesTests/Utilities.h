#pragma once
#include "AesProvider.h"
#include <string>

//Konwertuje tablice bajtow do ich reprezentacji w formie heksadecymalnej z podzialem na bloki danych
std::string DataBlocksHexStringFormat(std::string input);

//Zwraca nazwe wybranego trybu praqcy
std::string AesModeToString(AesModes mode);

//Testuje wszystkie implementowane tryby pracy. Jezeli w trakcie dzialania wystapi blad to oznacza problem z konfiguracja OpenSLL lub parametrow wejsciowych.
void TestAllEncryption();