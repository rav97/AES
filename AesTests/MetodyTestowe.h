#pragma once
#include "AesProvider.h"
#include "File.h"
#include "Utilities.h"
#include "OpenSslTypes.h"

//Pomiar czasow operacji szyfrowania i deszyfrowania oraz zapisanie wynikow do pliku csv; 
void Test_WydajnoscCzasowa(AesModes mode, int liczbaPomiarow);

//Wykonanie Test_WydajnoscCzasowa dla wszystkich trybow
void Test_WydajnosciCzasowe();

//Test odpornosci trybu pracy na modyfikacje pojedynczego bitu szyfrogramu
void Test_OdpornoscNaZmianeBitu(AesModes mode);

//Test odpornosci trybu pracy na zmiane polozenia na nosniku
void Test_ZmianaIV(AesModes mode);

//Przedstawienie roznic w dlugosci szyfrogramu w zaleznosci od trybu pracy
void Test_DlugoscSzyfrogramow(AesModes mode);