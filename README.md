# AES

## O projekcie
Program jest implementacją testów przeprowadzonych w ramach pracy magisterskiej na temat bezpieczeństwa danych magazynowanych w zakresie wybranych trybów pracy algorytmu AES (CBC, CTR, XTS). Do testów wykorzystano bibliotekę OpenSSL implementującą wybrane tryby pracy.

## Jak uruchomić?
W celu uruchomienia pożądanego testu należy edytować plik main.cpp poprzez odkomentowanie odpowiedniej metody testowej oraz wskazanie trybu pracy do testów (enum AesModes).

## Uwagi
Przed uruchomieniem testu wydajności czasowej należy wstępnie przygotować ścieżkę do której zapisane zostaną wygenerowane pliki. Aby tego dokonać należy uruchomić skrypt zapisany w pliku ClearFiles.cmd
