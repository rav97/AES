#pragma once
#include <string>

std::string ReadTextFile(std::string filePath);
std::string ReadBinaryFile(std::string filePath);
bool SaveBinaryFile(std::string fileName, std::string content);