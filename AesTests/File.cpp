#include "File.h"
#include <fstream>
#include <sstream>

std::string ReadTextFile(std::string filePath)
{
	std::ifstream inFile;
	inFile.open(filePath);

	std::stringstream buffer;
	buffer << inFile.rdbuf();

	return buffer.str();
}

std::string ReadBinaryFile(std::string filePath)
{
	std::ifstream inFile(filePath, std::ios::in | std::ios::binary);

	unsigned int size = 0;
	inFile.read(reinterpret_cast<char*>(&size), sizeof(size));

	std::string buffer;
	buffer.resize(size);

	inFile.read(&buffer[0], buffer.size());
	inFile.close();

	return buffer;
}

bool SaveBinaryFile(std::string fileName, std::string content)
{
	std::ofstream ofFile(fileName, std::ios::out | std::ios::binary);

	if (!ofFile)
		return false;

	unsigned int size = content.size();
	ofFile.write(reinterpret_cast<char*>(&size), sizeof(size));
	ofFile.write(content.c_str(), content.size());

	ofFile.close();

	return ofFile.good();
}
