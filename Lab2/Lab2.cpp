// Lab2.cpp: определяет точку входа для консольного приложения.
//


#include "stdafx.h"

#include <stdio.h> 
#include <tchar.h> 
#include <stdint.h> 
#include <iostream> 
#include <bitset> 
#include <vector> 
#include <cstdlib> 
#include <time.h>

using namespace std;

vector<uint64_t> EncryptionVector(vector<uint64_t> blocks, vector <uint16_t> keys);
vector<uint64_t> DecryptionVector(vector<uint64_t> blocks, vector <uint16_t> keys);
vector<uint64_t> CBCDecryption(vector<uint64_t> data, vector<uint16_t> keys, uint64_t InitVector);
vector<uint64_t> CBCEncryption(vector<uint64_t> data, vector<uint16_t> keys, uint64_t InitVector);
vector<uint16_t> GetKeys(int rounds);


int main()
{
	
	vector<uint64_t> blocks;
	blocks.push_back(0);
	blocks.push_back(0);

	vector<uint16_t> keys = GetKeys(250);
	uint64_t init_vect = 1;

	cout << "Input" << endl;
	for (int i = 0; i < blocks.size(); i++)
	{
		cout << blocks[i] << " ";
	}

	cout << endl << "Input as 01" << endl;
	for (int i = 0; i < blocks.size(); i++)
	{
		cout << bitset<64>(blocks[i]).to_string() << " ";
	}
	cout << endl << "Encryption" << endl;
	blocks = EncryptionVector(blocks, keys);
	for (int i = 0; i < blocks.size(); i++)
	{
		cout << bitset<64>(blocks[i]).to_string() << " ";
	}
	
	cout << endl << "Decode" << endl;
	blocks = DecryptionVector(blocks, keys);
	for (int i = 0; i < blocks.size(); i++)
	{
		cout << bitset<64>(blocks[i]).to_string() << " ";
	}

	cout << endl << "CBC_Encryption" << endl;
	blocks = CBCEncryption(blocks, keys, init_vect);
	for (int i = 0; i < blocks.size(); i++)
	{
		cout << bitset<64>(blocks[i]).to_string() << " ";
	}

	cout << endl << "CBC_Decode" << endl;
	blocks = CBCDecryption(blocks, keys, init_vect);
	for (int i = 0; i < blocks.size(); i++)
	{
		cout << bitset<64>(blocks[i]).to_string() << " ";
	}

	cout << endl;
	system("pause");
	exit(EXIT_SUCCESS);
}

uint16_t RotLeft16(uint16_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);
	c &= mask;
	return (n << c) | (n >> ((c)&mask));
}

uint16_t RotRight16(uint16_t n, unsigned int c)
{
	const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);
	c &= mask;
	return (n >> c) | (n << ((c)&mask));
}

vector<uint16_t> GetKeys(int rounds)
{
	srand(time(0));
	vector<uint16_t> result;

	uint16_t key = rand();

	for (int i = 0; i < rounds - 1; i++)
	{
		result.push_back(RotRight16(key, i * 8));
	}

	return result;
}

uint16_t GetBlock(uint64_t num, int block)
{
	return (uint16_t)(num >> block * 16);
}

uint64_t Merge(uint16_t b0, uint16_t b1, uint16_t b2, uint16_t b3)
{
	return (uint64_t)b0 << 16 * 0 | (uint64_t)b1 << 16 * 1 | (uint64_t)b2 << 16 * 2 | (uint64_t)b3 << 16 * 3;
}

uint32_t EncryptFunction(uint16_t num, uint16_t key)
{
	return RotLeft16(num, 9) ^ (~(RotRight16(key, 11) ^ num));
}

uint64_t Encryption(uint64_t num, vector<uint16_t> keys)
{
	uint16_t b0 = GetBlock(num, 0);
	uint16_t b1 = GetBlock(num, 1);
	uint16_t b2 = GetBlock(num, 2);
	uint16_t b3 = GetBlock(num, 3);

	for (int i = 0; i < keys.size(); i++)
	{
		uint16_t z0 = EncryptFunction(b0, keys[i]) ^ b1;
		uint16_t z1 = b2;
		uint16_t z2 = b3;
		uint16_t z3 = b0;

		b0 = z0;
		b1 = z1;
		b2 = z2;
		b3 = z3;
	}

	return Merge(b0, b1, b2, b3);
}

uint64_t Decode(uint64_t num, vector<uint16_t> keys)
{
	uint16_t b0 = GetBlock(num, 0);
	uint16_t b1 = GetBlock(num, 1);
	uint16_t b2 = GetBlock(num, 2);
	uint16_t b3 = GetBlock(num, 3);

	for (int i = keys.size() - 1; i >= 0; i--)
	{
		uint16_t z0 = b3;
		uint16_t z1 = EncryptFunction(b3, keys[i]) ^ b0;
		uint16_t z2 = b1;
		uint16_t z3 = b2;

		b0 = z0;
		b1 = z1;
		b2 = z2;
		b3 = z3;
	}

	return Merge(b0, b1, b2, b3);
}

vector<uint64_t> CBCEncryption(vector<uint64_t> data, vector<uint16_t> keys, uint64_t initVector)
{
	vector<uint64_t> res(data.size());

	for (int i = 0; i < data.size(); i++)
	{
		uint64_t init;

		if (i == 0)
		{
			init = initVector;
		}
		else
		{
			init = res[i - 1];
		}

		res[i] = Encryption(data[i] ^ init, keys);
	}

	return res;
}

vector<uint64_t> CBCDecryption(vector<uint64_t> data, vector<uint16_t> keys, uint64_t InitVector)
{
	vector<uint64_t> res(data.size());

	for (int i = data.size() - 1; i >= 0; i--)
	{
		uint64_t init;

		if (i == 0)
		{
			init = InitVector;
		}
		else
		{
			init = data[i - 1];
		}

		res[i] = Decode(data[i], keys) ^ init;
	}

	return res;
}

vector<uint64_t> EncryptionVector(vector<uint64_t> blocks, vector <uint16_t> keys)
{
	vector<uint64_t> result(blocks.size());

	for (int i = 0; i < blocks.size(); i++)
	{
		result[i] = Encryption(blocks[i], keys);
	}

	return result;
}

vector<uint64_t> DecryptionVector(vector<uint64_t> blocks, vector <uint16_t> keys)
{
	vector<uint64_t> result;
	for each (uint64_t block in blocks)
	{
		result.push_back(Decode(block, keys));
	}
	return result;
}