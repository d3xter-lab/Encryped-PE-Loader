#include "Crypto.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include "DG.h"

// Crypto++ static libray setting
#pragma comment ( lib, "cryptlib" )

#define MAGIC_SIZE 4
#define MAGIC2_SIZE 8

static byte key[CryptoPP::AES::DEFAULT_KEYLENGTH] = { 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef, 0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01 };
static byte iv[CryptoPP::AES::BLOCKSIZE] = { 0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef, 0x34,0x56,0x78,0x90,0xab,0xcd,0xef,0x12 };

int Crypto::checkSignature(unsigned char* data, int dataSize, unsigned __int64& realSize)
{
	int signatureSize = 0;
	char* magic = nullptr;
	char realMagic[MAGIC_SIZE] = "\x52\x44";

	if (data == nullptr)
		return -1;

	magic = (char *)(data);
	if (strncmp(magic, realMagic, 2) == 0)
	{
		LOGD("Crypto::checkSignature - find magic number!");
		realSize = *(unsigned __int64*)(data + 4);
		LOGD("Crypto::checkSignature - exe real size[%d]", realSize);
	}
	return 1;
}

inline bool Crypto::EndOfFile(const CryptoPP::FileSource& file)
{
	std::istream* stream = const_cast<CryptoPP::FileSource&>(file).GetStream();
	return stream->eof();
}

bool Crypto::encryptFileByAES(const std::string& clearfile, const std::string& encfile)
{
	try {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
		encryptor.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

		CryptoPP::StreamTransformationFilter filter(encryptor);

		CryptoPP::FileSource source(clearfile.c_str(), false);
		CryptoPP::FileSink sink(encfile.c_str());

		source.Attach(new CryptoPP::Redirector(filter));
		filter.Attach(new CryptoPP::Redirector(sink));

		const CryptoPP::word64 BLOCK_SIZE = 4096;
		CryptoPP::word64 processed = 0;

		while (!EndOfFile(source) && !source.SourceExhausted()) {
			source.Pump(BLOCK_SIZE);
			filter.Flush(false);
			processed += BLOCK_SIZE;
		}

		filter.MessageEnd();
		return true;
	}
	catch (const CryptoPP::Exception& ex) {
		return false;
	}
}

bool Crypto::decryptFileByAES(const std::string& encfile, const std::string& clearfile)
{
	try {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
		decryptor.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

		CryptoPP::StreamTransformationFilter filter(decryptor);

		CryptoPP::FileSource source(encfile.c_str(), false);
		CryptoPP::FileSink sink(clearfile.c_str());

		source.Attach(new CryptoPP::Redirector(filter));
		filter.Attach(new CryptoPP::Redirector(sink));

		const CryptoPP::word64 BLOCK_SIZE = 4096;
		CryptoPP::word64 processed = 0;

		while (!EndOfFile(source) && !source.SourceExhausted()) {
			source.Pump(BLOCK_SIZE);
			filter.Flush(false);
			processed += BLOCK_SIZE;
		}
		
		filter.MessageEnd();
		return true;
	}
	catch (const CryptoPP::Exception& ex) {
		return false;
	}
}

BYTE* Crypto::decryptByteByAES(BYTE* cipher, LONGLONG size)
{
	LOGI("Crypto::decryptByteByAES - exe decrypt");
	unsigned __int64 realSize;
	checkSignature(cipher, size, realSize);
	std::vector<byte> recover;
	CryptoPP::HexEncoder encoder(new CryptoPP::FileSink(std::cout));
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
	dec.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

	recover.resize(realSize);
	CryptoPP::ArraySink rs(&recover[0], recover.size());
	CryptoPP::ArraySource(cipher + MAGIC_SIZE + MAGIC2_SIZE, realSize, true, new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::Redirector(rs), CryptoPP::StreamTransformationFilter::ZEROS_PADDING));
	recover.resize(rs.TotalPutLength());

	char* temp;
	temp = new char[recover.size()];
	std::copy(recover.begin(), recover.end(), temp);
	BYTE* result = reinterpret_cast<BYTE*>(temp);
	return result;
}
