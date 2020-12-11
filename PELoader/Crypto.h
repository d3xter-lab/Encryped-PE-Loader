#pragma once
#include <string>
#include <windows.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/modes.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/osrng.h"
#include "cryptopp/config.h"
#include "cryptopp/hex.h"

class Crypto
{
public:
	Crypto();
	virtual ~Crypto();

	static int checkSignature(unsigned char* data, int dataSize, unsigned __int64& realSize);
	static bool encryptFileByAES(const std::string& clearfile, const std::string& encfile);
	static bool decryptFileByAES(const std::string& encfile, const std::string& clearfile);
	static BYTE* decryptByteByAES(BYTE* cipher, LONGLONG size);

private:
	static inline bool EndOfFile(const CryptoPP::FileSource& file);
};