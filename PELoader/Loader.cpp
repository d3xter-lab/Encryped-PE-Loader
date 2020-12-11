#include "stdafx.h"
#include "Loader.h"
#include "ST.h"

int main()
{
	LOGI("loader - start");
	char strBuffer[_MAX_PATH] = { 0, };
	std::string CurrentFilePath = "";
	std::string exePath = "";
	const char exeName[16] = { 0xBB, 0xCD, 0x63, 0x09, 0x07, 0xA0, 0xB9, 0xED, 0x90, };

	CurrentFilePath = getcwd(strBuffer, _MAX_PATH);
	exePath = CurrentFilePath + "\\data\\";
	for (int i = 0; i < sizeof(exeName); i++)
	{
		exePath += exeName[i] ^ 6;
		LOGD("loader - get exe name [%x -> %x]", exeName[i], exeName[i] ^ 6);
	}

	LONGLONG fileSize = -1;
	BYTE* enc = ST<Util>::getInstance()->MapFileToMemory(exePath.c_str(), fileSize);
	BYTE* dec = Crypto::decryptByteByAES(enc, fileSize);

#ifdef _WIN64
	peLoader64* peLoader_ = new peLoader64;
	peLoader_->load(dec);
#else
	peLoader32* peLoader_ = new peLoader32;
	peLoader_->load(buffer);
#endif
	return 0;
}