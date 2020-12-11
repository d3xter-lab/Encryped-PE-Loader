#pragma once
#include <windows.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include "DG.h"

class Util
{
public:
	BYTE* MapFileToMemory(LPCSTR filename, LONGLONG& filelen);
	BYTE* getNtHdrs(BYTE* pe_buffer);
	IMAGE_DATA_DIRECTORY* getPeDir(PVOID pe_buffer, size_t dir_id);
	void masqueradeCmdline(const wchar_t* cmdline);
	bool fixIAT(PVOID modulePtr);
	bool applyReloc(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr, SIZE_T moduleSize);
	unsigned int getFileSize(const char* fileName);
};