#pragma once
#include <windows.h>
#include <TlHelp32.h>

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#define CONTEXTAX(CTX) CTX->Rax
#define CONTEXTBX(CTX) CTX->Rbx
#else
typedef IMAGE_NT_HEADERS32  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#define CONTEXTAX(CTX) CTX->Eax
#define CONTEXTBX(CTX) CTX->Ebx
#endif

class peLoader32
{
public:
	peLoader32();
	~peLoader32();

	bool load(BYTE* data);
};