#include "PE64.h"
#include "stdafx.h"
#include "ST.h"
#include "Util.h"

peLoader64::peLoader64()
{
}

peLoader64::~peLoader64()
{
}

bool peLoader64::load(BYTE* data)
{
	LOGI("peLoader64::load - start");
	LONGLONG fileSize = -1;
	BYTE* pImageBase = NULL;
	LPVOID preferAddr = 0;
	IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)ST<Util>::getInstance()->getNtHdrs(data);

	IMAGE_DATA_DIRECTORY* relocDir = ST<Util>::getInstance()->getPeDir(data, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	preferAddr = (LPVOID)ntHeader->OptionalHeader.ImageBase;
	LOGD("Exe File Prefer Image Base at %x", preferAddr);

	HMODULE dll = LoadLibraryA("ntdll.dll");
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(dll, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);

	pImageBase = (BYTE*)VirtualAlloc(preferAddr, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pImageBase && !relocDir)
	{
		LOGE("Allocate Image Base At %x Failure.", preferAddr);
		return false;
	}
	if (!pImageBase && relocDir)
	{
		LOGD("Try to Allocate Memory for New Image Base");
		pImageBase = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pImageBase)
		{
			LOGE("Allocate Memory For Image Base Failure.");
			return false;
		}
	}

	ntHeader->OptionalHeader.ImageBase = (size_t)pImageBase;
	memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

	IMAGE_SECTION_HEADER* SectionHeaderArr = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++)
	{
		LOGD("Mapping Section %s", SectionHeaderArr[i].Name);
		memcpy
		(
			LPVOID(size_t(pImageBase) + SectionHeaderArr[i].VirtualAddress),
			LPVOID(size_t(data) + SectionHeaderArr[i].PointerToRawData),
			SectionHeaderArr[i].SizeOfRawData
		);
	}

	//masqueradeCmdline(cmdline);
	ST<Util>::getInstance()->fixIAT(pImageBase);

	if (pImageBase != preferAddr)
		if (ST<Util>::getInstance()->applyReloc((size_t)pImageBase, (size_t)preferAddr, pImageBase, ntHeader->OptionalHeader.SizeOfImage))
			LOGD("Relocation Fixed.");
	size_t retAddr = (size_t)(pImageBase)+ntHeader->OptionalHeader.AddressOfEntryPoint;

	((void(*)())retAddr)();
}