#include "Util.h"

#define _CRT_SECURE_NO_WARNINGS
#define RELOC_32BIT_FIELD 3
#define BUF_SIZE 1024
#pragma warning( disable : 4996 )

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;

bool hijackCmdline = false;
char* sz_masqCmd_Ansi = NULL, * sz_masqCmd_ArgvAnsi[100] = {  };
wchar_t* sz_masqCmd_Widh = NULL, * sz_masqCmd_ArgvWidh[100] = { };
int int_masqCmd_Argc = 0;
LPWSTR hookGetCommandLineW() { return sz_masqCmd_Widh; }
LPSTR hookGetCommandLineA() { return sz_masqCmd_Ansi; }

unsigned int Util::getFileSize(const char* fileName)
{
	unsigned int ret = 0;
	struct stat fileInfo = { 0, };
	if (stat(fileName, &fileInfo) < 0)
	{
		return ret;
	}
	return fileInfo.st_size;
}

BYTE* Util::MapFileToMemory(LPCSTR filename, LONGLONG& filelen)
{
	LOGI("Util::MapFileToMemory - %s", filename);
	FILE* fileptr;
	BYTE* buffer;

	fileptr = fopen(filename, "rb");  // Open the file in binary mode
	fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
	filelen = ftell(fileptr);             // Get the current byte offset in the file
	rewind(fileptr);                      // Jump back to the beginning of the file

	buffer = (BYTE*)malloc((filelen + 1) * sizeof(char)); // Enough memory for file + \0
	fread(buffer, filelen, 1, fileptr); // Read in the entire file
	fclose(fileptr); // Close the file

	return buffer;
}

BYTE* Util::getNtHdrs(BYTE* pe_buffer)
{
	if (pe_buffer == NULL) return NULL;

	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	const LONG kMaxOffset = 1024;
	LONG pe_offset = idh->e_lfanew;
	if (pe_offset > kMaxOffset) return NULL;
	IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)((BYTE*)pe_buffer + pe_offset);
	if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;
	return (BYTE*)inh;
}

IMAGE_DATA_DIRECTORY* Util::getPeDir(PVOID pe_buffer, size_t dir_id)
{
	if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

	BYTE* nt_headers = getNtHdrs((BYTE*)pe_buffer);
	if (nt_headers == NULL) return NULL;

	IMAGE_DATA_DIRECTORY* peDir = NULL;

	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
	peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

	if (peDir->VirtualAddress == NULL) {
		return NULL;
	}
	return peDir;
}

bool Util::applyReloc(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr, SIZE_T moduleSize)
{
	IMAGE_DATA_DIRECTORY* relocDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (relocDir == NULL) /* Cannot relocate - application have no relocation table */
		return false;

	size_t maxSize = relocDir->Size;
	size_t relocAddr = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* reloc = NULL;

	size_t parsedSize = 0;
	for (; parsedSize < maxSize; parsedSize += reloc->SizeOfBlock) {
		reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + size_t(modulePtr));
		if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0)
			break;

		size_t entriesNum = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		size_t page = reloc->VirtualAddress;

		BASE_RELOCATION_ENTRY* entry = (BASE_RELOCATION_ENTRY*)(size_t(reloc) + sizeof(IMAGE_BASE_RELOCATION));
		for (size_t i = 0; i < entriesNum; i++) {
			size_t offset = entry->Offset;
			size_t type = entry->Type;
			size_t reloc_field = page + offset;
			if (entry == NULL || type == 0)
				break;
			if (type != RELOC_32BIT_FIELD) {
				LOGE("Not supported relocations format at %d: %d", (int)i, (int)type);
				return false;
			}
			if (reloc_field >= moduleSize) {
				LOGE("Out of Bound Field: %lx", reloc_field);
				return false;
			}

			size_t* relocateAddr = (size_t*)(size_t(modulePtr) + reloc_field);
			LOGD("Apply Reloc Field at %x", relocateAddr);
			(*relocateAddr) = ((*relocateAddr) - oldBase + newBase);
			entry = (BASE_RELOCATION_ENTRY*)(size_t(entry) + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	return (parsedSize != 0);
}

void Util::masqueradeCmdline(const wchar_t* cmdline)
{
	if (!cmdline) return;
	auto sz_wcmdline = std::wstring(cmdline);

	// 
	sz_masqCmd_Widh = new wchar_t[sz_wcmdline.size() + 1];
	lstrcpyW(sz_masqCmd_Widh, sz_wcmdline.c_str());

	//
	auto k = std::string(sz_wcmdline.begin(), sz_wcmdline.end());
	sz_masqCmd_Ansi = new char[k.size() + 1];
	lstrcpyA(sz_masqCmd_Ansi, k.c_str());

	wchar_t** szArglist = CommandLineToArgvW(cmdline, &int_masqCmd_Argc);
	for (size_t i = 0; i < int_masqCmd_Argc; i++) {
		sz_masqCmd_ArgvWidh[i] = new wchar_t[lstrlenW(szArglist[i]) + 1];
		lstrcpyW(sz_masqCmd_ArgvWidh[i], szArglist[i]);

		auto b = std::string(std::wstring(sz_masqCmd_ArgvWidh[i]).begin(), std::wstring(sz_masqCmd_ArgvWidh[i]).end());
		sz_masqCmd_ArgvAnsi[i] = new char[b.size() + 1];
		lstrcpyA(sz_masqCmd_ArgvAnsi[i], b.c_str());
	}

	hijackCmdline = true;
}

int __wgetmainargs(int* _Argc, wchar_t*** _Argv, wchar_t*** _Env, int _useless_, void* _useless)
{
	*_Argc = int_masqCmd_Argc;
	*_Argv = (wchar_t**)sz_masqCmd_ArgvWidh;
	return 0;
}
int __getmainargs(int* _Argc, char*** _Argv, char*** _Env, int _useless_, void* _useless)
{
	*_Argc = int_masqCmd_Argc;
	*_Argv = (char**)sz_masqCmd_ArgvAnsi;
	return 0;
}

bool Util::fixIAT(PVOID modulePtr)
{
	LOGD("Fix Import Address Table");
	IMAGE_DATA_DIRECTORY* importsDir = getPeDir(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (importsDir == NULL) return false;

	size_t maxSize = importsDir->Size;
	size_t impAddr = importsDir->VirtualAddress;

	IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
	size_t parsedSize = 0;

	for (; parsedSize < maxSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;
		LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
		LOGD("Import DLL: %s", lib_name);

		size_t call_via = lib_desc->FirstThunk;
		size_t thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

		size_t offsetField = 0;
		size_t offsetThunk = 0;
		while (true)
		{
			IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
			IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);
			PIMAGE_THUNK_DATA  import_Int = (PIMAGE_THUNK_DATA)(lib_desc->OriginalFirstThunk + size_t(modulePtr));

			if (import_Int->u1.Ordinal & 0x80000000) {
				//Find Ordinal Id
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), (char*)(orginThunk->u1.Ordinal & 0xFFFF));
				LOGD("- API %x at %x", orginThunk->u1.Ordinal, addr);
				fieldThunk->u1.Function = addr;

			}

			if (fieldThunk->u1.Function == NULL) break;

			if (fieldThunk->u1.Function == orginThunk->u1.Function) {

				PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);
				if (orginThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) return false;

				LPSTR func_name = (LPSTR)by_name->Name;
				size_t addr = (size_t)GetProcAddress(LoadLibraryA(lib_name), func_name);
				LOGD("- API %s at %x", func_name, addr);

				if (hijackCmdline && _strcmpi(func_name, "GetCommandLineA") == 0)
					fieldThunk->u1.Function = (size_t)hookGetCommandLineA;
				else if (hijackCmdline && _strcmpi(func_name, "GetCommandLineW") == 0)
					fieldThunk->u1.Function = (size_t)hookGetCommandLineW;
				else if (hijackCmdline && _strcmpi(func_name, "__wgetmainargs") == 0)
					fieldThunk->u1.Function = (size_t)__wgetmainargs;
				else if (hijackCmdline && _strcmpi(func_name, "__getmainargs") == 0)
					fieldThunk->u1.Function = (size_t)__getmainargs;
				else
					fieldThunk->u1.Function = addr;

			}
			offsetField += sizeof(IMAGE_THUNK_DATA);
			offsetThunk += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return true;
}