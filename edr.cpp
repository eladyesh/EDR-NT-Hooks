#include <iostream>
#include <Windows.h>
#include <psapi.h>
#include <tchar.h>


std::string GetModuleNameFromAddress(void* address)
{
	std::string moduleName;
	HMODULE hModule = NULL;
	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)address, &hModule))
	{
		TCHAR szModuleName[MAX_PATH];
		if (GetModuleFileNameEx(GetCurrentProcess(), hModule, szModuleName, sizeof(szModuleName) / sizeof(TCHAR)))
		{
#ifdef UNICODE
			std::wstring wszModuleName(szModuleName);
			moduleName = std::string(wszModuleName.begin(), wszModuleName.end());
#else
			moduleName = szModuleName;
#endif
		}
	}
	return moduleName;
}

int main()
{
	PDWORD functionAddress = (PDWORD)0;

	HMODULE libraryBase = LoadLibraryA("ntdll");

	// Base of image_dos_header --> ntdll
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	// Go to the Export Directory
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	// Start iteration over IAT
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++)
	{
		// Functions Names
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		
		// Function Addresses
		DWORD_PTR functionAddressRVA = 0;
		functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
		
		// SYS paralogue stub
		unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

		// Check for Nt or Zw
		if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
		{	
			// Not the regular 4 bytes, potentially hooked by the EDR system
			if (memcmp(functionAddress, syscallPrologue, 4) != 0) {
				
				// Check for the jmp instruction. First byte --> 0xE9
				if (*((unsigned char*)functionAddress) == 0xE9)
				{
					// Check for a relative jump instruction at the beginning of a function, and retrieves information about the module that contains the destination address of the jump.
					// The second line retrieves the signed offset value that specifies the change in the program counter, by reading the next 4 bytes after the jmp instruction
					DWORD jumpTargetRelative = *((PDWORD)((char*)functionAddress + 1));

					// Calculate the destination address of the jump by adding the offset to the address of the jmp instruction (which is functionAddress + 5) and stores the result in the variable jumpTarget.
					PDWORD jumpTarget = functionAddress + 5 + jumpTargetRelative;

					// Meaning --> The change in program counter + the jmp address ==> Destination

					// Name of module
					std::string moduleName = GetModuleNameFromAddress(jumpTarget);
					printf("Hooked: %s : %p into module %s\n", functionName, functionAddress, moduleName.c_str());
				}
				else
				{
					// Hooked by the EDR system, without jmp instruction
					printf("Potentially hooked: %s : %p\n", functionName, functionAddress);
				}

			}
		}
	}

	return 0;
}
