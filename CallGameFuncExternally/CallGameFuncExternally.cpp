#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <sstream>

// 1 byte for the call instruction and 4 bytes for the addr
CONST int SIZEOF_RELATIVE_ADDR_CALL = 5;
CONST int SIZEOF_END_SHELLCODE = 4;

#pragma region STATIC
void PrintEndOfProgram()
{
	std::cout << "Press ENTER to close APP...\n";
	int res = getchar();
	exit(-1);
}

DWORD GetProcessId(const char* processName)
{
	DWORD pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 process;
	process.dwSize = sizeof(process);
	if (Process32First(snapshot, &process)) {
		do {
			if (strcmp(process.szExeFile, processName) == 0) {
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	if (pid == NULL) {
		std::cout << "Error: Unable to find process id.\n";
		PrintEndOfProgram();
	}

	return pid;
}

HANDLE OpenProc(const char* processName)
{
	DWORD pid = GetProcessId(processName);

	// Get handle to target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProcess == NULL) {
		std::cout << "Error: Unable to open process.\n";
		PrintEndOfProgram();
	}

	return hProcess;
}

void CloseProperly(HANDLE hProcess, HANDLE hThread, LPVOID pRemoteBuffer, unsigned char* shellcode)
{
	// Wait for the remote thread to finish execution
	WaitForSingleObject(hThread, INFINITE);
	// Free the allocated memory and close handles
	VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	free(shellcode);
}

LPVOID VirtualAllocation(HANDLE hProcess, const int sizeofShellcode)
{
	// Allocate memory in target process for shellcode
	LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, sizeofShellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (pRemoteBuffer == NULL) {
		std::cout << "Error: Unable to allocate memory.\n";
		PrintEndOfProgram();
	}

	return pRemoteBuffer;
}

void WriteShellcodeInMemory(HANDLE hProcess, LPVOID pRemoteBuffer, unsigned char* shellcode, const int sizeofShellcode)
{
	// Write shellcode to target process
	if (!WriteProcessMemory(hProcess, pRemoteBuffer, shellcode, sizeofShellcode, NULL)) {
		std::cout << "Error: Unable to write shellcode.\n";
		PrintEndOfProgram();
	}
}

HANDLE CreateRemThread(HANDLE hProcess, LPVOID pRemoteBuffer)
{
	// Create a remote thread in the target process to execute the shellcode
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);

	if (hThread == NULL) {
		std::cout << "Error: Unable to create remote thread.\n";
		PrintEndOfProgram();
	}

	return hThread;
}
#pragma endregion

unsigned char* GetRelativeAddr(LPVOID pRemoteBuffer, DWORD callAddress, const int sizeofFuncHeaders)
{
	DWORD targetFunctionAddress = (DWORD)pRemoteBuffer;
	DWORD relativeAddress = (callAddress - targetFunctionAddress - sizeofFuncHeaders - 5);

	std::stringstream stream;
	stream << std::hex << relativeAddress;
	std::string hexString(stream.str());

	std::vector<unsigned char> hexBytes;

	hexBytes.push_back(static_cast<unsigned char>(0xE8));

	for (int i = 0; i < hexString.size(); i += 2) {
		unsigned long byte = std::stoul(hexString.substr(i, 2), nullptr, 16);
		hexBytes.push_back(static_cast<unsigned char>(byte));
	}

	// start at index one to place E8 (call) instruction first
	std::reverse(hexBytes.begin() + 1, hexBytes.end());

	// 4 bytes for Calling addr
	unsigned char* relativeAddressArray = new unsigned char[SIZEOF_RELATIVE_ADDR_CALL];
	std::copy(hexBytes.begin(), hexBytes.end(), relativeAddressArray);

	return relativeAddressArray;
}

unsigned char* CreateShellcode(unsigned char* shellcodeHeadersArray, unsigned char* relativeAddressArray, const int sizeofShellcode, const int sizeofFuncHeaders, int nbArgsPushed = 1, bool isRet = true)
{
	int clearStackArgs = (4 * nbArgsPushed);
	int retVal = (isRet == true ? 0xC3 : 0x90);

	unsigned char endShellcode[] = {
		0x83, 0xC4, clearStackArgs, // add esp, (4 x nbArgs)
		retVal // ret or nop
	};

	// Create a new dynamic character array to hold the shellcode
	unsigned char* shellcode = new unsigned char[sizeofShellcode];

	// Copy the elements of startShellcode to the beginning of shellcode
	memcpy(shellcode, shellcodeHeadersArray, sizeofFuncHeaders);
	// Copy the elements of relativeAddressArr to the end of shellcode
	memcpy(shellcode + sizeofFuncHeaders, relativeAddressArray, SIZEOF_RELATIVE_ADDR_CALL);
	// Copy the elements of closeShellcode to the end of shellcode
	memcpy(shellcode + SIZEOF_RELATIVE_ADDR_CALL + sizeofFuncHeaders, endShellcode, sizeof(endShellcode));

	return shellcode;
}

void CallGameFunc(HANDLE hProcess, unsigned char* funcHeaders, DWORD callAddress, const int sizeofFuncHeaders, const int nbArgsPushed = 1)
{
	const int sizeofShellcode = sizeofFuncHeaders + SIZEOF_RELATIVE_ADDR_CALL + SIZEOF_END_SHELLCODE;

	LPVOID pRemoteBuffer = VirtualAllocation(hProcess, sizeofShellcode);

	unsigned char* relativeAddrBytes = GetRelativeAddr(pRemoteBuffer, callAddress, sizeofFuncHeaders);

	unsigned char* shellcode = CreateShellcode(funcHeaders, relativeAddrBytes, sizeofShellcode, sizeofFuncHeaders, nbArgsPushed, true);

	WriteShellcodeInMemory(hProcess, pRemoteBuffer, shellcode, sizeofShellcode);

	HANDLE hThread = CreateRemThread(hProcess, pRemoteBuffer);

	CloseProperly(hProcess, hThread, pRemoteBuffer, shellcode);
}

template<typename... Args>
void MultipleCallGameFunc(HANDLE hProcess, DWORD* callAddressesArray, const int sizeofArray, int* sizeofArrays, int* nbArgsPushedArray, unsigned char* headersArray, Args... shellcodeHeaders)
{
	int sizeofWholeShellcode = 0;

	//Start at one to not take sizeofCalls
	for (int i = 1; i < sizeofArray; i++)
	{
		sizeofWholeShellcode += (sizeofArrays[i] + SIZEOF_RELATIVE_ADDR_CALL + SIZEOF_END_SHELLCODE);
	}

	LPVOID pRemoteBuffer = VirtualAllocation(hProcess, sizeofWholeShellcode);

	unsigned char* shellcode = NULL;

	bool isRet = false;

	int i = 0;

	int sizeofCallAddressArray = sizeofArrays[0];

	char* pRemoteBufferOffset = (char*)pRemoteBuffer;

	int sizeofCurrentAndPrecedentFunc = 0;

	for (unsigned char* shellcodeHeadersArray : { shellcodeHeaders... }) {
		int sizeofCurrentShellcode = sizeofArrays[i + 1] + SIZEOF_RELATIVE_ADDR_CALL + SIZEOF_END_SHELLCODE;
		int sizeofCurrentFuncHeader = sizeofArrays[i + 1];

		if (i == 0)
		{
			sizeofCurrentAndPrecedentFunc += sizeofArrays[i + 1];
		}
		else
		{
			sizeofCurrentAndPrecedentFunc = 0;

			for (int x = 1; x < (i + 1); x++)
			{
				int sizeofPrecedentShellcode = sizeofArrays[x] + SIZEOF_RELATIVE_ADDR_CALL + SIZEOF_END_SHELLCODE;

				if ((x + 1) < i)
				{
					sizeofCurrentAndPrecedentFunc += sizeofPrecedentShellcode;
				}
				else
				{
					sizeofCurrentAndPrecedentFunc += (sizeofPrecedentShellcode + sizeofArrays[x + 1]);
				}
			}
		}

		if ((i + 1) == sizeofCallAddressArray)
		{
			isRet = true;
		}

		if (i > 0)
		{
			int sizeofPrecedentShellcode = sizeofArrays[i] + SIZEOF_RELATIVE_ADDR_CALL + SIZEOF_END_SHELLCODE;
			pRemoteBufferOffset += sizeofPrecedentShellcode;
		}

		unsigned char* relativeAddrBytes = GetRelativeAddr(pRemoteBuffer, callAddressesArray[i], sizeofCurrentAndPrecedentFunc);

		shellcode = CreateShellcode(shellcodeHeadersArray, relativeAddrBytes, sizeofCurrentShellcode, sizeofCurrentFuncHeader, nbArgsPushedArray[i], isRet);

		WriteShellcodeInMemory(hProcess, pRemoteBufferOffset, shellcode, sizeofCurrentShellcode);

		i++;
	}

	HANDLE hThread = CreateRemThread(hProcess, pRemoteBuffer);

	CloseProperly(hProcess, hThread, pRemoteBuffer, shellcode);
}

void CallPrintConsoleFunc(HANDLE hProcess)
{
	unsigned char mallocHeader[] = {
		0x6A, 0x0A
	};

	unsigned char printConsoleHeader[] = {
		0x89, 0xC3, 0xC6, 0x03, 0x49, 0xC6, 0x43, 0x01, 0x4E, 0xC6, 0x43, 0x02, 0x4A, 0xC6, 0x43, 0x03, 0x45, 0xC6, 0x43, 0x04, 0x43, 0xC6, 0x43, 0x05, 0x54, 0xC6, 0x43, 0x06, 0x49, 0xC6, 0x43, 0x07, 0x4F, 0xC6, 0x43, 0x08, 0x4E, 0xC6, 0x43, 0x09, 0x21, 0x53
	};

	unsigned char headersArray[] = {
		*mallocHeader,
		*printConsoleHeader
	};

	int nbArgsPushedArray[] = {
		1,
		1
	};

	//int* mallocAddr = (int*)malloc(sizeof(int));
	//DWORD mallocAddrFunc = (DWORD)mallocAddr;

	DWORD mallocAddrFunc = 0x769C74F0;
	DWORD printConsoleFunc = 0x004DAD50;

	DWORD callAddressesArray[] = {
		mallocAddrFunc,
		printConsoleFunc
	};

	int sizeofArrays[] = {
		sizeof callAddressesArray / sizeof callAddressesArray[0],
		sizeof mallocHeader,
		sizeof printConsoleHeader
	};

	int sizeofArray = sizeof sizeofArrays / sizeof sizeofArrays[0];

	MultipleCallGameFunc(hProcess, callAddressesArray, sizeofArray, sizeofArrays, nbArgsPushedArray, headersArray, mallocHeader, printConsoleHeader);
}

void CallSinglePrintConsole(HANDLE hProcess)
{
	DWORD printConsoleFunc = 0x004DAD50;

	unsigned char printConsoleHeader[] = {
		0x68, 0xE4, 0xA8, 0x55, 0x00
	};

	CallGameFunc(hProcess, printConsoleHeader, printConsoleFunc, sizeof printConsoleHeader);
}

int main()
{
	const char* processName = "ac_client.exe";
	HANDLE hProcess = OpenProc(processName);

	CallPrintConsoleFunc(hProcess);
	//CallSinglePrintConsole(hProcess);

	std::cout << "Injection ended successfully.\n\n";

	PrintEndOfProgram();
}