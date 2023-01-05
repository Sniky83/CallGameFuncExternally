#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <sstream>

#pragma region Consts
CONST int SIZEOF_RELATIVE_ADDR_CALL = 4;
CONST int SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION = 5;
CONST int SIZEOF_END_SHELLCODE = 4;
#pragma endregion

#pragma region Enums
enum INSTRUCTION {
	CALL = 0xE8,
	PUSH = 0x68
};
#pragma endregion

#pragma region End APP
void PrintEndOfProgram()
{
	std::cout << "Press ENTER to close APP...\n";
	int res = getchar();
	exit(-1);
}
#pragma endregion

#pragma region Find Process
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
#pragma endregion

#pragma region Memory
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
	memcpy(shellcode + sizeofFuncHeaders, relativeAddressArray, SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION);
	// Copy the elements of closeShellcode to the end of shellcode
	memcpy(shellcode + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION + sizeofFuncHeaders, endShellcode, sizeof(endShellcode));

	return shellcode;
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

void CloseProperly(HANDLE hProcess, HANDLE hThread, LPVOID pRemoteBuffer, unsigned char* finalAddrBytes = NULL, unsigned char* shellcode = NULL)
{
	// Wait for the remote thread to finish execution
	WaitForSingleObject(hThread, INFINITE);
	// Free the allocated memory and close handles
	VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	delete[] finalAddrBytes;
	delete[] shellcode;
}
#pragma endregion

#pragma region Adresses Manipulation
DWORD GetAddrLittleIndian(DWORD addr) {
	unsigned char* char_array = (unsigned char*)&addr;
	std::reverse(char_array, char_array + sizeof(DWORD));

	return addr;
}

DWORD GetRelativeAddr(LPVOID pRemoteBuffer, DWORD callAddress, const int sizeofFuncHeaders)
{
	DWORD targetFunctionAddress = (DWORD)pRemoteBuffer;
	DWORD relativeAddress = (callAddress - targetFunctionAddress - sizeofFuncHeaders - 5);

	DWORD relativeAddressArray = GetAddrLittleIndian(relativeAddress);

	return relativeAddressArray;
}

unsigned char* GetFinalAddrWithInstruction(DWORD addr, INSTRUCTION instruction, bool isReverse = true)
{
	unsigned char* addrWithFirstByteArray = new unsigned char[SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION];

	addrWithFirstByteArray[0] = instruction;
	std::memcpy(addrWithFirstByteArray + 1, &addr, sizeof addr);

	if (isReverse)
	{
		std::reverse(addrWithFirstByteArray + 1, addrWithFirstByteArray + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION);
	}

	return addrWithFirstByteArray;
}
#pragma endregion

#pragma region Create Calling Game Funcs
void CallGameFunc(HANDLE hProcess, unsigned char* funcHeaders, DWORD callAddress, const int sizeofFuncHeaders, const int nbArgsPushed = 1)
{
	const int sizeofShellcode = sizeofFuncHeaders + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION + SIZEOF_END_SHELLCODE;

	LPVOID pRemoteBuffer = VirtualAllocation(hProcess, sizeofShellcode);

	DWORD relativeAddrBytes = GetRelativeAddr(pRemoteBuffer, callAddress, sizeofFuncHeaders);
	unsigned char* finalAddrBytes = GetFinalAddrWithInstruction(relativeAddrBytes, INSTRUCTION::CALL);

	unsigned char* shellcode = CreateShellcode(funcHeaders, finalAddrBytes, sizeofShellcode, sizeofFuncHeaders, nbArgsPushed, true);

	WriteShellcodeInMemory(hProcess, pRemoteBuffer, shellcode, sizeofShellcode);

	HANDLE hThread = CreateRemThread(hProcess, pRemoteBuffer);

	CloseProperly(hProcess, hThread, pRemoteBuffer, finalAddrBytes, shellcode);
}

template<typename... Args>
void MultipleCallGameFunc(HANDLE hProcess, DWORD* callAddressesArray, const int sizeofArray, int* sizeofArrays, int* nbArgsPushedArray, Args... shellcodeHeaders)
{
	int sizeofWholeShellcode = 0;

	//Start at one to not take sizeofCalls
	for (int i = 1; i < sizeofArray; i++)
	{
		sizeofWholeShellcode += (sizeofArrays[i] + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION + SIZEOF_END_SHELLCODE);
	}

	LPVOID pRemoteBuffer = VirtualAllocation(hProcess, sizeofWholeShellcode);

	unsigned char* shellcode = NULL;

	bool isRet = false;

	int i = 0;

	int sizeofCallAddressArray = sizeofArrays[0];

	char* pRemoteBufferOffset = (char*)pRemoteBuffer;

	int sizeofCurrentAndPrecedentFunc = 0;

	for (unsigned char* shellcodeHeadersArray : { shellcodeHeaders... }) {
		int sizeofCurrentShellcode = sizeofArrays[i + 1] + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION + SIZEOF_END_SHELLCODE;
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
				int sizeofPrecedentShellcode = sizeofArrays[x] + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION + SIZEOF_END_SHELLCODE;

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
			int sizeofPrecedentShellcode = sizeofArrays[i] + SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION + SIZEOF_END_SHELLCODE;
			pRemoteBufferOffset += sizeofPrecedentShellcode;
		}

		DWORD relativeAddrBytes = GetRelativeAddr(pRemoteBuffer, callAddressesArray[i], sizeofCurrentAndPrecedentFunc);
		unsigned char* finalAddrBytes = GetFinalAddrWithInstruction(relativeAddrBytes, INSTRUCTION::CALL);

		shellcode = CreateShellcode(shellcodeHeadersArray, finalAddrBytes, sizeofCurrentShellcode, sizeofCurrentFuncHeader, nbArgsPushedArray[i], isRet);

		WriteShellcodeInMemory(hProcess, pRemoteBufferOffset, shellcode, sizeofCurrentShellcode);

		delete[] finalAddrBytes;
		delete[] shellcode;

		i++;
	}

	HANDLE hThread = CreateRemThread(hProcess, pRemoteBuffer);

	CloseProperly(hProcess, hThread, pRemoteBuffer);
}
#pragma endregion

#pragma region Game Funcs To Call
/// <summary>
/// Call the console func to write message in the game
/// Multiple call with malloc + console func
/// </summary>
/// <param name="hProcess"></param>
void MultipleCallPrintConsoleFunc(HANDLE hProcess)
{
	// Header for malloc func (param)
	unsigned char mallocHeader[] = {
		0x6A, 0x0A
	};

	// Header for printConsoleHeader func param and stuff
	unsigned char printConsoleHeader[] = {
		0x89, 0xC3, 0xC6, 0x03, 0x49, 0xC6, 0x43, 0x01, 0x4E, 0xC6, 0x43, 0x02, 0x4A, 0xC6, 0x43, 0x03, 0x45, 0xC6, 0x43, 0x04, 0x43, 0xC6, 0x43, 0x05, 0x54, 0xC6, 0x43, 0x06, 0x49, 0xC6, 0x43, 0x07, 0x4F, 0xC6, 0x43, 0x08, 0x4E, 0xC6, 0x43, 0x09, 0x21, 0x53
	};

	// Number of args pushed to the stack by calling array
	int nbArgsPushedArray[] = {
		1,
		1
	};

	// This addr changes so you have to find it to use correctly this method
	// This was an example so you can make whatever you want 
	DWORD mallocAddrFunc = 0x769C74F0;
	// This is the game function I want to call
	DWORD printConsoleAddrFunc = 0x004DAD50;

	// Addresses array of all my addr I want to call
	DWORD callAddressesArray[] = {
		mallocAddrFunc,
		printConsoleAddrFunc
	};

	// Sizeof call addr array with my headers
	int sizeofArrays[] = {
		sizeof callAddressesArray / sizeof callAddressesArray[0],
		sizeof mallocHeader,
		sizeof printConsoleHeader
	};

	// Sizeof my size array to get the number of elements in it
	int sizeofArray = sizeof sizeofArrays / sizeof sizeofArrays[0];

	// Fill the func with everything to call multiple func in my game
	MultipleCallGameFunc(hProcess, callAddressesArray, sizeofArray, sizeofArrays, nbArgsPushedArray, mallocHeader, printConsoleHeader);
}

/// <summary>
/// Also calling the console func to write message in the game
/// Instead of malloc I allocated memory outside my shellcode
/// Which is cleaner and easier to do
/// </summary>
/// <param name="hProcess"></param>
void SingleCallPrintConsoleFunc(HANDLE hProcess)
{
	// Allocate new memory space to store a message in it
	const char* message = "PRINT CONSOLE FUNC CALLED WITHOUT DLL !";
	LPVOID pMessageBuffer = VirtualAllocation(hProcess, strlen(message));
	WriteProcessMemory(hProcess, pMessageBuffer, message, strlen(message), NULL);

	// Addr of my game func to call
	DWORD printConsoleFunc = 0x004DAD50;
	// Push addr of my message into the stack
	unsigned char* finalAddrPushArgPrintConsole = GetFinalAddrWithInstruction((DWORD)pMessageBuffer, INSTRUCTION::PUSH, false);
	// Sending my push instruction with addr of my message with the addr of printConsoleFunc to call it after the push bytes code
	CallGameFunc(hProcess, finalAddrPushArgPrintConsole, printConsoleFunc, SIZEOF_RELATIVE_ADDR_CALL_WITH_INSTRUCTION);

	// Release memory to avoid leaks
	VirtualFreeEx(hProcess, pMessageBuffer, 0, MEM_RELEASE);
	delete[] finalAddrPushArgPrintConsole;
}
#pragma endregion

int main()
{
	const char* processName = "ac_client.exe";
	HANDLE hProcess = OpenProc(processName);

	//CallPrintConsoleFunc(hProcess);
	SingleCallPrintConsoleFunc(hProcess);

	std::cout << "Injection ended successfully.\n\n";

	PrintEndOfProgram();
}