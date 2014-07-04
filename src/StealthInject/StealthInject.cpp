#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define INJECTOR_MAGIC 0x40ADAD40

IMAGE_DOS_HEADER _mainDosHeader;
IMAGE_NT_HEADERS _mainNtHeaders;

IMAGE_DOS_HEADER _injectingDosHeader;
IMAGE_NT_HEADERS32 _injectingNtHeaders;

IMAGE_DOS_HEADER* _injectedDosHeader;
IMAGE_NT_HEADERS32* _injectedNtHeaders;

char* _dllData;
char* _dllStart;
DWORD _pid;

HMODULE GetRemoteModuleHandle(HANDLE hProcess, const char* module)
{
	// Main DLL we will need to load
	HMODULE kernel32	= NULL;

	// Main functions we will need to import
	FARPROC loadlibrary		= NULL;
	FARPROC getprocaddress	= NULL;
	FARPROC exitprocess		= NULL;
	FARPROC exitthread		= NULL;
	FARPROC freelibraryandexitthread = NULL;

	// The workspace we will build the code cave on locally
	LPBYTE workspace		= NULL;
	DWORD workspaceIndex	= 0;

	// The memory in the process we write to
	LPVOID codecaveAddress	= NULL;
	DWORD dwCodecaveAddress = 0;

	// Strings we have to write into the process
	char procName[MAX_PATH + 1]	= {0};
	char injectError0[MAX_PATH + 1]		= {0};
	char injectError1[MAX_PATH + 1]		= {0};
	char injectError2[MAX_PATH + 1]		= {0};
	char user32Name[MAX_PATH + 1]		= {0};
	char msgboxName[MAX_PATH + 1]		= {0};

	// Placeholder addresses to use the strings
	DWORD user32NameAddr	= 0;
	DWORD user32Addr		= 0;
	DWORD msgboxNameAddr	= 0;
	DWORD msgboxAddr		= 0;
	DWORD dllAddr			= 0;
	DWORD dllNameAddr		= 0;
	DWORD funcNameAddr		= 0;
	DWORD error0Addr		= 0;
	DWORD error1Addr		= 0;
	DWORD error2Addr		= 0;
	FARPROC getModuleHandleAddr = 0;

	// Where the codecave execution should begin at
	DWORD codecaveExecAddr = 0;

	// Handle to the thread we create in the process
	HANDLE hThread = NULL;

	// Temp variables
	DWORD dwTmpSize = 0;

	// Old protection on page we are writing to in the process and the bytes written
	DWORD oldProtect	= 0;	
	DWORD bytesRet		= 0;

	// Get the address of the main DLL
	kernel32	= LoadLibrary("kernel32.dll");

	// Get our functions
	loadlibrary		= GetProcAddress(kernel32,	"LoadLibraryA");
	getprocaddress	= GetProcAddress(kernel32,	"GetProcAddress");
	exitthread		= GetProcAddress(kernel32,	"ExitThread");
	getModuleHandleAddr = GetProcAddress(kernel32, "GetModuleHandleA");

	// Build names
	_snprintf(procName, MAX_PATH, "%s", module);
	_snprintf(user32Name, MAX_PATH, "user32.dll");
	_snprintf(msgboxName, MAX_PATH, "MessageBoxA");

	// Build error messages
	_snprintf(injectError0, MAX_PATH, "Error");

	// Create the workspace
	workspace = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);

	// Allocate space for the codecave in the process
	codecaveAddress = VirtualAllocEx(hProcess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	dwCodecaveAddress = PtrToUlong(codecaveAddress);

	// Write out the address for the user32 dll address
	user32Addr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// Write out the address for the MessageBoxA address
	msgboxAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// Write out the address for the injected DLL's module
	dllAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// User32 Dll Name
	user32NameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(user32Name) + 1;
	memcpy(workspace + workspaceIndex, user32Name, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// MessageBoxA name
	msgboxNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(msgboxName) + 1;
	memcpy(workspace + workspaceIndex, msgboxName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Dll Name
	dllNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(procName) + 1;
	memcpy(workspace + workspaceIndex, procName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Pad a few INT3s after string data is written for seperation
	workspace[workspaceIndex++] = 0xCC;
	workspace[workspaceIndex++] = 0xCC;
	workspace[workspaceIndex++] = 0xCC;

	// Store where the codecave execution should begin
	codecaveExecAddr = workspaceIndex + dwCodecaveAddress;

	if (module)
	{
		//PUSH dllNameAddr
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &dllNameAddr, 4);
		workspaceIndex += 4;
	}
	else
	{
		//PUSH 0
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;
	}

	// MOV EAX, ADDRESS - Move the address of GetProcAddress into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &getModuleHandleAddr, 4);
	workspaceIndex += 4;

	// CALL EAX - Call getModuleHandle
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

	// ExitProcess
	// Push eax (proc address)
	workspace[workspaceIndex++] = 0x50;

	// MOV EAX, ADDRESS - Move the address of ExitThread into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &exitthread, 4);
	workspaceIndex += 4;

	// CALL EAX - Call ExitThread
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

	VirtualProtectEx(hProcess, codecaveAddress, workspaceIndex, PAGE_EXECUTE_READWRITE, &oldProtect);

	// Write out the patch
	WriteProcessMemory(hProcess, codecaveAddress, workspace, workspaceIndex, &bytesRet);

	// Restore page protection
	VirtualProtectEx(hProcess, codecaveAddress, workspaceIndex, oldProtect, &oldProtect);

	// Make sure our changes are written right away
	FlushInstructionCache(hProcess, codecaveAddress, workspaceIndex);

	// Free the workspace memory
	HeapFree(GetProcessHeap(), 0, workspace);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((void*)codecaveExecAddr), 0, 0, NULL);
	WaitForSingleObject(hThread, INFINITE); 

	DWORD address;
	GetExitCodeThread(hThread, &address);

	// Free the memory in the process that we allocated
	VirtualFreeEx(hProcess, codecaveAddress, 0, MEM_RELEASE);
	return (HMODULE)address;
}

FARPROC RemoteGetProcAddress(HANDLE hProcess, HMODULE hModule, const char* func)
{
	// Main DLL we will need to load
	HMODULE kernel32	= NULL;

	// Main functions we will need to import
	FARPROC loadlibrary		= NULL;
	FARPROC getprocaddress	= NULL;
	FARPROC exitprocess		= NULL;
	FARPROC exitthread		= NULL;
	FARPROC freelibraryandexitthread = NULL;

	// The workspace we will build the code cave on locally
	LPBYTE workspace		= NULL;
	DWORD workspaceIndex	= 0;

	// The memory in the process we write to
	LPVOID codecaveAddress	= NULL;
	DWORD dwCodecaveAddress = 0;

	// Strings we have to write into the process
	char procName[MAX_PATH + 1]	= {0};
	char injectError0[MAX_PATH + 1]		= {0};
	char injectError1[MAX_PATH + 1]		= {0};
	char injectError2[MAX_PATH + 1]		= {0};
	char user32Name[MAX_PATH + 1]		= {0};
	char msgboxName[MAX_PATH + 1]		= {0};

	// Placeholder addresses to use the strings
	DWORD user32NameAddr	= 0;
	DWORD user32Addr		= 0;
	DWORD msgboxNameAddr	= 0;
	DWORD msgboxAddr		= 0;
	DWORD dllAddr			= 0;
	DWORD dllNameAddr		= 0;
	DWORD funcNameAddr		= 0;
	DWORD error0Addr		= 0;
	DWORD error1Addr		= 0;
	DWORD error2Addr		= 0;

	// Where the codecave execution should begin at
	DWORD codecaveExecAddr = 0;

	// Handle to the thread we create in the process
	HANDLE hThread = NULL;

	// Temp variables
	DWORD dwTmpSize = 0;

	// Old protection on page we are writing to in the process and the bytes written
	DWORD oldProtect	= 0;	
	DWORD bytesRet		= 0;

	// Get the address of the main DLL
	kernel32	= LoadLibrary("kernel32.dll");

	// Get our functions
	loadlibrary		= GetProcAddress(kernel32,	"LoadLibraryA");
	getprocaddress	= GetProcAddress(kernel32,	"GetProcAddress");
	exitthread		= GetProcAddress(kernel32,	"ExitThread");

	// Build names
	_snprintf(procName, MAX_PATH, "%s", func);
	_snprintf(user32Name, MAX_PATH, "user32.dll");
	_snprintf(msgboxName, MAX_PATH, "MessageBoxA");

	// Build error messages
	_snprintf(injectError0, MAX_PATH, "Error");

	// Create the workspace
	workspace = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);

	// Allocate space for the codecave in the process
	codecaveAddress = VirtualAllocEx(hProcess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	dwCodecaveAddress = PtrToUlong(codecaveAddress);

	// Write out the address for the user32 dll address
	user32Addr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// Write out the address for the MessageBoxA address
	msgboxAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// Write out the address for the injected DLL's module
	dllAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// User32 Dll Name
	user32NameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(user32Name) + 1;
	memcpy(workspace + workspaceIndex, user32Name, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// MessageBoxA name
	msgboxNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(msgboxName) + 1;
	memcpy(workspace + workspaceIndex, msgboxName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Dll Name
	dllNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(procName) + 1;
	memcpy(workspace + workspaceIndex, procName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Pad a few INT3s after string data is written for seperation
	workspace[workspaceIndex++] = 0xCC;
	workspace[workspaceIndex++] = 0xCC;
	workspace[workspaceIndex++] = 0xCC;

	// Store where the codecave execution should begin
	codecaveExecAddr = workspaceIndex + dwCodecaveAddress;

	//PUSH dllNameAddr
	workspace[workspaceIndex++] = 0x68;
	memcpy(workspace + workspaceIndex, &dllNameAddr, 4);
	workspaceIndex += 4;

	//PUSH hModule
	workspace[workspaceIndex++] = 0x68;
	memcpy(workspace + workspaceIndex, &hModule, 4);
	workspaceIndex += 4;

	// MOV EAX, ADDRESS - Move the address of GetProcAddress into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &getprocaddress, 4);
	workspaceIndex += 4;

	// CALL EAX - Call GetProcAddress
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

	// ExitProcess
	// Push eax (proc address)
	workspace[workspaceIndex++] = 0x50;

	// MOV EAX, ADDRESS - Move the address of ExitThread into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &exitthread, 4);
	workspaceIndex += 4;

	// CALL EAX - Call ExitThread
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

	VirtualProtectEx(hProcess, codecaveAddress, workspaceIndex, PAGE_EXECUTE_READWRITE, &oldProtect);

	// Write out the patch
	WriteProcessMemory(hProcess, codecaveAddress, workspace, workspaceIndex, &bytesRet);

	// Restore page protection
	VirtualProtectEx(hProcess, codecaveAddress, workspaceIndex, oldProtect, &oldProtect);

	// Make sure our changes are written right away
	FlushInstructionCache(hProcess, codecaveAddress, workspaceIndex);

	// Free the workspace memory
	HeapFree(GetProcessHeap(), 0, workspace);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((void*)codecaveExecAddr), 0, 0, NULL);
	WaitForSingleObject(hThread, INFINITE); 

	DWORD address;
	GetExitCodeThread(hThread, &address);

	// Free the memory in the process that we allocated
	VirtualFreeEx(hProcess, codecaveAddress, 0, MEM_RELEASE);
	return (FARPROC)address;
}

DWORD Inject(HANDLE hProcess, const char* dllname)
{
	// Main DLL we will need to load
	HMODULE kernel32	= NULL;

	// Main functions we will need to import
	FARPROC loadlibrary		= NULL;
	FARPROC getprocaddress	= NULL;
	FARPROC exitprocess		= NULL;
	FARPROC exitthread		= NULL;
	FARPROC freelibraryandexitthread = NULL;

	// The workspace we will build the code cave on locally
	LPBYTE workspace		= NULL;
	DWORD workspaceIndex	= 0;

	// The memory in the process we write to
	LPVOID codecaveAddress	= NULL;
	DWORD dwCodecaveAddress = 0;

	// Strings we have to write into the process
	char injectDllName[MAX_PATH + 1]	= {0};
	char injectFuncName[MAX_PATH + 1]	= {0};
	char injectError0[MAX_PATH + 1]		= {0};
	char injectError1[MAX_PATH + 1]		= {0};
	char injectError2[MAX_PATH + 1]		= {0};
	char user32Name[MAX_PATH + 1]		= {0};
	char msgboxName[MAX_PATH + 1]		= {0};

	// Placeholder addresses to use the strings
	DWORD user32NameAddr	= 0;
	DWORD user32Addr		= 0;
	DWORD msgboxNameAddr	= 0;
	DWORD msgboxAddr		= 0;
	DWORD dllAddr			= 0;
	DWORD dllNameAddr		= 0;
	DWORD funcNameAddr		= 0;
	DWORD error0Addr		= 0;
	DWORD error1Addr		= 0;
	DWORD error2Addr		= 0;

	// Where the codecave execution should begin at
	DWORD codecaveExecAddr = 0;

	// Handle to the thread we create in the process
	HANDLE hThread = NULL;

	// Temp variables
	DWORD dwTmpSize = 0;

	// Old protection on page we are writing to in the process and the bytes written
	DWORD oldProtect	= 0;	
	DWORD bytesRet		= 0;

	// Get the address of the main DLL
	kernel32	= LoadLibrary("kernel32.dll");

	// Get our functions
	loadlibrary		= GetProcAddress(kernel32,	"LoadLibraryA");
	getprocaddress	= GetProcAddress(kernel32,	"GetProcAddress");
	exitprocess		= GetProcAddress(kernel32,	"ExitProcess");
	exitthread		= GetProcAddress(kernel32,	"ExitThread");
	freelibraryandexitthread = GetProcAddress(kernel32,	"FreeLibraryAndExitThread");

	// Build names
	_snprintf(injectDllName, MAX_PATH, "%s", dllname);
	_snprintf(injectFuncName, MAX_PATH, "%s", "Initialize");
	_snprintf(user32Name, MAX_PATH, "user32.dll");
	_snprintf(msgboxName, MAX_PATH, "MessageBoxA");

	// Build error messages
	_snprintf(injectError0, MAX_PATH, "Error");
	_snprintf(injectError1, MAX_PATH, "Could not load the dll: %s", injectDllName);
	_snprintf(injectError2, MAX_PATH, "Could not load the function: %s", injectFuncName);

	// Create the workspace
	workspace = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);

	// Allocate space for the codecave in the process
	codecaveAddress = VirtualAllocEx(hProcess, 0, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	dwCodecaveAddress = PtrToUlong(codecaveAddress);

	// Write out the address for the user32 dll address
	user32Addr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// Write out the address for the MessageBoxA address
	msgboxAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// Write out the address for the injected DLL's module
	dllAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = 0;
	memcpy(workspace + workspaceIndex, &dwTmpSize, 4);
	workspaceIndex += 4;

	// User32 Dll Name
	user32NameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(user32Name) + 1;
	memcpy(workspace + workspaceIndex, user32Name, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// MessageBoxA name
	msgboxNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(msgboxName) + 1;
	memcpy(workspace + workspaceIndex, msgboxName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Dll Name
	dllNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(injectDllName) + 1;
	memcpy(workspace + workspaceIndex, injectDllName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Function Name
	funcNameAddr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(injectFuncName) + 1;
	memcpy(workspace + workspaceIndex, injectFuncName, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Error Message 1
	error0Addr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(injectError0) + 1;
	memcpy(workspace + workspaceIndex, injectError0, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Error Message 2
	error1Addr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(injectError1) + 1;
	memcpy(workspace + workspaceIndex, injectError1, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Error Message 3
	error2Addr = workspaceIndex + dwCodecaveAddress;
	dwTmpSize = (DWORD)strlen(injectError2) + 1;
	memcpy(workspace + workspaceIndex, injectError2, dwTmpSize);
	workspaceIndex += dwTmpSize;

	// Pad a few INT3s after string data is written for seperation
	workspace[workspaceIndex++] = 0xCC;
	workspace[workspaceIndex++] = 0xCC;
	workspace[workspaceIndex++] = 0xCC;

	// Store where the codecave execution should begin
	codecaveExecAddr = workspaceIndex + dwCodecaveAddress;

// User32 DLL Loading
	// PUSH 0x00000000 - Push the address of the DLL name to use in LoadLibraryA
	workspace[workspaceIndex++] = 0x68;
	memcpy(workspace + workspaceIndex, &user32NameAddr, 4);
	workspaceIndex += 4;

	// MOV EAX, ADDRESS - Move the address of LoadLibraryA into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &loadlibrary, 4);
	workspaceIndex += 4;

	// CALL EAX - Call LoadLibraryA
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

// MessageBoxA Loading
	// PUSH 0x000000 - Push the address of the function name to load
	workspace[workspaceIndex++] = 0x68;
	memcpy(workspace + workspaceIndex, &msgboxNameAddr, 4);
	workspaceIndex += 4;

	// Push EAX, module to use in GetProcAddress
	workspace[workspaceIndex++] = 0x50;

	// MOV EAX, ADDRESS - Move the address of GetProcAddress into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &getprocaddress, 4);
	workspaceIndex += 4;

	// CALL EAX - Call GetProcAddress
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

	// MOV [ADDRESS], EAX - Save the address to our variable
	workspace[workspaceIndex++] = 0xA3;
	memcpy(workspace + workspaceIndex, &msgboxAddr, 4);
	workspaceIndex += 4;

// DLL Loading
	// PUSH 0x00000000 - Push the address of the DLL name to use in LoadLibraryA
	workspace[workspaceIndex++] = 0x68;
	memcpy(workspace + workspaceIndex, &dllNameAddr, 4);
	workspaceIndex += 4;

	// MOV EAX, ADDRESS - Move the address of LoadLibraryA into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &loadlibrary, 4);
	workspaceIndex += 4;

	// CALL EAX - Call LoadLibraryA
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

// Error Checking
	// CMP EAX, 0
	workspace[workspaceIndex++] = 0x83;
	workspace[workspaceIndex++] = 0xF8;
	workspace[workspaceIndex++] = 0x00;

// JNZ EIP + 0x1E to skip over eror code
	workspace[workspaceIndex++] = 0x75;
	workspace[workspaceIndex++] = 0x1E;

// Error Code 1
	// MessageBox
		// PUSH 0x10 (MB_ICONHAND)
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x10;

		// PUSH 0x000000 - Push the address of the MessageBox title
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &error0Addr, 4);
		workspaceIndex += 4;

		// PUSH 0x000000 - Push the address of the MessageBox message
		workspace[workspaceIndex++] = 0x68;
		memcpy(workspace + workspaceIndex, &error1Addr, 4);
		workspaceIndex += 4;

		// Push 0
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;

		// MOV EAX, [ADDRESS] - Move the address of MessageBoxA into EAX
		workspace[workspaceIndex++] = 0xA1;
		memcpy(workspace + workspaceIndex, &msgboxAddr, 4);
		workspaceIndex += 4;

		// CALL EAX - Call MessageBoxA
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

// ExitProcess
		// Push 0
		workspace[workspaceIndex++] = 0x6A;
		workspace[workspaceIndex++] = 0x00;

		// MOV EAX, ADDRESS - Move the address of ExitProcess into EAX
		workspace[workspaceIndex++] = 0xB8;
		memcpy(workspace + workspaceIndex, &exitprocess, 4);
		workspaceIndex += 4;

		// CALL EAX - Call MessageBoxA
		workspace[workspaceIndex++] = 0xFF;
		workspace[workspaceIndex++] = 0xD0;

	// MOV [ADDRESS], EAX - Save the address to our variable
	workspace[workspaceIndex++] = 0xA3;
	memcpy(workspace + workspaceIndex, &dllAddr, 4);
	workspaceIndex += 4;

// ExitProcess
	// Push eax (library address)
	workspace[workspaceIndex++] = 0x50;

	// MOV EAX, ADDRESS - Move the address of ExitThread into EAX
	workspace[workspaceIndex++] = 0xB8;
	memcpy(workspace + workspaceIndex, &exitthread, 4);
	workspaceIndex += 4;

	// CALL EAX - Call ExitThread
	workspace[workspaceIndex++] = 0xFF;
	workspace[workspaceIndex++] = 0xD0;

	VirtualProtectEx(hProcess, codecaveAddress, workspaceIndex, PAGE_EXECUTE_READWRITE, &oldProtect);

	// Write out the patch
	WriteProcessMemory(hProcess, codecaveAddress, workspace, workspaceIndex, &bytesRet);

	// Restore page protection
	VirtualProtectEx(hProcess, codecaveAddress, workspaceIndex, oldProtect, &oldProtect);

	// Make sure our changes are written right away
	FlushInstructionCache(hProcess, codecaveAddress, workspaceIndex);

	// Free the workspace memory
	HeapFree(GetProcessHeap(), 0, workspace);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((void*)codecaveExecAddr), 0, 0, NULL);
	WaitForSingleObject(hThread, INFINITE); 

	DWORD address;
	GetExitCodeThread(hThread, &address);

	// Free the memory in the process that we allocated
	VirtualFreeEx(hProcess, codecaveAddress, 0, MEM_RELEASE);
	return address;
}

bool ReadMemory(HANDLE hProcess, LPVOID baseAddress, LPVOID buffer, int size)
{
	static DWORD bytesRead;
	return ReadProcessMemory(hProcess, baseAddress, buffer, size, &bytesRead) == TRUE;
}

bool WriteMemory(HANDLE hProcess, LPVOID baseAddress, LPVOID buffer, int size)
{
	static DWORD bytesWritten;
	return WriteProcessMemory(hProcess, baseAddress, buffer, size, &bytesWritten) == TRUE;
}

void LoadSections(HANDLE hProcess)
{
	IMAGE_SECTION_HEADER* sectionPointer = (IMAGE_SECTION_HEADER*)(_injectedNtHeaders + 1);
	IMAGE_SECTION_HEADER section;

	int uninitializedDataSize = _injectingNtHeaders.OptionalHeader.SizeOfUninitializedData;
	int initializedDataSize = _injectingNtHeaders.OptionalHeader.SizeOfInitializedData;

	for (int i = 0; i < _injectingNtHeaders.FileHeader.NumberOfSections; i++, sectionPointer++)
	{
		ReadMemory(hProcess, sectionPointer, &section, sizeof(IMAGE_SECTION_HEADER));

		int size;
		if (section.SizeOfRawData == 0)
		{
			if ((section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) == IMAGE_SCN_CNT_INITIALIZED_DATA)
				size = initializedDataSize;
			else if ((section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) == IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				size = uninitializedDataSize;
			else
				size = 0;
		}
		else
			size = section.SizeOfRawData;

		if (size == 0)
			continue;

		void* sectionAddress = _dllStart + section.VirtualAddress/*VirtualAlloc(_dllStart + section->VirtualAddress, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)*/;
		WriteMemory(hProcess, (DWORD)&section.Misc.PhysicalAddress - (DWORD)&section + (char*)sectionPointer, &sectionAddress, sizeof(DWORD));

		if (section.SizeOfRawData)
			WriteMemory(hProcess, sectionAddress, _dllData + section.PointerToRawData, size);
		else
		{
			char* dummy = new char[size];
			memset(dummy, 0, size);
			WriteMemory(hProcess, sectionAddress, dummy, size);
			delete[] dummy;
		}
	}
}

void Relocate(HANDLE hProcess, int delta)
{
	IMAGE_DATA_DIRECTORY* relocationDataDirectory = &_injectingNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (relocationDataDirectory->Size == 0)
		return;

	_IMAGE_BASE_RELOCATION* relocationPointer = (_IMAGE_BASE_RELOCATION*)(_dllStart + relocationDataDirectory->VirtualAddress);
	_IMAGE_BASE_RELOCATION relocation;
	ReadMemory(hProcess, relocationPointer, &relocation, sizeof(_IMAGE_BASE_RELOCATION));

	while (relocation.VirtualAddress)
	{
		char* destination = _dllStart + relocation.VirtualAddress;
		unsigned short* relocationInformationPointer = (unsigned short *)((char*)relocationPointer + sizeof(_IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < (relocation.SizeOfBlock - sizeof(_IMAGE_BASE_RELOCATION)) / 2; i++, relocationInformationPointer++) 
		{
			unsigned short relocationInformation;
			ReadMemory(hProcess, relocationInformationPointer, &relocationInformation, sizeof(unsigned short));

			//upper 4
			int type = relocationInformation >> 12;

			//lower 12
			int offset = relocationInformation & 0xFFF;

			switch (type)
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				{
					DWORD addr;
					DWORD* addrPointer = (DWORD*)(destination + offset);
					ReadMemory(hProcess, addrPointer, &addr, sizeof(DWORD));

					addr += delta;
					WriteMemory(hProcess, addrPointer, &addr, sizeof(DWORD));
					break;
				}
			default:
				break;
			}
		}

		relocationPointer = (_IMAGE_BASE_RELOCATION*)((char*)relocationPointer + relocation.SizeOfBlock);
		ReadMemory(hProcess, relocationPointer, &relocation, sizeof(_IMAGE_BASE_RELOCATION));
	}
}

void ResolveImports(HANDLE hProcess)
{
	char libraryName[MAX_PATH];

	IMAGE_DATA_DIRECTORY* relocationDataDirectory = &_injectingNtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (relocationDataDirectory->Size == 0)
		return;

	_IMAGE_IMPORT_DESCRIPTOR* importDescriptorPointer = (_IMAGE_IMPORT_DESCRIPTOR*)(_dllStart + relocationDataDirectory->VirtualAddress);
	_IMAGE_IMPORT_DESCRIPTOR importDescriptor;
	ReadMemory(hProcess, importDescriptorPointer, &importDescriptor, sizeof(_IMAGE_IMPORT_DESCRIPTOR));

	while (importDescriptor.Name) 
	{
		ReadMemory(hProcess, _dllStart + importDescriptor.Name, &libraryName, sizeof(libraryName));

		HMODULE handle = (HMODULE)Inject(hProcess, libraryName);
		if (handle == NULL) 
			return;

		DWORD* thunkRefPointer;
		FARPROC* funcRefPointer;
		if (importDescriptor.OriginalFirstThunk) 
		{
			thunkRefPointer = (DWORD*)(_dllStart + importDescriptor.OriginalFirstThunk);
			funcRefPointer = (FARPROC *)(_dllStart + importDescriptor.FirstThunk);
		} 
		else 
		{
			thunkRefPointer = (DWORD*)(_dllStart + importDescriptor.FirstThunk);
			funcRefPointer = (FARPROC*)(_dllStart + importDescriptor.FirstThunk);
		}

		DWORD thunkRef;
		FARPROC funcRef;

		ReadMemory(hProcess, thunkRefPointer, &thunkRef, sizeof(DWORD));

		while (thunkRef) 
		{
			if (IMAGE_SNAP_BY_ORDINAL(thunkRef)) 
				ReadMemory(hProcess, (LPVOID)IMAGE_ORDINAL(thunkRef), libraryName, sizeof(libraryName));
			else 
			{
				PIMAGE_IMPORT_BY_NAME thunkDataPointer = (PIMAGE_IMPORT_BY_NAME)(_dllStart + thunkRef);
				IMAGE_IMPORT_BY_NAME thunkData;
				ReadMemory(hProcess, thunkDataPointer, &thunkData, sizeof(IMAGE_IMPORT_BY_NAME));
				ReadMemory(hProcess, (DWORD)&thunkData.Name - (DWORD)&thunkData + (char*)thunkDataPointer, libraryName, sizeof(libraryName));
			}

			funcRef = (FARPROC)RemoteGetProcAddress(hProcess, handle, libraryName);
			if (funcRef == 0)
				return;

			WriteMemory(hProcess, funcRefPointer, &funcRef, sizeof(FARPROC));

			thunkRefPointer++;
			funcRefPointer++;

			ReadMemory(hProcess, thunkRefPointer, &thunkRef, sizeof(DWORD));
			ReadMemory(hProcess, funcRefPointer, &funcRef, sizeof(FARPROC));
		}

		importDescriptorPointer++;
		ReadMemory(hProcess, importDescriptorPointer, &importDescriptor, sizeof(_IMAGE_IMPORT_DESCRIPTOR));
	}
}

bool StealthLoadLibraryMemory(HANDLE hProcess, void* address)
{
	_dllData = (char*)address;

	_injectingDosHeader = *(IMAGE_DOS_HEADER*)_dllData;
	if (_injectingDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	_injectingNtHeaders = *(IMAGE_NT_HEADERS*)((char*)_dllData + _injectingDosHeader.e_lfanew);
	if (_injectingNtHeaders.Signature != IMAGE_NT_SIGNATURE)
		return false;
		
	//MainModule
	IMAGE_DOS_HEADER* mainDosHeaderPointer = (IMAGE_DOS_HEADER*)GetRemoteModuleHandle(hProcess, NULL);
	ReadMemory(hProcess, mainDosHeaderPointer, &_mainDosHeader, sizeof(IMAGE_DOS_HEADER));
	if (_mainDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	ReadMemory(hProcess, (char*)mainDosHeaderPointer + _mainDosHeader.e_lfanew, &_mainNtHeaders, sizeof(IMAGE_NT_HEADERS));
	if (_mainNtHeaders.Signature != IMAGE_NT_SIGNATURE)
		return false;

	_dllStart = (char*)VirtualAllocEx(hProcess, (LPVOID)(_injectingNtHeaders.OptionalHeader.ImageBase), _injectingNtHeaders.OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!_dllStart)
	{
		_dllStart = (char*)VirtualAllocEx(hProcess, NULL, _injectingNtHeaders.OptionalHeader.SizeOfImage, MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!_dllStart)
			return false;
	}

	VirtualAllocEx(hProcess, _dllStart, _injectingNtHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//Copy over the headers
	void* headers = _dllStart/*VirtualAlloc(_dllStart, _injectingNtHeaders->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE)*/;
	WriteMemory(hProcess, headers, _dllData, _injectingDosHeader.e_lfanew + _injectingNtHeaders.OptionalHeader.SizeOfHeaders);

	_injectedDosHeader = (IMAGE_DOS_HEADER*)headers;
	_injectedNtHeaders = (IMAGE_NT_HEADERS*)((char*)_injectedDosHeader + _injectingDosHeader.e_lfanew);

	int bytesMoved = (DWORD)_dllStart - _injectingNtHeaders.OptionalHeader.ImageBase;
	_injectingNtHeaders.OptionalHeader.ImageBase = (DWORD)_dllStart;
	WriteMemory(hProcess, (DWORD)&_injectingNtHeaders.OptionalHeader.ImageBase - (DWORD)&_injectingNtHeaders + (char*)_injectedNtHeaders, &_dllStart, sizeof(DWORD));

	LoadSections(hProcess);
	if (bytesMoved)
		Relocate(hProcess, bytesMoved);

	ResolveImports(hProcess);
	//Finalize? doesn't seem necessary tbh for our application

	//Call DllMain!
	if (_injectingNtHeaders.OptionalHeader.AddressOfEntryPoint)
	{
		//((BOOL (WINAPI*)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved))(_dllStart + _injectingNtHeaders.OptionalHeader.AddressOfEntryPoint))((HINSTANCE)_dllStart, DLL_PROCESS_ATTACH, 0);
		void* addr = _dllStart + _injectingNtHeaders.OptionalHeader.AddressOfEntryPoint;

		BYTE localPage[256];
		int codeIndex = 0;
		void* page = VirtualAllocEx(hProcess, NULL, 256, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		//PUSH 0
		localPage[codeIndex++] = 0x6A;
		localPage[codeIndex++] = 0x00;

		//PUSH DLL_PROCESS_ATTACH
		localPage[codeIndex++] = 0x6A;
		localPage[codeIndex++] = DLL_PROCESS_ATTACH;		

		//PUSH _dllStart
		localPage[codeIndex++] = 0x68;
		memcpy(localPage + codeIndex, &_dllStart, sizeof(DWORD));
		codeIndex += 4;

		//MOV EAX, DllMain
		localPage[codeIndex++] = 0xB8;
		memcpy(localPage + codeIndex, &addr, sizeof(DWORD));
		codeIndex += 4;

		//CALL EAX
		localPage[codeIndex++] = 0xFF;
		localPage[codeIndex++] = 0xD0;

		DWORD exitThread = (DWORD)GetProcAddress(GetModuleHandle("kernel32"), "ExitThread");

		//PUSH EAX
		localPage[codeIndex++] = 0x50;

		//MOV EAX, exitThread
		localPage[codeIndex++] = 0xB8;
		memcpy(localPage + codeIndex, &exitThread, sizeof(DWORD));
		codeIndex += 4;

		//CALL EAX
		localPage[codeIndex++] = 0xFF;
		localPage[codeIndex++] = 0xD0;

		WriteMemory(hProcess, page, localPage, 256);

		FlushInstructionCache(hProcess, page, codeIndex);

		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((void*)page), 0, 0, NULL);
		WaitForSingleObject(hThread, INFINITE); 

		DWORD result;
		GetExitCodeThread(hThread, &result);
		VirtualFreeEx(hProcess, page, 0, MEM_RELEASE);

		return result == TRUE;
	}
	return true;
}

extern "C" _declspec(dllexport) void StealthLoadLibrary(HANDLE hProcess, const char* path)
{
	HANDLE hDllFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDllFile == INVALID_HANDLE_VALUE)
		return;

	DWORD size = GetFileSize(hDllFile, NULL);
	DWORD bytesRead = 0;
	char* dllData = new char[size];

	if (!ReadFile(hDllFile, dllData, size, &bytesRead, NULL))
		return;

	CloseHandle(hDllFile);
	StealthLoadLibraryMemory(hProcess, dllData);
	delete[] dllData;
}

char* ToLower(char* text) 
{
	for (unsigned int i = 0; i < strlen(text); i++) 
		if (text[i] >= 0x41 && text[i] <= 0x5A) 
			text[i] = text[i] + 0x20;
	return text;
}

int main(int argc, const char* argv[])
{
	const char* dll;
	const char* exe;

	if (argc < 2)
	{
		printf("Usage: stealthinject dll exe");
		return 0;
	}
	
	dll = argv[1];

	char buffer[MAX_PATH];
	strcpy(buffer, argv[2]);
	exe = ToLower(buffer);

	PROCESSENTRY32 process;
	memset(&process, 0, sizeof(process));
	process.dwSize = sizeof(process);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create snapshot.\n");
		return 0;
	}

	printf("Searching for process '%s'.\n", exe);

	_pid = INFINITE;
	while (_pid == INFINITE)
	{
		if (!Process32First(hSnapshot, &process))
		{
			printf("Failed to get first process.\n");
			return 0;
		}

		do 
		{
			if (strcmp(exe, ToLower(process.szExeFile)) == 0)
			{
				printf("Found process.\n");
				_pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &process));

		Sleep(100);
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, _pid);
	if (hProcess == NULL)
	{
		printf("Failed to open process.\n");
		return 0;
	}

	printf("Injecting library '%s' into process.\n", dll);
	StealthLoadLibrary(hProcess, dll);

	return 0;
}