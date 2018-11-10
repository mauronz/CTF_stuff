// injector.cpp : Defines the exported functions for the DLL application.
//

#include "injector.h"
#include "hooks.h"

extern HMODULE hGlobalModule;

BOOL __cdecl inject() {
	int argc;
	SIZE_T written;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	LPWSTR pCmdline = GetCommandLineW();
	LPWSTR *pArgv = CommandLineToArgvW(pCmdline, &argc);
	WCHAR pFilename[MAX_PATH];
	DWORD dwFilenameSize = GetModuleFileNameW(hGlobalModule, pFilename, MAX_PATH);

	if (argc > 3) {
		LPWSTR pTargetCmd = wcsstr(pCmdline, pArgv[3]);
		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&si, sizeof(pi));
		if (!CreateProcessW(NULL, pTargetCmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			OutputDebugStringA("[-] Error creating process\n");
			return FALSE;
		}
		LPVOID pRemoteAddress = VirtualAllocEx(pi.hProcess, NULL, 0x100, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!pRemoteAddress) {
			OutputDebugStringA("[-] Error allocating remote memory\n");
			return FALSE;
		}
		if (!WriteProcessMemory(pi.hProcess, pRemoteAddress, pFilename, dwFilenameSize * sizeof(WCHAR), &written)) {
			OutputDebugStringA("[-] Error writing remote memory\n");
			return FALSE;
		}
		if (!CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, pRemoteAddress, 0, NULL)) {
			OutputDebugStringA("[-] Error creating remote thread\n");
			return FALSE;
		}
		ResumeThread(pi.hThread);
	}
	return TRUE;
}

BOOL SetHooks() {
	// cipher_routine at is 0x12a0
	LPVOID addr = (LPVOID)((DWORD)GetModuleHandleW(NULL) + 0x12a0);
	SetHookByAddr(addr, 4, CV_CDECL, NULL, (FARPROC)ah_Encryption, TRUE, FALSE);
	return TRUE;
}