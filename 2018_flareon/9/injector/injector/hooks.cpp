#include "hooks.h"

VOID __stdcall ah_Encryption(
	LPVOID arg1,
	BYTE *targetAddr,
	DWORD isVBScriptAlgo,
	DWORD isEncryption,
	DWORD retvalue
) {
	CHAR line[1024];
	HANDLE hFile;
	DWORD dwBytes;
	if (isVBScriptAlgo == 1 && isEncryption == 0) {
		wsprintfA(line, "%08x %02x %02x\n", targetAddr, targetAddr[0], targetAddr[1]);
		hFile = CreateFileA("log.txt", GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		SetFilePointer(hFile, 0, NULL, FILE_END);
		WriteFile(hFile, line, lstrlenA(line), &dwBytes, NULL);
		CloseHandle(hFile);
	}
}