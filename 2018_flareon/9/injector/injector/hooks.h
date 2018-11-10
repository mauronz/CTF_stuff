#pragma once

#include <Windows.h>

VOID __stdcall ah_Encryption(
	LPVOID arg1,
	BYTE *targetAddr,
	DWORD isVBScriptAlgo,
	DWORD isEncryption,
	DWORD retvalue
);