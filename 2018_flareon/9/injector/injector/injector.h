#pragma once

#include <Windows.h>
#include <stdio.h>
#include "APIhooklib.h"

extern "C" BOOL __declspec(dllexport) __cdecl inject();

BOOL SetHooks();