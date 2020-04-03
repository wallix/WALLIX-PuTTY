// iploop.cpp : Defines the entry point for the application.
//

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>
// C RunTime Header Files
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <winsock.h>
#include <processenv.h>

#include "iploop.h"

static const wchar_t* appname = L"Putty Loopback IP Manager";

int error(const wchar_t* message, DWORD code) {
	PWSTR lpMsgBuf = NULL;
	WCHAR buf[1024];
	if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL) > 0) {
		_snwprintf(buf, 1024, L"%s: %s", message, (PWSTR)lpMsgBuf);
	}
	else {
		wcsncpy(buf, message, 1024);
	}
	buf[1023] = '\0';

	if (lpMsgBuf != NULL) {
		LocalFree(lpMsgBuf);
	}

	MessageBox(NULL, buf, appname, MB_ICONERROR | MB_OK);

	return 1;
}

void unmap(ULONG* nte, int n) {
	for (int i = 0; i < n; i++) {
		DWORD ret = DeleteIPAddress(nte[i]);
		if (ret != NO_ERROR) {
			error(L"Cannot unmap address from loopback inerface", ret);
		}
	}
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {

	wchar_t eventName[MAX_PATH];
	if (GetEnvironmentVariable(L"IPLOOP_EVENT", eventName, MAX_PATH) == 0) {
		return error(L"Event name is not defined", GetLastError());
	}

	HANDLE event = OpenEvent(SYNCHRONIZE|DELETE, FALSE, eventName);
	if (NULL == event) {
		return error(L"Cannot access event", GetLastError());
	}

	int nArgs;
	LPWSTR* szArglist = CommandLineToArgvW(pCmdLine, &nArgs);
	if (NULL == szArglist) {
		MessageBox(NULL, L"Cannot parse command line", appname, MB_ICONERROR | MB_OK);
		return 1;
	}
	if (nArgs < 1) {
		LocalFree(szArglist);
		MessageBox(NULL, L"iploop ip1 ip2...", appname, MB_ICONERROR | MB_OK);
		return 1;
	}

	int nbContexts = 0;
	HANDLE heap = GetProcessHeap();
	if (NULL == heap) {
		LocalFree(szArglist);
		return error(L"Cannot get process heap", GetLastError());
	}
 	ULONG* NTEContexts = (ULONG*)HeapAlloc(heap, HEAP_GENERATE_EXCEPTIONS, sizeof(ULONG) * (nArgs - 1));
	if (NULL == NTEContexts) {
		LocalFree(szArglist);
		return error(L"Cannot allocate NTE Contexts", GetLastError());
	}

	for (int i = 0; i < nArgs; i++) {
		char addr[24];
		if (WideCharToMultiByte(CP_ACP, 0, szArglist[i], -1, addr, 24, NULL, NULL) == 0) {
			return error(L"Cannot convert IP to ANSI", GetLastError());
		}
		unsigned int iaIPAddress = inet_addr(addr);
		unsigned int iaIPMask = inet_addr("255.255.255.255");
		ULONG NTEInstance = 0;
		DWORD ret = AddIPAddress(iaIPAddress, iaIPMask, 1, &NTEContexts[nbContexts], &NTEInstance);
		if (ret != NO_ERROR && ret != ERROR_OBJECT_ALREADY_EXISTS) {
			unmap(NTEContexts, nbContexts);
			return error(L"Cannot map IP address to loopback interface", ret);
		}
		if (ret != ERROR_OBJECT_ALREADY_EXISTS) {
			nbContexts++;
		}
	}

	if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0) {
		error(L"Event not signaled", GetLastError());
	}

	if (CloseHandle(event) == FALSE) {
		error(L"Cannot close event", GetLastError());
	}

	unmap(NTEContexts, nbContexts);

	LocalFree(szArglist);
	HeapFree(heap, 0, NTEContexts);

	return 0;
}