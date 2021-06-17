#pragma once

#include "unique.h"

#define SYS_INVALID_PROCESS_ID ((DWORD)-1)

bool SYSDisableWow64FsRedirection(_Out_ bool& rbNeedRevert,
	_Out_ PVOID& rpvOldValue, _Out_ DWORD& rdwLastError);

bool SYSExpandEnvironmentStringsW(_Out_ std::wstring& rstrDstW,
	_In_ LPCWSTR lpszSrcW, _Out_ DWORD& rdwLastError);

class SYSErrorMessageW
{
public:
    SYSErrorMessageW(_In_ DWORD dwErrorCode);
    ~SYSErrorMessageW();

    operator LPCWSTR() const;

private:
    LPWSTR m_pszErrorMessageW = nullptr;
};  // class SYSErrorMessageW

SYSErrorMessageW SYSGetErrorMessageW(_In_ DWORD dwErrorCode);

bool SYSGetProcessNameByIdW(_Out_ std::wstring& rstrNameW, _In_ ULONG ulPid);

bool SYSRevertWow64FsRedirection(_In_ PVOID pvOldValue,
	_Out_ DWORD& rdwLastError);

HANDLE SYSRunProcessWithRedirectedIOW(_In_ LPCWSTR lpszApplicationNameW,
	_In_ LPCWSTR lpszCommandLineW, _In_ LPCWSTR lpszCurrentDirectoryW,
	_Out_ UniqueFile& rStdInReadHandle,
	_Out_ UniqueFile& rStdInWriteHandle,
	_Out_ UniqueFile& rStdOutReadHandle,
	_Out_ UniqueFile& rStdOutWriteHandle,
	_Out_ UniqueFile& rStdErrReadHandle,
	_Out_ UniqueFile& rStdErrWriteHandle, _Out_ DWORD& rdwProcessId,
	_Out_ DWORD& rdwLastError);
