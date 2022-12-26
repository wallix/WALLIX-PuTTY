#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#include <windows.h>

#include <cassert>
#include <string>

#include <Psapi.h>

#include "strutils.h"
#include "sysutils.h"

bool SYSDisableWow64FsRedirection(_Out_ bool& rbNeedRevert,
    _Out_ PVOID& rpvOldValue, _Out_ DWORD& rdwLastError)
{
    rdwLastError = ERROR_SUCCESS;

    rbNeedRevert = false;
    rpvOldValue = NULL;

    OutputDebugStringW(L"SYSDisableWow64FsRedirection(): ...");

#if defined(_WIN64)
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): Done. NeedRevert=%s",
            (rbNeedRevert ? L"yes" : L"no"));
        OutputDebugStringW(szDebugStringW);
    }

    return true;
#else   // #if defined(_WIN64)
    BOOL bWow64Process = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &bWow64Process))
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): "
                L"Failed to determines whether the current process "
                    L"is running under WOW64! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

        return false;
    }   // if (!IsWow64Process(GetCurrentProcess(), &bWow64Process))

    if (!bWow64Process)
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): Done. "
                L"32 Bit Operating System detected. NeedRevert=%s",
            (rbNeedRevert ? L"yes" : L"no"));
        OutputDebugStringW(szDebugStringW);

        return true;
    }   // if (!bWow64Process)

    HMODULE hKernel32DLL = LoadLibraryW(L"Kernel32.dll");
    if (!hKernel32DLL)
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): "
                L"Failed to load \"Kernel32.dll\" into the "
                    L"address space of the current process! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

        return false;
    }   // if (!hKernel32DLL)

    bool bResult = false;

    typedef BOOL (WINAPI *PWOW64DISABLEWOW64FSREDIRECTION)(_Out_ PVOID *);

    PWOW64DISABLEWOW64FSREDIRECTION fnWow64DisableWow64FsRedirection =
        (PWOW64DISABLEWOW64FSREDIRECTION)GetProcAddress(hKernel32DLL,
            "Wow64DisableWow64FsRedirection");
    if (!fnWow64DisableWow64FsRedirection)
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): "
                L"Failed to retrieve the address of "
                    L"\"Wow64DisableWow64FsRedirection\" function "
                    L"from the dynamic-link library! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
    }
    else    // if (!fnWow64DisableWow64FsRedirection)
    {
        if (!fnWow64DisableWow64FsRedirection(&rpvOldValue))
        {
            DWORD const dwLastError = GetLastError();
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSDisableWow64FsRedirection(): "
                    L"Failed to disable WOW64 file system redirection "
                        L"for the current thread! "
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
            if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
        }
        else    // if (!fnWow64DisableWow64FsRedirection(&rpvOldValue))
        {
            bResult = true;
            rbNeedRevert = true;
        }   // if (!fnWow64DisableWow64FsRedirection(&rpvOldValue))
    }   // if (!fnWow64DisableWow64FsRedirection)

    if (!FreeLibrary(hKernel32DLL))
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): "
                L"Failed to free loaded \"Kernel32.dll\" module! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
    }   // if (!FreeLibrary(hKernel32DLL))

    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSDisableWow64FsRedirection(): Done. "
                L"Return %s. NeedRevert=%s",
            (bResult ? L"true" : L"false"),
            (rbNeedRevert ? L"yes" : L"no"));
        OutputDebugStringW(szDebugStringW);
    }

    return bResult;
#endif  // #if defined(_WIN64)
}   // bool SYSDisableWow64FsRedirection(_Out_ bool& rbNeedRevert,
    //     _Out_ PVOID& rpvOldValue, _Out_ DWORD& rdwLastError)

bool SYSExpandEnvironmentStringsW(_Out_ std::wstring& rstrDstW,
    _In_ LPCWSTR lpszSrcW, _Out_ DWORD& rdwLastError)
{
    rdwLastError = ERROR_SUCCESS;

    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSExpandEnvironmentStrings(): ... Src=\"%s\"",
            (lpszSrcW ? lpszSrcW : L"(null)"));
        OutputDebugStringW(szDebugStringW);
    }

    rstrDstW.clear();

    if (lpszSrcW && *lpszSrcW)
    {
        DWORD dwResult = ExpandEnvironmentStringsW(
                /*lpSrc =*/ lpszSrcW,
                /*lpDst =*/ NULL,
                /*nSize =*/ 0
            );
        if (!dwResult)
        {
            DWORD const dwLastError = GetLastError();
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSExpandEnvironmentStrings(): "
                    L"Failed to get required buffer size! "
                    L"Src=\"%s\" LastError=\"%s\"(%u)",
                lpszSrcW,
                static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
            if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

            return false;
        }   // if (!dwResult)

        rstrDstW.resize(dwResult);

        dwResult = ExpandEnvironmentStringsW(
                /*lpSrc =*/ lpszSrcW,
                /*lpDst =*/ &rstrDstW[0],
                /*nSize =*/ dwResult
            );
        if (!dwResult)
        {
            DWORD const dwLastError = GetLastError();
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSExpandEnvironmentStrings(): "
                    L"Failed to expand environment-variable strings! "
                    L"Src=\"%s\" LastError=\"%s\"(%u)",
                lpszSrcW,
                static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
            if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

            rstrDstW.clear();

            return false;
        }   // if (!dwResult)

        STRTrimTrailingNullCharactersW(rstrDstW);
    }   // if (lpszSrcW && *lpszSrcW)

    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSExpandEnvironmentStrings(): Done. "
                L"ExpandedStrings=\"%s\" LastError=\"%s\"(%u)",
            rstrDstW.c_str(),
            static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
            rdwLastError);
        OutputDebugStringW(szDebugStringW);
    }

    return true;
}   // bool SYSExpandEnvironmentStringsW(_Out_ std::wstring& rstrDstW,
    //     _In_ LPCWSTR lpszSrcW, _Out_ DWORD& rdwLastError)

SYSErrorMessageW::SYSErrorMessageW(_In_ DWORD dwErrorCode)
{
    if (!::FormatMessageW(
                /*dwFlags      =*/ FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                   FORMAT_MESSAGE_FROM_SYSTEM |
                                   FORMAT_MESSAGE_IGNORE_INSERTS |
                                   FORMAT_MESSAGE_MAX_WIDTH_MASK,
                /*lpSource     =*/ NULL,
                /*dwMessageId  =*/ dwErrorCode,
                /*dwLanguageId =*/ MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                /*lpBuffer     =*/ reinterpret_cast<LPWSTR>(
                                       &m_pszErrorMessageW),
                /*nSize        =*/ 0,
                /*Arguments    =*/ NULL
            ))
        m_pszErrorMessageW = nullptr;
    else if (int const nErrorMessageLength =
                 static_cast<int>(::lstrlenW(m_pszErrorMessageW)))
    {
        for (int nPos = nErrorMessageLength - 1; 0 <= nPos; --nPos)
            if (L' ' == m_pszErrorMessageW[nPos])
                m_pszErrorMessageW[nPos] = L'\0';
            else    // if (L' ' == m_pszErrorMessageW[nPos])
                break;
    }   // else if (const int nErrorMessageLength =
}   // SYSErrorMessageW::SYSErrorMessageW(DWORD dwErrorCode)

SYSErrorMessageW::~SYSErrorMessageW()
{
    if (m_pszErrorMessageW)
        ::LocalFree(m_pszErrorMessageW);
}   // SYSErrorMessageW::~SYSErrorMessageW()

SYSErrorMessageW::operator LPCWSTR() const
{
    if (m_pszErrorMessageW)
        return m_pszErrorMessageW;

    return L"<unknown>";
}   // SYSErrorMessageW::operator LPCWSTR() const

SYSErrorMessageW SYSGetErrorMessageW(_In_ DWORD dwErrorCode)
{
    return SYSErrorMessageW(dwErrorCode);
}   // SYSErrorMessageW SYSGetErrorMessageW(_In_ DWORD dwErrorCode)

bool SYSGetProcessNameByIdW(_Out_ std::wstring& rstrNameW, _In_ ULONG ulPid)
{
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSGetProcessNameById(): ... Pid=%u", ulPid);
        OutputDebugStringW(szDebugStringW);
    }

    rstrNameW.clear();

    OutputDebugStringW(L"SYSGetProcessNameById(): Opening the process ...");

    UniqueProcess shProcess(
            OpenProcess(
                /*dwDesiredAccess =*/   PROCESS_QUERY_INFORMATION
                                      | PROCESS_VM_READ,
                /*bInheritHandle  =*/ FALSE,
                /*dwProcessId     =*/ ulPid
        ));
    if (shProcess)
    {
        OutputDebugStringW(L"SYSGetProcessNameById(): Process opened.");

        OutputDebugStringW(L"SYSGetProcessNameById(): "
            L"Retrieving the name of the executable file for "
                L"the process ...");

        size_t const IMAGE_FILE_NAME_BUFFER_SIZE = 2048;
        static_assert(IMAGE_FILE_NAME_BUFFER_SIZE >= _MAX_PATH + 1,
            "IMAGE_FILE_NAME_BUFFER_SIZE must be greater than or "
                "equal to _MAX_PATH + 1");
        wchar_t szImageFileNameW[IMAGE_FILE_NAME_BUFFER_SIZE];

        DWORD dwResult = GetProcessImageFileNameW(
                /*hProcess        =*/ shProcess.Get(),
                /*lpImageFileName =*/ szImageFileNameW,
                /*nSize           =*/ IMAGE_FILE_NAME_BUFFER_SIZE
            );
        if (dwResult)
        {
            {
                wchar_t szDebugStringW[256];
                _snwprintf(szDebugStringW, _countof(szDebugStringW),
                    L"SYSGetProcessNameById(): "
                        "Name of the executable file retrieved. "
                        "ExecutableFileName=\"%s\"",
                    szImageFileNameW);
                OutputDebugStringW(szDebugStringW);
            }

            LPCWSTR lpszLastOcurrenceW = wcsrchr(szImageFileNameW, L'\\');
            if (lpszLastOcurrenceW)
            {
                rstrNameW = lpszLastOcurrenceW + 1;

                {
                    wchar_t szDebugStringW[256];
                    _snwprintf(szDebugStringW, _countof(szDebugStringW),
                        L"SYSGetProcessNameById(): ProcessName=\"%s\"",
                        szImageFileNameW);
                    OutputDebugStringW(szDebugStringW);
                }
            }
            else    // if (lpszLastOcurrence)
            {
                OutputDebugStringW(L"SYSGetProcessNameById(): "
                    L"Failed to find process name separator!");
            }   // if (lpszLastOcurrence)
        }
        else    // if (dwResult)
        {
            DWORD const dwLastError = GetLastError();
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSGetProcessNameById(): "
                    L"Failed to retrieve the name of the executable "
                        L"file for the process! "
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
        }   // if (dwResult)

        if (!CloseHandle(shProcess.Release()))
        {
            DWORD const dwLastError = GetLastError();
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSGetProcessNameById(): "
                    L"Failed to close the handle of the process! "
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
        }   // if (!CloseHandle(shProcess.Release()))
    }
    else    // if (shProcess)
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSGetProcessNameById(): "
                L"Failed to open the process! LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
    }   // if (shProcess)

    return (!rstrNameW.empty());
}   // bool SYSGetProcessNameByIdW(_Out_ std::wstring& rstrNameW, _In_ ULONG ulPid)

bool SYSRevertWow64FsRedirection(_In_ PVOID pvOldValue,
    _Out_ DWORD& rdwLastError)
{
    rdwLastError = ERROR_SUCCESS;

    OutputDebugStringW(L"SYSRevertWow64FsRedirection(): ...");

#if defined(_WIN64)
    OutputDebugStringW(L"SYSRevertWow64FsRedirection(): Done.");

    return true;
#else   // #if defined(_WIN64)
    BOOL bWow64Process = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &bWow64Process))
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRevertWow64FsRedirection(): "
                L"Failed to determines whether the current process "
                    L"is running under WOW64! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

        return false;
    }   // if (!IsWow64Process(GetCurrentProcess(), &bWow64Process))

    if (!bWow64Process)
    {
        OutputDebugStringW(L"SYSRevertWow64FsRedirection(): Done. "
            L"32 Bit Operating System detected.");

        return true;
    }   // if (!bWow64Process)

    HMODULE hKernel32DLL = LoadLibraryW(L"Kernel32.dll");
    if (!hKernel32DLL)
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRevertWow64FsRedirection(): "
                L"Failed to load \"Kernel32.dll\" into the "
                    L"address space of the current process! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

        return false;
    }   // if (!hKernel32DLL)

    bool bResult = false;

    typedef BOOL(WINAPI *PWOW64REVERTWOW64FSREDIRECTION)(_In_ PVOID);

    PWOW64REVERTWOW64FSREDIRECTION fnWow64RevertWow64FsRedirection =
        (PWOW64REVERTWOW64FSREDIRECTION)GetProcAddress(hKernel32DLL,
            "Wow64RevertWow64FsRedirection");
    if (!fnWow64RevertWow64FsRedirection)
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRevertWow64FsRedirection(): "
                L"Failed to retrieve the address of "
                    L"\"Wow64RevertWow64FsRedirection\" function "
                    L"from the dynamic-link library! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
    }
    else    // if (!fnWow64RevertWow64FsRedirection)
    {
        if (!fnWow64RevertWow64FsRedirection(pvOldValue))
        {
            DWORD const dwLastError = GetLastError();
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRevertWow64FsRedirection(): "
                    L"Failed to restore "
                        L"WOW64 file system redirection "
                        L"for the current thread! "
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
            if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
        }
        else    // if (!fnWow64RevertWow64FsRedirection(pvOldValue))
            bResult = true;
    }   // if (!fnWow64RevertWow64FsRedirection)

    if (!FreeLibrary(hKernel32DLL))
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRevertWow64FsRedirection(): "
                L"Failed to free loaded \"Kernel32.dll\" module! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
    }   // if (!FreeLibrary(hKernel32DLL))

    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRevertWow64FsRedirection(): Done. "
                L"Return %s",
            (bResult ? L"true" : L"false"));
        OutputDebugStringW(szDebugStringW);
    }

    return bResult;
#endif  // #if defined(_WIN64)
}   // bool SYSRevertWow64FsRedirection(_In_ PVOID pvOldValue,
    //     _Out_ DWORD& rdwLastError)

HANDLE SYSRunProcessWithRedirectedIOW(_In_ LPCWSTR lpszApplicationNameW,
    _In_ LPCWSTR lpszCommandLineW, _In_ LPCWSTR lpszCurrentDirectoryW,
    _Out_ UniqueFile& rStdInReadHandle,
    _Out_ UniqueFile& rStdInWriteHandle,
    _Out_ UniqueFile& rStdOutReadHandle,
    _Out_ UniqueFile& rStdOutWriteHandle,
    _Out_ UniqueFile& rStdErrReadHandle,
    _Out_ UniqueFile& rStdErrWriteHandle, _Out_ DWORD& rdwProcessId,
    _Out_ DWORD& rdwLastError)
{
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRunProcessWithRedirectedIO(): ... "
                L"ApplicationName=\"%s\" CommandLine=\"%s\" "
                L"CurrentDirectory=\"%s\"",
            (lpszApplicationNameW ? lpszApplicationNameW : L"(null)"),
            (lpszCommandLineW ? lpszCommandLineW : L"(null)"),
            (lpszCurrentDirectoryW ? lpszCurrentDirectoryW : L"(null)"));
        OutputDebugStringW(szDebugStringW);
    }

    rStdInReadHandle.Reset();
    rStdInWriteHandle.Reset();
    rStdOutReadHandle.Reset();
    rStdOutWriteHandle.Reset();
    rStdErrReadHandle.Reset();
    rStdErrWriteHandle.Reset();

    rdwProcessId = SYS_INVALID_PROCESS_ID;
    rdwLastError = ERROR_SUCCESS;

    bool  bWow64FsRedirectionNeedRevert = false;
    PVOID pvOldValue                    = NULL;

    constexpr DWORD dwPipeBufferSize = 32768;

    UniqueProcess shProcess;
    UniqueThread  shThread;

    std::wstring strApplicationNameW;
    std::wstring strCommandLineW;
    std::wstring strCurrentDirectoryW;

    {
        DWORD dwLastError = ERROR_SUCCESS;
        if (!SYSExpandEnvironmentStringsW(
                strApplicationNameW,
                lpszApplicationNameW,
                dwLastError
            ))
        {
            if ((ERROR_SUCCESS == rdwLastError) &&
                (ERROR_SUCCESS != dwLastError))
                rdwLastError = dwLastError;

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SYSExpandEnvironmentStrings(
    }

    {
        DWORD dwLastError = ERROR_SUCCESS;
        if (!SYSExpandEnvironmentStringsW(
                strCommandLineW,
                lpszCommandLineW,
                dwLastError
            ))
        {
            if ((ERROR_SUCCESS == rdwLastError) &&
                (ERROR_SUCCESS != dwLastError))
                rdwLastError = dwLastError;

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SYSExpandEnvironmentStrings(
    }

    {
        DWORD dwLastError = ERROR_SUCCESS;
        if (!SYSExpandEnvironmentStringsW(
                strCurrentDirectoryW,
                lpszCurrentDirectoryW,
                dwLastError
            ))
        {
            if ((ERROR_SUCCESS == rdwLastError) &&
                (ERROR_SUCCESS != dwLastError))
                rdwLastError = dwLastError;

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SYSExpandEnvironmentStrings(
    }

    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRunProcessWithRedirectedIO(): "
                L"ApplicationName=\"%s\" CommandLine=\"%s\" "
                L"CurrentDirectory=\"%s\"",
            strApplicationNameW.c_str(), strCommandLineW.c_str(),
            strCurrentDirectoryW.c_str());
        OutputDebugStringW(szDebugStringW);
    }

    SECURITY_ATTRIBUTES SecurityAttributes;

    ZeroMemory(&SecurityAttributes, sizeof(SecurityAttributes));

    SecurityAttributes.nLength        = sizeof(SecurityAttributes);
    SecurityAttributes.bInheritHandle = true;

    {
        if (!CreatePipe(
                    /*hReadPipe        =*/ rStdInReadHandle.GetPtr(),
                    /*hWritePipe       =*/ rStdInWriteHandle.GetPtr(),
                    /*lpPipeAttributes =*/ &SecurityAttributes,
                    /*nSize            =*/ dwPipeBufferSize
                ))
        {
            rdwLastError = GetLastError();

            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRunProcessWithRedirectedIO(): "
                    L"Failed to create anonymous pipe! (STDIN)"
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
                rdwLastError);
            OutputDebugStringW(szDebugStringW);

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!CreatePipe(

        if (!SetHandleInformation(
                /*hObject =*/ rStdInWriteHandle.Get(),
                /*dwMask  =*/ HANDLE_FLAG_INHERIT,
                /*dwFlags =*/0))
        {
            rdwLastError = GetLastError();

            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRunProcessWithRedirectedIO(): "
                    L"Failed to mark write end of pipe as "
                        L"no-inheritable! (STDIN)"
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
                rdwLastError);
            OutputDebugStringW(szDebugStringW);

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SetHandleInformation(
    }

    {
        if (!CreatePipe(
                    /*hReadPipe        =*/ rStdOutReadHandle.GetPtr(),
                    /*hWritePipe       =*/ rStdOutWriteHandle.GetPtr(),
                    /*lpPipeAttributes =*/ &SecurityAttributes,
                    /*nSize            =*/ dwPipeBufferSize
                ))
        {
            rdwLastError = GetLastError();

            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRunProcessWithRedirectedIO(): "
                    L"Failed to create anonymous pipe! (STDOUT)"
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
                rdwLastError);
            OutputDebugStringW(szDebugStringW);

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!CreatePipe(

        if (!SetHandleInformation(
                /*hObject =*/ rStdOutReadHandle.Get(),
                /*dwMask  =*/ HANDLE_FLAG_INHERIT,
                /*dwFlags =*/0))
        {
            rdwLastError = GetLastError();

            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRunProcessWithRedirectedIO(): "
                    L"Failed to mark read end of pipe as "
                        L"no-inheritable! (STDOUT)"
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
                rdwLastError);
            OutputDebugStringW(szDebugStringW);

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SetHandleInformation(
    }

    {
        if (!CreatePipe(
                    /*hReadPipe        =*/ rStdErrReadHandle.GetPtr(),
                    /*hWritePipe       =*/ rStdErrWriteHandle.GetPtr(),
                    /*lpPipeAttributes =*/ &SecurityAttributes,
                    /*nSize            =*/ dwPipeBufferSize
                ))
        {
            rdwLastError = GetLastError();

            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRunProcessWithRedirectedIO(): "
                    L"Failed to create anonymous pipe! (STDERR)"
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
                rdwLastError);
            OutputDebugStringW(szDebugStringW);

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!CreatePipe(

        if (!SetHandleInformation(
                /*hObject =*/ rStdErrReadHandle.Get(),
                /*dwMask  =*/ HANDLE_FLAG_INHERIT,
                /*dwFlags =*/0))
        {
            rdwLastError = GetLastError();

            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"SYSRunProcessWithRedirectedIO(): "
                    L"Failed to mark read end of pipe as "
                        L"no-inheritable! (STDERR)"
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
                rdwLastError);
            OutputDebugStringW(szDebugStringW);

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SetHandleInformation(
    }

    {
        DWORD dwLastError = ERROR_SUCCESS;
        if (!SYSDisableWow64FsRedirection(bWow64FsRedirectionNeedRevert,
                                          pvOldValue, dwLastError))
        {
            if ((ERROR_SUCCESS == rdwLastError) &&
                (ERROR_SUCCESS != dwLastError))
                rdwLastError = dwLastError;

#ifdef _DEBUG
            assert(!bWow64FsRedirectionNeedRevert);
#endif  // #ifdef _DEBUG

            goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
        }   // if (!SYSDisableWow64FsRedirection( ...
    }

    STARTUPINFOW StartupInfoW;
    ZeroMemory(&StartupInfoW, sizeof(StartupInfoW));
    StartupInfoW.cb          = sizeof(StartupInfoW);
    StartupInfoW.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    StartupInfoW.wShowWindow = SW_HIDE;
    StartupInfoW.hStdInput   = rStdInReadHandle.Get();
    StartupInfoW.hStdOutput  = rStdOutWriteHandle.Get();
    StartupInfoW.hStdError   = rStdErrWriteHandle.Get();

    PROCESS_INFORMATION ProcessInformation;
    ZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

    if (!CreateProcessW(
            /*lpApplicationName   =*/ (!strApplicationNameW.empty() ?
                                       &strApplicationNameW[0] : NULL),
            /*lpCommandLine       =*/ (!strCommandLineW.empty() ?
                                       &strCommandLineW[0] : NULL),
            /*lpProcessAttributes =*/ NULL,
            /*lpThreadAttributes  =*/ NULL,
            /*bInheritHandles     =*/ TRUE,
            /*dwCreationFlags     =*/ 0,
            /*lpEnvironment       =*/ NULL,
            /*lpCurrentDirectory  =*/ (!strCurrentDirectoryW.empty() ?
                                       &strCurrentDirectoryW[0] : NULL),
                                      &StartupInfoW,
                                      &ProcessInformation
        ))
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRunProcessWithRedirectedIO(): "
                L"Failed to create application process! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;

        goto SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP;
    }   // if (CreateProcess(

    shProcess.Reset(ProcessInformation.hProcess);
    shThread.Reset(ProcessInformation.hThread);

    if (!CloseHandle(shThread.Release()))
    {
        DWORD const dwLastError = GetLastError();
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRunProcessWithRedirectedIO(): "
                L"Failed to close the handle of the primary "
                    L"thread of the newly created process! "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(dwLastError)),
            dwLastError);
        OutputDebugStringW(szDebugStringW);
        if (ERROR_SUCCESS == rdwLastError) rdwLastError = dwLastError;
    }   // if (!CloseHandle(shThread.Release()))

    rdwProcessId = ProcessInformation.dwProcessId;

SYS_RUN_PROCESS_WITH_REDIRECTED_I_O_CLEAN_UP:

    if (bWow64FsRedirectionNeedRevert)
    {
        DWORD dwLastError = ERROR_SUCCESS;
        if (!SYSRevertWow64FsRedirection(pvOldValue, dwLastError))
            if ((ERROR_SUCCESS == rdwLastError) &&
                (ERROR_SUCCESS != dwLastError))
                rdwLastError = dwLastError;
    }   // if (bWow64FsRedirectionNeedRevert)

    if (!shProcess)
    {
        rStdInReadHandle.Reset();
        rStdInWriteHandle.Reset();
        rStdOutReadHandle.Reset();
        rStdOutWriteHandle.Reset();
        rStdErrReadHandle.Reset();
        rStdErrWriteHandle.Reset();
    }   // if (!shProcess)

    if (shProcess)
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRunProcessWithRedirectedIO(): Done. "
                L"Return hProcess=0x%X. "
                L"LastError=\"%s\"(%u)",
            reinterpret_cast<DWORD>(shProcess.Get()),
            static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
            rdwLastError);
        OutputDebugStringW(szDebugStringW);
    }
    else    // if (shProcess)
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"SYSRunProcessWithRedirectedIO(): Return NULL. "
                L"LastError=\"%s\"(%u)",
            static_cast<LPCWSTR>(SYSGetErrorMessageW(rdwLastError)),
            rdwLastError);
        OutputDebugStringW(szDebugStringW);
    }   // if (shProcess)

    return shProcess.Release();
}   // HANDLE SYSRunProcessWithRedirectedIOW(_In_ LPCWSTR lpszApplicationNameW,
    //     _In_ LPCWSTR lpszCommandLineW, _In_ LPCWSTR lpszCurrentDirectoryW,
    //     _Out_ UniqueFile& rStdInReadHandle,
    //     _Out_ UniqueFile& rStdInWriteHandle,
    //     _Out_ UniqueFile& rStdOutReadHandle,
    //     _Out_ UniqueFile& rStdOutWriteHandle,
    //     _Out_ UniqueFile& rStdErrReadHandle,
    //     _Out_ UniqueFile& rStdErrWriteHandle, _Out_ DWORD& rdwProcessId,
    //     _Out_ DWORD& rdwLastError)
