// iploop.cpp : Defines the entry point for the application.
//

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files
#include <windows.h>

#include <cassert>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

// C RunTime Header Files
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <memory.h>
#include <Windows.h>
#include <tchar.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include "iploop.h"
#include "strutils.h"
#include "sysutils.h"

int error(const wchar_t* message, DWORD code);

static const wchar_t* appname = L"WALLIX PuTYY IP Loopback Manager";

static char szSvcLocalAddressA[] = "0.0.0.0:102";
static wchar_t szSvcNameW[] = L"s7oiehsx64";

class ListeningPortPresenceChecker
{
    UniqueProcess m_shProcess;

    UniqueFile m_shStdInRead;
    UniqueFile m_shStdInWrite;
    UniqueFile m_shStdOutRead;
    UniqueFile m_shStdOutWrite;
    UniqueFile m_shStdErrRead;
    UniqueFile m_shStdErrWrite;

    bool m_bListeningPortFound = false;

    const std::string m_strLocalAddressA;

public:
    ListeningPortPresenceChecker(const char * pszLocalAddressA) :
        m_strLocalAddressA(pszLocalAddressA)
    {
        char szDebugStringA[256];
        ::_snprintf(szDebugStringA, _countof(szDebugStringA),
            "ListeningPortPresenceChecker::ListeningPortPresenceChecker(): LocalAddress=\"%s\"",
            m_strLocalAddressA.c_str());
        ::OutputDebugStringA(szDebugStringA);
    }

    bool IsInProgress() const
    {
        return static_cast<bool>(m_shProcess);
    }

    bool IsListeningPortFound() const
    {
        return m_bListeningPortFound;
    }

    void CheckResult()
    {
        ::OutputDebugStringW(L"ListeningPortPresenceChecker::CheckResult(): ...");

        if (!IsInProgress())
        {
            assert(false);

            ::OutputDebugStringW(L"ListeningPortPresenceChecker::CheckResult(): "
                L"The checker is not in-progress! Return");

            return;
        }   // if (!IsInProgress())

        if (WAIT_OBJECT_0 == ::WaitForSingleObject(m_shProcess.Get(), 0))
        {
            ::OutputDebugStringW(L"ListeningPortPresenceChecker::CheckResult(): "
                L"The process object is signaled.");

            char szOutputData[32768];

            ::ZeroMemory(szOutputData, sizeof(szOutputData));

            DWORD const dwNumberOfBytesToRead = sizeof(szOutputData);
            DWORD       dwNumberOfBytesRead   = 0;

            LPOVERLAPPED lpOverlapped = nullptr;

            if (::ReadFile(m_shStdOutRead.Get(), szOutputData,
                    dwNumberOfBytesToRead, &dwNumberOfBytesRead,
                    lpOverlapped))
            {
                if (dwNumberOfBytesRead < dwNumberOfBytesToRead)
                    ParseResult(szOutputData);
                else    // if (dwNumberOfBytesRead < dwNumberOfBytesToRead)
                {
                    ::OutputDebugStringW(L"ListeningPortPresenceChecker::CheckResult(): "
                        L"The data area passed to a system call is too small! (STDOUT)");
                }   // if (dwNumberOfBytesRead < dwNumberOfBytesToRead)
            }
            else    // if (::ReadFile(m_shStdOutRead.Get(), szOutputData,
            {
                DWORD const dwLastError = ::GetLastError();
                wchar_t szDebugStringW[256];
                ::_snwprintf(szDebugStringW, _countof(szDebugStringW),
                    L"ListeningPortPresenceChecker::CheckResult(): "
                        L"Failed to read anonymous pipe! (STDOUT)"
                        L"LastError=\"%s\"(%u)",
                    static_cast<LPCWSTR>(::SYSGetErrorMessageW(dwLastError)),
                    dwLastError);
                OutputDebugStringW(szDebugStringW);
            }   // if (::ReadFile(m_shStdOutRead.Get(), szOutputData,

            m_shProcess.Reset();

            m_shStdInRead.Reset();
            m_shStdInWrite.Reset();
            m_shStdOutRead.Reset();
            m_shStdOutWrite.Reset();
            m_shStdErrRead.Reset();
            m_shStdErrWrite.Reset();
        }   // if (WAIT_OBJECT_0 == ::WaitForSingleObject(m_shProcess.Get(), 0))

        {
            wchar_t szDebugStringW[256];
            ::_snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"ListeningPortPresenceChecker::CheckResult(): Done. "
                    L"AlwaysInProgress=%s",
                (IsInProgress() ? L"yes" : L"no"));
            ::OutputDebugStringW(szDebugStringW);
        }
    }

private:
    void ParseResult(LPCSTR lpszResultA)
    {
        ::OutputDebugStringW(
            L"ListeningPortPresenceChecker::ParseResult(): ...");

        std::istringstream issA(lpszResultA);

        std::string lineA;

        while (std::getline(issA, lineA))
        {
            std::stringstream ssA(lineA);

            std::istream_iterator<std::string> begin(ssA);
            std::istream_iterator<std::string> end;
            std::vector<std::string> vstringsA(begin, end);

            if (vstringsA.size() == 5 &&
                !::_stricmp("TCP", vstringsA[0].c_str()) &&
                !::_stricmp(m_strLocalAddressA.c_str(), vstringsA[1].c_str()) &&
                !::_stricmp("LISTENING", vstringsA[3].c_str()))
            {
                ::OutputDebugStringW(
                    L"ListeningPortPresenceChecker::ParseResult(): "
                        L"Listening address/port is found.");

                DWORD pid = ::atoi(vstringsA[4].c_str());

                {
                    wchar_t szDebugStringW[256];
                    ::_snwprintf(szDebugStringW, _countof(szDebugStringW),
                        L"ListeningPortPresenceChecker::ParseResult(): "
                            L"PID=%u",
                        pid);
                    ::OutputDebugStringW(szDebugStringW);
                }

                std::wstring strNameW;
                if (::SYSGetProcessNameByIdW(strNameW, pid))
                {
                    {
                        wchar_t szDebugStringW[256];
                        ::_snwprintf(szDebugStringW, _countof(szDebugStringW),
                            L"ListeningPortPresenceChecker::ParseResult(): "
                                L"ProcessName=\"%s\"",
                            strNameW.c_str());
                        ::OutputDebugStringW(szDebugStringW);
                    }

                    if (!::lstrcmpiW(strNameW.c_str(), L"svchost.exe"))
                    {
                        m_bListeningPortFound = true;
                    }
                }

                m_bListeningPortFound = true;
            }
        }

        {
            wchar_t szDebugStringW[256];
            ::_snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"ListeningPortPresenceChecker::ParseResult(): Done. "
                    L"ListeningPortFound=%s",
                (m_bListeningPortFound ? L"yes" : L"no"));
            ::OutputDebugStringW(szDebugStringW);
        }
    }

public:
    void Start()
    {
        ::OutputDebugStringW(
            L"ListeningPortPresenceChecker::Start(): ...");

        if (IsInProgress())
        {
            assert(false);

            ::OutputDebugStringW(L"ListeningPortPresenceChecker::Start(): "
                    L"The task is already in-progress! Return");

            return;
        }   // if (IsInProgress())

        LPCWSTR      lpszApplicationNameW  = nullptr;
        std::wstring strCommandLineW       =
            L"NETSTAT.EXE -ano -p tcp";
        LPCWSTR      lpszCurrentDirectoryW = nullptr;

        {
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"ListeningPortPresenceChecker::Start(): "
                    L"CommandLine=\"%s\"",
                strCommandLineW.c_str());
            OutputDebugStringW(szDebugStringW);
        }   // if (pLogger)

        DWORD dwProcessId = 0;
        DWORD dwLastError = ERROR_SUCCESS;

        m_shProcess.Reset(
                ::SYSRunProcessWithRedirectedIOW(
                        lpszApplicationNameW, strCommandLineW.c_str(),
                        lpszCurrentDirectoryW,
                        m_shStdInRead, m_shStdInWrite,
                        m_shStdOutRead, m_shStdOutWrite,
                        m_shStdErrRead, m_shStdErrWrite,
                        dwProcessId, dwLastError
                    )
            );
        if (!m_shProcess || (ERROR_SUCCESS != dwLastError))
        {
            wchar_t szDebugStringW[256];
            _snwprintf(szDebugStringW, _countof(szDebugStringW),
                L"ListeningPortPresenceChecker::Start(): "
                    L"Failed to create child process! "
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(::SYSGetErrorMessageW(dwLastError)),
                dwLastError);
            OutputDebugStringW(szDebugStringW);
        }   // if (!m_shProcess || (ERROR_SUCCESS != dwLastError))

        ::OutputDebugStringW(
            L"ListeningPortPresenceChecker::Start(): Done.");
    }
};

VOID __stdcall DoStartSvc()
{
    SERVICE_STATUS_PROCESS ssStatus;
    DWORD dwOldCheckPoint;
    DWORD dwStartTickCount;
    DWORD dwWaitTime;
    DWORD dwBytesNeeded;

    // Get a handle to the SCM database.

    SC_HANDLE schSCManager = OpenSCManagerW(
        NULL,                    // local computer
        NULL,                    // servicesActive database
        SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        error(L"OpenSCManager failed (%d)", GetLastError());
        return;
    }

    // Get a handle to the service.

    SC_HANDLE schService = OpenServiceW(
        schSCManager,         // SCM database
        szSvcNameW,           // name of service
        SERVICE_ALL_ACCESS);  // full access

    if (schService == NULL)
    {
        error(L"OpenService failed (%d)", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Check the status in case the service is not stopped.

    if (!QueryServiceStatusEx(
            schService,                     // handle to service
            SC_STATUS_PROCESS_INFO,         // information level
            (LPBYTE) &ssStatus,             // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded ) )              // size needed if buffer is too small
    {
        error(L"QueryServiceStatusEx failed (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }

    // Check if the service is already running. It would be possible
    // to stop the service here, but for simplicity this example just returns.

    if(ssStatus.dwCurrentState != SERVICE_STOPPED && ssStatus.dwCurrentState != SERVICE_STOP_PENDING)
    {
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }

    // Save the tick count and initial checkpoint.

    dwStartTickCount = GetTickCount();
    dwOldCheckPoint = ssStatus.dwCheckPoint;

    // Wait for the service to stop before attempting to start it.

    while (ssStatus.dwCurrentState == SERVICE_STOP_PENDING)
    {
        // Do not wait longer than the wait hint. A good interval is
        // one-tenth of the wait hint but not less than 1 second
        // and not more than 10 seconds.

        dwWaitTime = ssStatus.dwWaitHint / 10;

        if( dwWaitTime < 1000 )
            dwWaitTime = 1000;
        else if ( dwWaitTime > 10000 )
            dwWaitTime = 10000;

        Sleep( dwWaitTime );

        // Check the status until the service is no longer stop pending.

        if (!QueryServiceStatusEx(
                schService,                     // handle to service
                SC_STATUS_PROCESS_INFO,         // information level
                (LPBYTE) &ssStatus,             // address of structure
                sizeof(SERVICE_STATUS_PROCESS), // size of structure
                &dwBytesNeeded ) )              // size needed if buffer is too small
        {
            error(L"QueryServiceStatusEx failed (%d)", GetLastError());
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return;
        }

        if ( ssStatus.dwCheckPoint > dwOldCheckPoint )
        {
            // Continue to wait and check.

            dwStartTickCount = GetTickCount();
            dwOldCheckPoint = ssStatus.dwCheckPoint;
        }
        else
        {
            if(GetTickCount()-dwStartTickCount > ssStatus.dwWaitHint)
            {
                error(L"Timeout waiting for service to stop", ERROR_SERVICE_REQUEST_TIMEOUT);
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                return;
            }
        }
    }

    // Attempt to start the service.

    if (!StartService(
            schService,  // handle to service
            0,           // number of arguments
            NULL) )      // no arguments
    {
        error(L"StartService failed (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }
//    else printf("Service start pending...\n");

    // Check the status until the service is no longer start pending.

    if (!QueryServiceStatusEx(
            schService,                     // handle to service
            SC_STATUS_PROCESS_INFO,         // info level
            (LPBYTE) &ssStatus,             // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded ) )              // if buffer too small
    {
        error(L"QueryServiceStatusEx failed (%d)", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }

    // Save the tick count and initial checkpoint.

    dwStartTickCount = GetTickCount();
    dwOldCheckPoint = ssStatus.dwCheckPoint;

    while (ssStatus.dwCurrentState == SERVICE_START_PENDING)
    {
        // Do not wait longer than the wait hint. A good interval is
        // one-tenth the wait hint, but no less than 1 second and no
        // more than 10 seconds.

        dwWaitTime = ssStatus.dwWaitHint / 10;

        if( dwWaitTime < 1000 )
            dwWaitTime = 1000;
        else if ( dwWaitTime > 10000 )
            dwWaitTime = 10000;

        Sleep( dwWaitTime );

        // Check the status again.

        if (!QueryServiceStatusEx(
            schService,             // handle to service
            SC_STATUS_PROCESS_INFO, // info level
            (LPBYTE) &ssStatus,             // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded ) )              // if buffer too small
        {
            error(L"QueryServiceStatusEx failed (%d)", GetLastError());
            break;
        }

        if ( ssStatus.dwCheckPoint > dwOldCheckPoint )
        {
            // Continue to wait and check.

            dwStartTickCount = GetTickCount();
            dwOldCheckPoint = ssStatus.dwCheckPoint;
        }
        else
        {
            if(GetTickCount()-dwStartTickCount > ssStatus.dwWaitHint)
            {
                // No progress made within the wait hint.
                break;
            }
        }
    }

    // Determine whether the service is running.

/*
    if (ssStatus.dwCurrentState == SERVICE_RUNNING)
    {
        printf("Service started successfully.\n");
    }
    else
    {
        printf("Service not started. \n");
        printf("  Current State: %d\n", ssStatus.dwCurrentState);
        printf("  Exit Code: %d\n", ssStatus.dwWin32ExitCode);
        printf("  Check Point: %d\n", ssStatus.dwCheckPoint);
        printf("  Wait Hint: %d\n", ssStatus.dwWaitHint);
    }
*/

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

BOOL __stdcall StopDependentServices(SC_HANDLE schSCManager, SC_HANDLE schService)
{
    DWORD i;
    DWORD dwBytesNeeded;
    DWORD dwCount;

    LPENUM_SERVICE_STATUSW  lpDependenciesW = NULL;
    ENUM_SERVICE_STATUSW    essW;
    SC_HANDLE               hDepService;
    SERVICE_STATUS_PROCESS  ssp;

    DWORD dwStartTime = GetTickCount();
    DWORD dwTimeout = 30000; // 30-second time-out

    // Pass a zero-length buffer to get the required buffer size.
    if (EnumDependentServicesW(schService, SERVICE_ACTIVE,
        lpDependenciesW, 0, &dwBytesNeeded, &dwCount))
    {
        // If the Enum call succeeds, then there are no dependent
        // services, so do nothing.
        return TRUE;
    }
    else
    {
        if (GetLastError() != ERROR_MORE_DATA)
            return FALSE; // Unexpected error

        // Allocate a buffer for the dependencies.
        lpDependenciesW = (LPENUM_SERVICE_STATUSW)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);

        if (!lpDependenciesW)
            return FALSE;

        __try {
            // Enumerate the dependencies.
            if (!EnumDependentServicesW(schService, SERVICE_ACTIVE,
                lpDependenciesW, dwBytesNeeded, &dwBytesNeeded,
                &dwCount))
                return FALSE;

            for (i = 0; i < dwCount; i++)
            {
                essW = *(lpDependenciesW + i);
                // Open the service.
                hDepService = OpenServiceW(schSCManager,
                    essW.lpServiceName,
                    SERVICE_STOP | SERVICE_QUERY_STATUS);

                if (!hDepService)
                    return FALSE;

                __try {
                    // Send a stop code.
                    if (!ControlService(hDepService,
                        SERVICE_CONTROL_STOP,
                        (LPSERVICE_STATUS)&ssp))
                        return FALSE;

                    // Wait for the service to stop.
                    while (ssp.dwCurrentState != SERVICE_STOPPED)
                    {
                        Sleep(ssp.dwWaitHint);
                        if (!QueryServiceStatusEx(
                            hDepService,
                            SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&ssp,
                            sizeof(SERVICE_STATUS_PROCESS),
                            &dwBytesNeeded))
                            return FALSE;

                        if (ssp.dwCurrentState == SERVICE_STOPPED)
                            break;

                        if (GetTickCount() - dwStartTime > dwTimeout)
                            return FALSE;
                    }
                }
                __finally
                {
                    // Always release the service handle.
                    CloseServiceHandle(hDepService);
                }
            }
        }
        __finally
        {
            // Always free the enumeration buffer.
            HeapFree(GetProcessHeap(), 0, lpDependenciesW);
        }
    }
    return TRUE;
}

VOID __stdcall DoStopSvc()
{
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwStartTime = GetTickCount();
    DWORD dwBytesNeeded;
    DWORD dwTimeout = 30000; // 30-second time-out
    DWORD dwWaitTime;

    // Get a handle to the SCM database.

    SC_HANDLE schSCManager = OpenSCManagerW(
        NULL,                    // local computer
        NULL,                    // ServicesActive database
        SC_MANAGER_ALL_ACCESS);  // full access rights

    if (NULL == schSCManager)
    {
        error(L"OpenSCManager failed (%d)", GetLastError());
        return;
    }

    // Get a handle to the service.

    SC_HANDLE schService = OpenService(
        schSCManager,         // SCM database
        szSvcNameW,            // name of service
        SERVICE_STOP |
        SERVICE_QUERY_STATUS |
        SERVICE_ENUMERATE_DEPENDENTS);

    if (schService == NULL)
    {
        error(L"OpenService failed (%d)", GetLastError());
        CloseServiceHandle(schSCManager);
        return;
    }

    // Make sure the service is not already stopped.

    if ( !QueryServiceStatusEx(
            schService,
            SC_STATUS_PROCESS_INFO,
            (LPBYTE)&ssp,
            sizeof(SERVICE_STATUS_PROCESS),
            &dwBytesNeeded ) )
    {
        error(L"QueryServiceStatusEx failed (%d)", GetLastError());
        goto stop_cleanup;
    }

    if ( ssp.dwCurrentState == SERVICE_STOPPED )
    {
        goto stop_cleanup;
    }

    // If a stop is pending, wait for it.

    while ( ssp.dwCurrentState == SERVICE_STOP_PENDING )
    {
        // Do not wait longer than the wait hint. A good interval is
        // one-tenth of the wait hint but not less than 1 second
        // and not more than 10 seconds.

        dwWaitTime = ssp.dwWaitHint / 10;

        if( dwWaitTime < 1000 )
            dwWaitTime = 1000;
        else if ( dwWaitTime > 10000 )
            dwWaitTime = 10000;

        Sleep( dwWaitTime );

        if ( !QueryServiceStatusEx(
                 schService,
                 SC_STATUS_PROCESS_INFO,
                 (LPBYTE)&ssp,
                 sizeof(SERVICE_STATUS_PROCESS),
                 &dwBytesNeeded ) )
        {
            error(L"QueryServiceStatusEx failed (%d)", GetLastError());
            goto stop_cleanup;
        }

        if ( ssp.dwCurrentState == SERVICE_STOPPED )
        {
            goto stop_cleanup;
        }

        if ( GetTickCount() - dwStartTime > dwTimeout )
        {
            error(L"Service stop timed out.", ERROR_SERVICE_REQUEST_TIMEOUT);
            goto stop_cleanup;
        }
    }

    // If the service is running, dependencies must be stopped first.

    StopDependentServices(schSCManager, schService);

    // Send a stop code to the service.

    if ( !ControlService(
            schService,
            SERVICE_CONTROL_STOP,
            (LPSERVICE_STATUS) &ssp ) )
    {
        error(L"ControlService failed (%d)", GetLastError() );
        goto stop_cleanup;
    }

    // Wait for the service to stop.

    while ( ssp.dwCurrentState != SERVICE_STOPPED )
    {
        Sleep( ssp.dwWaitHint );
        if ( !QueryServiceStatusEx(
                schService,
                SC_STATUS_PROCESS_INFO,
                (LPBYTE)&ssp,
                sizeof(SERVICE_STATUS_PROCESS),
                &dwBytesNeeded ) )
        {
            error(L"QueryServiceStatusEx failed (%d)", GetLastError() );
            goto stop_cleanup;
        }

        if ( ssp.dwCurrentState == SERVICE_STOPPED )
            break;

        if ( GetTickCount() - dwStartTime > dwTimeout )
        {
            error(L"Wait timed out", ERROR_SERVICE_REQUEST_TIMEOUT);
            goto stop_cleanup;
        }
    }
//    printf("Service stopped successfully\n");

stop_cleanup:
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

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
    {
        wchar_t szDebugStringW[256];
        _snwprintf(szDebugStringW, _countof(szDebugStringW),
            L"wWinMain(): ... CommandLine=\"%s\"",
            pCmdLine);
        OutputDebugStringW(szDebugStringW);
    }

    int nArgs;
    LPWSTR* szArglist = CommandLineToArgvW(pCmdLine, &nArgs);
    if (NULL == szArglist) {
        MessageBox(NULL, L"Cannot parse command line", appname, MB_ICONERROR | MB_OK);
        return 1;
    }
    if (nArgs < 2) {
        LocalFree(szArglist);
        MessageBox(NULL, L"iploop <event name> ip1 ip2...", appname, MB_ICONERROR | MB_OK);
        return 1;
    }

    wchar_t* eventNameBase = szArglist[0];

    bool tia_portal = false;
    for (int i = 1; i < nArgs; i++) {
        if (!lstrcmpiW(szArglist[i], L"/tia"))
        {
            OutputDebugStringW(L"wWinMain(): Enable TIA portal support.");

            tia_portal = true;
            break;
        }
    }

	OutputDebugStringW(L"wWinMain(): Command line parsed.");

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

	OutputDebugStringW(L"wWinMain(): NTE Context allocated.");

    ADDRINFOW hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    WSADATA wsaData;
    DWORD wsaErr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaErr != 0) {
        return error(L"Winsock initialization failed", wsaErr);
    }

	OutputDebugStringW(L"wWinMain(): Winsock initialized.");

    wchar_t eventNameI2P[MAX_PATH];
    wcscpy(eventNameI2P, eventNameBase);
    wcscat(eventNameI2P, L"-I2P");
    HANDLE event_i2p = OpenEvent(SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE, FALSE, eventNameI2P);
    if (NULL == event_i2p) {
        return error(L"Cannot access event (I2P)", GetLastError());
    }

    wchar_t eventNameP2I[MAX_PATH];
    wcscpy(eventNameP2I, eventNameBase);
    wcscat(eventNameP2I, L"-P2I");
    HANDLE event_p2i = OpenEvent(SYNCHRONIZE | DELETE, FALSE, eventNameP2I);
    if (NULL == event_p2i) {
        CloseHandle(event_i2p);
        return error(L"Cannot access event (P2I)", GetLastError());
    }

	OutputDebugStringW(L"wWinMain(): Event objects opened.");

    class ServiceGuard
    {
    public:
        ServiceGuard()
        {
            ::OutputDebugStringW(L"ServiceGuard::ServiceGuard(): Stop service ...");

            ::DoStopSvc();

            ::OutputDebugStringW(L"ServiceGuard::ServiceGuard(): Stop service done.");
        }

        ~ServiceGuard()
        {
            ::OutputDebugStringW(L"ServiceGuard::~ServiceGuard(): Start service ...");

            ::DoStartSvc();

            ::OutputDebugStringW(L"ServiceGuard::~ServiceGuard(): Start service done.");
        }
    };
    std::unique_ptr<ServiceGuard> service_guard_sp;


    if (tia_portal)
    {
        OutputDebugStringW(L"wWinMain(): Check the presence of the service local address ...");

        ListeningPortPresenceChecker listening_port_presence_checker(szSvcLocalAddressA);

        listening_port_presence_checker.Start();
        while (listening_port_presence_checker.IsInProgress())
        {
            Sleep(1000);
            listening_port_presence_checker.CheckResult();
        }
        if (listening_port_presence_checker.IsListeningPortFound())
        {
            OutputDebugStringW(L"wWinMain(): The service local address is present.");

            service_guard_sp = std::make_unique<ServiceGuard>();

            OutputDebugStringW(L"wWinMain(): Check the nonpresence of the service local address ...");

            while (true)
            {
                ListeningPortPresenceChecker listening_port_nonpresence_checker(szSvcLocalAddressA);

                listening_port_nonpresence_checker.Start();
                while (listening_port_nonpresence_checker.IsInProgress())
                {
                    Sleep(1000);
                    listening_port_nonpresence_checker.CheckResult();
                }
                if (!listening_port_nonpresence_checker.IsListeningPortFound())
                {
                    OutputDebugStringW(L"wWinMain(): The local address of the service is no longer present.");

                    break;
                }
            }
        }
        else
        {
            OutputDebugStringW(L"wWinMain(): The service local address is not present.");
        }
    }

    std::string strWALLIXPuTTYLocalAddressA;

    for (int i = 1; i < nArgs; i++) {
        if (!lstrcmpiW(szArglist[i], L"/tia"))
        {
            continue;
        }
        else if (service_guard_sp)
        {
			OutputDebugStringW(L"wWinMain(): Generate WALLIX-PuTTY local address.");

            std::wstring strWALLIXPuTTYLocalAddressW = szArglist[i];
            strWALLIXPuTTYLocalAddressW += L":102";

            size_t ulNumberOfBytesWritten;
            STRWideCharToAnsi(strWALLIXPuTTYLocalAddressW.c_str(), strWALLIXPuTTYLocalAddressA,
                ulNumberOfBytesWritten);

            {
                char szDebugStringA[256];
                _snprintf(szDebugStringA, _countof(szDebugStringA),
                    "wWinMain(): WALLIXPuTTYLocalAddress=\"%s\"",
                    strWALLIXPuTTYLocalAddressA.c_str());
                OutputDebugStringA(szDebugStringA);
            }
        }

        PADDRINFOW resAddr;
        DWORD ret = GetAddrInfoW(szArglist[i], NULL, &hints, &resAddr);
        if (ret != 0) {
            unmap(NTEContexts, nbContexts);
            return error(szArglist[i], ret);
        }
        ULONG NTEInstance = 0;
        IN_ADDR *sin = (IN_ADDR*)(resAddr->ai_addr->sa_data + 2);
        ret = AddIPAddress((IPAddr)sin->S_un.S_addr, 0xFFFFFFFF, 1, &NTEContexts[nbContexts], &NTEInstance);
        if (ret != NO_ERROR && ret != ERROR_OBJECT_ALREADY_EXISTS) {
            unmap(NTEContexts, nbContexts);
            CloseHandle(event_i2p);
            CloseHandle(event_p2i);
            return error(L"Cannot map IP address to loopback interface", ret);
        }
        if (ret != ERROR_OBJECT_ALREADY_EXISTS) {
            nbContexts++;
        }
    }

    OutputDebugStringW(L"wWinMain(): Set event (I2P).");

    SetEvent(event_i2p);

    OutputDebugStringW(L"wWinMain(): Wait for event (P2I) ...");

/*
    if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0) {
        error(L"Event not signaled", GetLastError());
    }
*/
    while (true)
    {
        if (service_guard_sp)
        {
            OutputDebugStringW(L"wWinMain(): Check the presence of the WALLIX-PuTTY local address ...");

            ListeningPortPresenceChecker listening_port_presence_checker(strWALLIXPuTTYLocalAddressA.c_str());

            listening_port_presence_checker.Start();
            while (listening_port_presence_checker.IsInProgress())
            {
                Sleep(1000);
                listening_port_presence_checker.CheckResult();
            }
            if (listening_port_presence_checker.IsListeningPortFound())
            {
                OutputDebugStringW(L"wWinMain(): The WALLIX-PuTTY local address is present.");

                service_guard_sp.reset(nullptr);
            }
            else
            {
                OutputDebugStringW(L"wWinMain(): The WALLIX-PuTTY local address is not present.");
            }
        }

        DWORD const dwWaitResult = WaitForSingleObject(event_p2i, 1000);
        if (WAIT_OBJECT_0 == dwWaitResult)
        {
            OutputDebugStringW(L"wWinMain(): Event (P2I) signaled.");

            break;
        }

        if (WAIT_TIMEOUT != dwWaitResult)
        {
            error(L"Event not signaled", GetLastError());
            break;
        }
    }

    if (CloseHandle(event_i2p) == FALSE) {
        error(L"Cannot close event (I2P)", GetLastError());
    }

    if (CloseHandle(event_p2i) == FALSE) {
        error(L"Cannot close event (P2I)", GetLastError());
    }

    unmap(NTEContexts, nbContexts);

    LocalFree(szArglist);
    HeapFree(heap, 0, NTEContexts);

    OutputDebugStringW(L"wWinMain(): Done.");

    return 0;
}