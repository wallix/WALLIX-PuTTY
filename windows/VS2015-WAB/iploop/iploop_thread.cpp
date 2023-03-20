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

//int error(const wchar_t* message, DWORD code);

static const wchar_t* appname = L"WALLIX PuTYY IP Loopback Manager";

//static char           szSvcLocalAddressAndPortA[] = "0.0.0.0:102";
static TCHAR          szSvcLocalAddress[]         = _T("0.0.0.0");
static unsigned short usSvcLocalPort              = 102;

static wchar_t szSvcNameW[] = L"s7oiehsx64";

/*
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
        ::SendLogLine(_T("ListeningPortPresenceChecker::CheckResult(): ..."));

        if (!IsInProgress())
        {
            assert(false);

            ::SendLogLine(_T("ListeningPortPresenceChecker::CheckResult(): ")
                _T("The checker is not in-progress! Return"));

            return;
        }   // if (!IsInProgress())

        if (WAIT_OBJECT_0 == ::WaitForSingleObject(m_shProcess.Get(), 0))
        {
            ::SendLogLine(_T("ListeningPortPresenceChecker::CheckResult(): ")
                _T("The process object is signaled."));

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
                    ::SendLogLine(_T("ListeningPortPresenceChecker::CheckResult(): ")
                        _T("The data area passed to a system call is too small! (STDOUT)"));
                }   // if (dwNumberOfBytesRead < dwNumberOfBytesToRead)
            }
            else    // if (::ReadFile(m_shStdOutRead.Get(), szOutputData,
            {
                DWORD const dwLastError = ::GetLastError();
                ::SendLogLine(_T("ListeningPortPresenceChecker::CheckResult(): ")
                        _T("Failed to read anonymous pipe! (STDOUT)")
                        _T("LastError=\"%s\"(%u)"),
                    static_cast<LPCTSTR>(::SYSGetErrorMessageW(dwLastError)),
                    dwLastError);
            }   // if (::ReadFile(m_shStdOutRead.Get(), szOutputData,

            m_shProcess.Reset();

            m_shStdInRead.Reset();
            m_shStdInWrite.Reset();
            m_shStdOutRead.Reset();
            m_shStdOutWrite.Reset();
            m_shStdErrRead.Reset();
            m_shStdErrWrite.Reset();
        }   // if (WAIT_OBJECT_0 == ::WaitForSingleObject(m_shProcess.Get(), 0))

        ::SendLogLine(L"ListeningPortPresenceChecker::CheckResult(): Done. "
            L"AlwaysInProgress=%s",
            (IsInProgress() ? L"yes" : L"no"));
    }

private:
    void ParseResult(LPCSTR lpszResultA)
    {
        ::SendLogLine(_T("ListeningPortPresenceChecker::ParseResult(): ..."));

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
                (!::_stricmp("LISTENING", vstringsA[3].c_str()) ||
//                 !::strcmp("ABHÖREN", vstringsA[3].c_str()) ||
                 !::strncmp("ABH", vstringsA[3].c_str(), 3)))
            {
                ::SendLogLine(
                    _T("ListeningPortPresenceChecker::ParseResult(): ")
                        _T("Listening address/port is found."));

                DWORD pid = ::atoi(vstringsA[4].c_str());

                ::SendLogLine(L"ListeningPortPresenceChecker::ParseResult(): "
                    L"PID=%u",
                    pid);

                std::wstring strNameW;
                if (::SYSGetProcessNameByIdW(strNameW, pid))
                {
                    ::SendLogLine(L"ListeningPortPresenceChecker::ParseResult(): "
                        L"ProcessName=\"%s\"",
                        strNameW.c_str());

                    if (!::lstrcmpiW(strNameW.c_str(), L"svchost.exe"))
                    {
                        m_bListeningPortFound = true;
                    }
                }

                m_bListeningPortFound = true;
            }
        }

        ::SendLogLine(L"ListeningPortPresenceChecker::ParseResult(): Done. "
            L"ListeningPortFound=%s",
            (m_bListeningPortFound ? L"yes" : L"no"));
    }

public:
    void Start()
    {
        ::SendLogLine(_T("ListeningPortPresenceChecker::Start(): ..."));

        if (IsInProgress())
        {
            assert(false);

            ::SendLogLine(_T("ListeningPortPresenceChecker::Start(): ")
                    _T("The task is already in-progress! Return"));

            return;
        }   // if (IsInProgress())

        LPCWSTR      lpszApplicationNameW  = nullptr;
        std::wstring strCommandLineW       =
            L"NETSTAT.EXE -ano -p tcp";
        LPCWSTR      lpszCurrentDirectoryW = nullptr;

        ::SendLogLine(L"ListeningPortPresenceChecker::Start(): "
                L"CommandLine=\"%s\"",
            strCommandLineW.c_str());

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
            ::SendLogLine(L"ListeningPortPresenceChecker::Start(): "
                    L"Failed to create child process! "
                    L"LastError=\"%s\"(%u)",
                static_cast<LPCWSTR>(::SYSGetErrorMessageW(dwLastError)),
                dwLastError);
        }   // if (!m_shProcess || (ERROR_SUCCESS != dwLastError))

        ::SendLogLine(_T("ListeningPortPresenceChecker::Start(): Done."));
    }
};
*/

#if defined(_UNICODE) || defined(UNICODE)

using tstring = std::wstring;

#else   // #if defined(_UNICODE) || defined(UNICODE)

using tstring = std::string;

#endif  // #if defined(_UNICODE) || defined(UNICODE)

class ListeningPortPresenceChecker2
{
    tstring m_strLocalAddress;

    unsigned short m_usLocalPort = 0;

    bool m_bIsListeningPortFound = false;

public:
    ListeningPortPresenceChecker2(LPCTSTR pszLocalAddress, unsigned short usLocalPort) :
        m_strLocalAddress(pszLocalAddress), m_usLocalPort(usLocalPort) {}

    bool IsInProgress() const
    {
        return false;
    }

    bool IsListeningPortFound() const
    {
        return m_bIsListeningPortFound;
    }

private:
    static TCHAR *
        rep_inet_ntoa(struct in_addr ina, TCHAR * out_buf,
            size_t out_buf_len)
    {
        unsigned char * ucp = (unsigned char *)&ina;

        _sntprintf_s(out_buf, out_buf_len, _TRUNCATE, _T("%d.%d.%d.%d"),
            ucp[0] & 0xff,
            ucp[1] & 0xff,
            ucp[2] & 0xff,
            ucp[3] & 0xff);

        return out_buf;
    }

    static void STRTrimTrailingNullCharacters(_Inout_ tstring& rstr)
    {
        size_t const ulPos = rstr.find_last_not_of(_T('\0'));
        rstr.resize((std::string::npos == ulPos) ? 0 : ulPos + 1);
    }   // void STRTrimTrailingNullCharacters(_Inout_ tstring& rstr)

    static LPCTSTR NETGetTCPConnectionStateName(_In_ DWORD dwState)
    {
        switch (dwState)
        {
        case MIB_TCP_STATE_CLOSED:
            return _T("MIB_TCP_STATE_CLOSED");
        case MIB_TCP_STATE_LISTEN:
            return _T("MIB_TCP_STATE_LISTEN");
        case MIB_TCP_STATE_SYN_SENT:
            return _T("MIB_TCP_STATE_SYN_SENT");
        case MIB_TCP_STATE_SYN_RCVD:
            return _T("MIB_TCP_STATE_SYN_RCVD");
        case MIB_TCP_STATE_ESTAB:
            return _T("MIB_TCP_STATE_ESTAB");
        case MIB_TCP_STATE_FIN_WAIT1:
            return _T("MIB_TCP_STATE_FIN_WAIT1");
        case MIB_TCP_STATE_FIN_WAIT2:
            return _T("MIB_TCP_STATE_FIN_WAIT2");
        case MIB_TCP_STATE_CLOSE_WAIT:
            return _T("MIB_TCP_STATE_CLOSE_WAIT");
        case MIB_TCP_STATE_CLOSING:
            return _T("MIB_TCP_STATE_CLOSING");
        case MIB_TCP_STATE_LAST_ACK:
            return _T("MIB_TCP_STATE_LAST_ACK");
        case MIB_TCP_STATE_TIME_WAIT:
            return _T("MIB_TCP_STATE_TIME_WAIT");
        case MIB_TCP_STATE_DELETE_TCB:
            return _T("MIB_TCP_STATE_DELETE_TCB");
        default:
            return _T("<unknown>");
        }   // switch (dwState)
    }   // LPCTSTR NETGetTCPConnectionStateName(_In_ DWORD dwState)

public:
    void CheckResult()
    {
    }

    void Start()
    {
        DWORD dwSize = 0;
        DWORD dwResult = ::GetExtendedTcpTable(
                /*pTcpTable  =*/ NULL,
                /*pdwSize    =*/ &dwSize,
                /*bOrder     =*/ TRUE,
                /*ulAf       =*/ AF_INET,
                /*TableClass =*/ TCP_TABLE_OWNER_PID_ALL,
                /*Reserved   =*/ 0
            );
        if (ERROR_INSUFFICIENT_BUFFER == dwResult)
        {
            std::unique_ptr<BYTE[]> spbarrTcpTableData(new BYTE[dwSize]);

            PMIB_TCPTABLE_OWNER_PID pMIB_TCPTable_Owner_PID =
                reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(spbarrTcpTableData.get());

            dwResult = ::GetExtendedTcpTable(
                    /*pTcpTable  =*/ pMIB_TCPTable_Owner_PID,
                    /*pdwSize    =*/ &dwSize,
                    /*bOrder     =*/ TRUE,
                    /*ulAf       =*/ AF_INET,
                    /*TableClass =*/ TCP_TABLE_OWNER_PID_ALL,
                    /*Reserved   =*/ 0
                );
            if (NO_ERROR == dwResult)
            {
                for (DWORD i = 0; i < pMIB_TCPTable_Owner_PID->dwNumEntries; ++i)
                {
                    MIB_TCPROW_OWNER_PID & MIB_TCPRow_Owner_PID =
                        pMIB_TCPTable_Owner_PID->table[i];

                    struct in_addr ina = { 0 };
                    ina.S_un.S_addr = MIB_TCPRow_Owner_PID.dwLocalAddr;
                    tstring local_address;
                    size_t const IPV4_ADDRESS_BUFFER_SIZE = 4 * sizeof "123";
                    local_address.resize(IPV4_ADDRESS_BUFFER_SIZE);
                    rep_inet_ntoa(ina, &local_address[0],
                        local_address.size());
                    STRTrimTrailingNullCharacters(local_address);

                    struct in_addr outa = { 0 };
                    outa.S_un.S_addr = MIB_TCPRow_Owner_PID.dwRemoteAddr;
                    tstring remote_address;
                    remote_address.resize(IPV4_ADDRESS_BUFFER_SIZE);
                    rep_inet_ntoa(outa, &remote_address[0],
                        remote_address.size());
                    STRTrimTrailingNullCharacters(remote_address);

/*
                    {
                        ::SendLogLine(
                            _T("ListeningPortPresenceChecker2::Start(): ")
                                _T("Network endpoint identified. ")
                                _T("State=%s(%d) ")
                                _T("LocalAddress=%s LocalPort=%u ")
                                _T("RemoteAddress=%s RemotePort=%u ")
                                _T("OwningPid=%u"),
                            NETGetTCPConnectionStateName(
                                MIB_TCPRow_Owner_PID.dwState),
                            MIB_TCPRow_Owner_PID.dwState,
                            local_address.c_str(),
                            htons((unsigned short)
                                MIB_TCPRow_Owner_PID.dwLocalPort),
                            remote_address.c_str(),
                            htons((unsigned short)
                                MIB_TCPRow_Owner_PID.dwRemotePort),
                            MIB_TCPRow_Owner_PID.dwOwningPid);
                    }
*/

                    switch (MIB_TCPRow_Owner_PID.dwState)
                    {
                    case MIB_TCP_STATE_CLOSED:
                    case MIB_TCP_STATE_SYN_SENT:
                    case MIB_TCP_STATE_SYN_RCVD:
                    case MIB_TCP_STATE_ESTAB:
                    case MIB_TCP_STATE_FIN_WAIT1:
                    case MIB_TCP_STATE_FIN_WAIT2:
                    case MIB_TCP_STATE_CLOSE_WAIT:
                    case MIB_TCP_STATE_CLOSING:
                    case MIB_TCP_STATE_LAST_ACK:
                    case MIB_TCP_STATE_TIME_WAIT:
                    case MIB_TCP_STATE_DELETE_TCB:
/*
                        ::SendLogLine(
                            _T("ListeningPortPresenceChecker2::Start(): ")
                                _T("Ignored due to state of connection."));
*/
                        continue;

                    case MIB_TCP_STATE_LISTEN:
                        if (!m_strLocalAddress.compare(local_address) &&
                            htons((unsigned short)MIB_TCPRow_Owner_PID.dwLocalPort) == m_usLocalPort)
                        {
                            m_bIsListeningPortFound = true;
                        }
/*
                        else {
                            ::SendLogLine(
                                _T("ListeningPortPresenceChecker2::Start(): ")
                                    _T("ExpectedAddr=%s GotAddr=%s ")
                                    _T("ExpectedPort=%u GotPort=%u"),
                                m_strLocalAddress.c_str(), local_address.c_str(),
                                m_usLocalPort, htons((unsigned short)MIB_TCPRow_Owner_PID.dwLocalPort));
                        }
*/
                        break;
                    }   // switch (MIB_TCPRow_Owner_PID.dwState)

                }   // for (DWORD i = 0; i < ...
            }
            else    // if (NO_ERROR == dwResult)
            {
                ::SendLogLine(
                    _T("ListeningPortPresenceChecker2::Start(): ")
                        _T("Failed to retrieve the list of TCP endpoints. ")
                        _T("Result=%u"),
                    dwResult);
            }   // if (NO_ERROR == dwResult)
        }
        else    // if (ERROR_INSUFFICIENT_BUFFER == dwResult)
        {
            ::SendLogLine(
                _T("ListeningPortPresenceChecker2::Start(): ")
                    _T("Failed to determine required buffer size to hold ")
                        _T("the list of TCP endpoints. ")
                    _T("Result=%u"),
                dwResult);
        }   // if (ERROR_INSUFFICIENT_BUFFER == dwResult)
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
        SendLogLine(L"DoStartSvc(): OpenSCManager failed! LastError=0x%X", GetLastError());
        return;
    }

    // Get a handle to the service.

    SC_HANDLE schService = OpenServiceW(
        schSCManager,         // SCM database
        szSvcNameW,           // name of service
        SERVICE_ALL_ACCESS);  // full access

    if (schService == NULL)
    {
        SendLogLine(L"DoStartSvc(): OpenService failed! LastError=0x%X", GetLastError());
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
        SendLogLine(L"DoStartSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
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
            SendLogLine(L"DoStartSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
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
                SendLogLine(L"DoStartSvc(): Timeout waiting for service to stop!");
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
        SendLogLine(L"DoStartSvc(): StartService failed! LastError=0x%X", GetLastError());
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return;
    }
    else SendLogLine(L"DoStartSvc(): Service start pending...");

    // Check the status until the service is no longer start pending.

    if (!QueryServiceStatusEx(
            schService,                     // handle to service
            SC_STATUS_PROCESS_INFO,         // info level
            (LPBYTE) &ssStatus,             // address of structure
            sizeof(SERVICE_STATUS_PROCESS), // size of structure
            &dwBytesNeeded ) )              // if buffer too small
    {
        SendLogLine(L"DoStartSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
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
            SendLogLine(L"DoStartSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
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

    if (ssStatus.dwCurrentState == SERVICE_RUNNING)
    {
        SendLogLine(L"DoStartSvc(): Service started successfully.");
    }
    else
    {
        SendLogLine(L"DoStartSvc(): Service not started!");
        SendLogLine(L"DoStartSvc(): Current State: %d", ssStatus.dwCurrentState);
        SendLogLine(L"DoStartSvc(): Exit Code: %d", ssStatus.dwWin32ExitCode);
        SendLogLine(L"DoStartSvc(): Check Point: %d", ssStatus.dwCheckPoint);
        SendLogLine(L"DoStartSvc(): Wait Hint: %d", ssStatus.dwWaitHint);
    }

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
        SendLogLine(L"DoStopSvc(): OpenSCManager failed! LastError=0x%X", GetLastError());
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
        SendLogLine(L"DoStopSvc(): OpenService failed! LastError=0x%X", GetLastError());
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
        SendLogLine(L"DoStopSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
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
            SendLogLine(L"DoStopSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
            goto stop_cleanup;
        }

        if ( ssp.dwCurrentState == SERVICE_STOPPED )
        {
            goto stop_cleanup;
        }

        if ( GetTickCount() - dwStartTime > dwTimeout )
        {
            SendLogLine(L"DoStopSvc(): Service stop timed out!");
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
        SendLogLine(L"DoStopSvc(): ControlService failed! LastError=0x%X", GetLastError());
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
            SendLogLine(L"DoStopSvc(): QueryServiceStatusEx failed! LastError=0x%X", GetLastError());
            goto stop_cleanup;
        }

        if ( ssp.dwCurrentState == SERVICE_STOPPED )
            break;

        if ( GetTickCount() - dwStartTime > dwTimeout )
        {
            SendLogLine(L"DoStopSvc(): Wait timed out!");
            goto stop_cleanup;
        }
    }
    SendLogLine(L"DoStopSvc(): Service stopped successfully.");

stop_cleanup:
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

void unmap(ULONG* nte, int n) {
    for (int i = 0; i < n; i++) {
        DWORD ret = DeleteIPAddress(nte[i]);
        if (ret != NO_ERROR) {
            SendLogLine(L"unmap(): Cannot unmap address from loopback inerface (%d)", i);
        }
    }
}

int WINAPI_wWinMain(IPLoopThreadParameter const* const lpThreadParameters) {
    int nbContexts = 0;
    HANDLE heap = GetProcessHeap();
    if (NULL == heap) {
        SendLogLine(L"IPLoopMain(): Cannot get process heap! LastError=0x%X", GetLastError());
        return 1;
    }
    ULONG* NTEContexts = (ULONG*)HeapAlloc(heap, HEAP_GENERATE_EXCEPTIONS, sizeof(ULONG) * lpThreadParameters->vecstrIPs.size());
    if (NULL == NTEContexts) {
        SendLogLine(L"IPLoopMain(): Cannot allocate NTE Contexts! LastError=0x%X", GetLastError());    
        return 1;
    }

	SendLogLine(L"IPLoopMain(): NTE Context allocated.");

    ADDRINFOW hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    WSADATA wsaData;
    DWORD wsaErr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaErr != 0) {
        SendLogLine(L"IPLoopMain(): Winsock initialization failed! LastError=0x%X", wsaErr);
        return 1;
    }

	SendLogLine(L"IPLoopMain(): Winsock initialized.");

    wchar_t eventNameI2P[MAX_PATH];
    wcscpy(eventNameI2P, lpThreadParameters->strEventNameBase.c_str());
    wcscat(eventNameI2P, L"-I2P");
    HANDLE event_i2p = NULL;
    if (!lpThreadParameters->bStandaloneMode) {
        event_i2p = OpenEvent(SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE, FALSE, eventNameI2P);
        if (NULL == event_i2p) {
            SendLogLine(L"IPLoopMain(): Cannot access event (I2P)! LastError=0x%X", GetLastError());
            return 1;
        }
    }

    HANDLE event_p2i = NULL;
    if (!lpThreadParameters->bStandaloneMode) {
        wchar_t eventNameP2I[MAX_PATH];
        wcscpy(eventNameP2I, lpThreadParameters->strEventNameBase.c_str());
        wcscat(eventNameP2I, L"-P2I");
        event_p2i = OpenEvent(SYNCHRONIZE | DELETE, FALSE, eventNameP2I);
        if (NULL == event_p2i) {
            if (event_i2p) { CloseHandle(event_i2p); }
            SendLogLine(L"IPLoopMain(): Cannot access event (P2I)! LastError=0x%X", GetLastError());
            return 1;
        }
    }
    else {
        wchar_t strEventName[MAX_PATH];
        _tcscat(strEventName, _T("Local\\"));
        wcscpy(strEventName, lpThreadParameters->strEventNameBase.c_str());
        wcscat(strEventName, L"-SA");
        event_p2i = CreateEvent(NULL, TRUE, FALSE, strEventName);
        if (NULL == event_p2i) {
            if (event_i2p) { CloseHandle(event_i2p); }
            SendLogLine(L"IPLoopMain(): Cannot create standalone event (SA)! LastError=0x%X", GetLastError());
            return 1;
        }
    }

	SendLogLine(L"IPLoopMain(): Event objects opened.");

    class ServiceGuard
    {
    public:
        ServiceGuard()
        {
            ::SendLogLine(L"ServiceGuard::ServiceGuard(): Stop service ...");

            ::DoStopSvc();

            ::SendLogLine(L"ServiceGuard::ServiceGuard(): Stop service done.");
        }

        ~ServiceGuard()
        {
            ::SendLogLine(L"ServiceGuard::~ServiceGuard(): Start service ...");

            ::DoStartSvc();

            ::SendLogLine(L"ServiceGuard::~ServiceGuard(): Start service done.");
        }
    };
    std::unique_ptr<ServiceGuard> service_guard_sp;


    if (lpThreadParameters->bTiaPortalSupport)
    {
        SendLogLine(L"IPLoopMain(): Check the presence of the service local address ...");

//        ListeningPortPresenceChecker listening_port_presence_checker(szSvcLocalAddressAndPortA);
        ListeningPortPresenceChecker2 listening_port_presence_checker(szSvcLocalAddress, usSvcLocalPort);

        listening_port_presence_checker.Start();
        while (listening_port_presence_checker.IsInProgress())
        {
            Sleep(1000);
            listening_port_presence_checker.CheckResult();
        }
        if (listening_port_presence_checker.IsListeningPortFound())
        {
            SendLogLine(L"IPLoopMain(): The service local address is present.");

            service_guard_sp = std::make_unique<ServiceGuard>();

            SendLogLine(L"IPLoopMain(): Check the nonpresence of the service local address ...");

            while (true)
            {
//                ListeningPortPresenceChecker listening_port_nonpresence_checker(szSvcLocalAddressAndPortA);
                ListeningPortPresenceChecker2 listening_port_nonpresence_checker(szSvcLocalAddress, usSvcLocalPort);

                listening_port_nonpresence_checker.Start();
                while (listening_port_nonpresence_checker.IsInProgress())
                {
                    Sleep(1000);
                    listening_port_nonpresence_checker.CheckResult();
                }
                if (!listening_port_nonpresence_checker.IsListeningPortFound())
                {
                    SendLogLine(L"IPLoopMain(): The local address of the service is no longer present.");

                    break;
                }
            }
        }
        else
        {
            SendLogLine(L"IPLoopMain(): The service local address is not present.");
        }
    }

    tstring strWALLIXPuTTYLocalAddress;

    std::string strWALLIXPuTTYLocalAddressAndPortA;

    for (size_t i = 0; i < lpThreadParameters->vecstrIPs.size(); i++) {
        SendLogLine(L"IPLoopMain(): Hostname=\"%s\" (%d)", lpThreadParameters->vecstrIPs[i].c_str(), i);

        if (service_guard_sp)
        {
            SendLogLine(L"IPLoopMain(): Generate WALLIX-PuTTY local address.");

            strWALLIXPuTTYLocalAddress = lpThreadParameters->vecstrIPs[i];

            std::wstring strWALLIXPuTTYLocalAddressAndPortW = lpThreadParameters->vecstrIPs[i];
            strWALLIXPuTTYLocalAddressAndPortW += L":102";

            size_t ulNumberOfBytesWritten;
            STRWideCharToAnsi(strWALLIXPuTTYLocalAddressAndPortW.c_str(), strWALLIXPuTTYLocalAddressAndPortA,
                ulNumberOfBytesWritten);

            SendLogLine(L"IPLoopMain(): WALLIXPuTTYLocalAddress=\"%s\"",
                strWALLIXPuTTYLocalAddressAndPortW.c_str());
        }

        PADDRINFOW resAddr;
        DWORD ret = GetAddrInfoW(lpThreadParameters->vecstrIPs[i].c_str(), NULL, &hints, &resAddr);
        if (ret != 0) {
            unmap(NTEContexts, nbContexts);
            if (event_i2p) {
                CloseHandle(event_i2p);
            }
            CloseHandle(event_p2i);
            SendLogLine(_T("IPLoopMain(): Failed to translate hostname (\"%s\") to address!"), lpThreadParameters->vecstrIPs[i].c_str());
            return 1;
        }
        ULONG NTEInstance = 0;
        IN_ADDR *sin = (IN_ADDR*)(resAddr->ai_addr->sa_data + 2);
        ret = AddIPAddress((IPAddr)sin->S_un.S_addr, 0xFFFFFFFF, 1, &NTEContexts[nbContexts], &NTEInstance);
        if (ret == NO_ERROR)
        {
            nbContexts++;

            SendLogLine(L"IPLoopMain(): IP address is mapped to loopback interface.");
        }
        else if (ret == ERROR_OBJECT_ALREADY_EXISTS)
        {
            unmap(NTEContexts, nbContexts);
            if (event_i2p) {
                CloseHandle(event_i2p);
            }
            CloseHandle(event_p2i);
            SendLogLine(L"IPLoopMain(): IP address is already mapped to loopback interface!");
        }
        else 
        {
            unmap(NTEContexts, nbContexts);
            if (event_i2p) {
                CloseHandle(event_i2p);
            }
            CloseHandle(event_p2i);
            SendLogLine(L"IPLoopMain(): Cannot map IP address to loopback interface!");
            return 1;
        }
    }

    if (event_i2p) {
        SendLogLine(L"IPLoopMain(): Set event (I2P).");

        SetEvent(event_i2p);
    }

    SendLogLine(L"IPLoopMain(): Wait for event (P2I) ...");

    while (true)
    {
        if (service_guard_sp)
        {
            SendLogLine(L"IPLoopMain(): Check the presence of the WALLIX-PuTTY local address ...");

//            ListeningPortPresenceChecker listening_port_presence_checker(strWALLIXPuTTYLocalAddressAndPortA.c_str());
            ListeningPortPresenceChecker2 listening_port_presence_checker(strWALLIXPuTTYLocalAddress.c_str(), 102);

            listening_port_presence_checker.Start();
            while (listening_port_presence_checker.IsInProgress())
            {
                Sleep(1000);
                listening_port_presence_checker.CheckResult();
            }
            if (listening_port_presence_checker.IsListeningPortFound())
            {
                SendLogLine(L"IPLoopMain(): The WALLIX-PuTTY local address is present.");

                service_guard_sp.reset(nullptr);
            }
            else
            {
                SendLogLine(L"IPLoopMain(): The WALLIX-PuTTY local address is not present.");
            }
        }

        DWORD const dwWaitResult = WaitForSingleObject(event_p2i, 1000);
        if (WAIT_OBJECT_0 == dwWaitResult)
        {
            SendLogLine(L"IPLoopMain(): Event (P2I) signaled.");

            break;
        }
        else if (WAIT_TIMEOUT != dwWaitResult)
        {
            SendLogLine(L"IPLoopMain(): Event (P2I) not signaled!", GetLastError());
            break;
        }
    }

    if (event_i2p && CloseHandle(event_i2p) == FALSE) {
        SendLogLine(L"IPLoopMain(): Cannot close event (I2P)! LastError=0x%X", GetLastError());
    }

    if (CloseHandle(event_p2i) == FALSE) {
        SendLogLine(L"IPLoopMain(): Cannot close event (P2I)! LastError=0x%X", GetLastError());
    }

    unmap(NTEContexts, nbContexts);

    HeapFree(heap, 0, NTEContexts);

    SendLogLine(L"IPLoopMain(): Done.");

    return 0;
}

DWORD WINAPI IPLoopThreadProc(_In_ void* lpParameter)
{
    IPLoopThreadParameter* lpThreadParameters = reinterpret_cast<IPLoopThreadParameter*>(lpParameter);

    try
    {
        WINAPI_wWinMain(lpThreadParameters);
    }
    catch (...)
    {
    }

    ::PostThreadMessage(lpThreadParameters->dwGUIThreadId, WM_QUIT, 0, 0);

    return 0;
}