#pragma once

#include "resource.h"

#if defined(_UNICODE) || defined(UNICODE)

using tstring = std::wstring;

#else   // #if defined(_UNICODE) || defined(UNICODE)

using tstring = std::string;

#endif  // #if defined(_UNICODE) || defined(UNICODE)

struct ManagedService
{
    tstring strName;

    unsigned short usPort = 0;

    std::vector<std::wstring> vecstrIPs;
};

struct IPLoopThreadParameter
{
    std::wstring strEventNameBase;

    std::vector<std::wstring> vecstrIPs;

    std::unique_ptr<ManagedService> spService;

    HANDLE hParentProcess = NULL;

    DWORD dwGUIThreadId = 0;

    bool bStandaloneMode = false;
};

DWORD WINAPI IPLoopThreadProc(void* lpParameter);

void SendLogLine(LPCTSTR lpszFormat, ...);
