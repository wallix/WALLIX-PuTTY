#pragma once

#include "resource.h"

struct IPLoopThreadParameter
{
    std::wstring strEventNameBase;

    std::vector<std::wstring> vecstrIPs;

    bool bTiaPortalSupport = FALSE;

    HANDLE hParentProcess = NULL;

    DWORD dwGUIThreadId = 0;
};

DWORD WINAPI IPLoopThreadProc(void* lpParameter);

void SendLogLine(LPCTSTR lpszFormat, ...);
