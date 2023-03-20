// IpLoop.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "iploop.h"

#include <vector>

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
TCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
TCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
HWND                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

int const nIdEdit = 5;

#define IDT_LOGLINES 10

HWND hwndMainFrame = NULL;
HWND hwndParent = NULL;

CRITICAL_SECTION csLogLines;
std::wstring strLogLines;

std::wstring strParentWindowTitle;

IPLoopThreadParameter parameters;

bool RaiseEndEvent(LPCTSTR lpszBaseEventName, LPCTSTR lpszMsgBoxTitle)
{
    TCHAR strEventName[MAX_PATH];
    _tcscat(strEventName, _T("Local\\"));
    wcscpy(strEventName, lpszBaseEventName);
    wcscat(strEventName, L"-SA");

    HANDLE hEvent = OpenEvent(SYNCHRONIZE | DELETE | EVENT_MODIFY_STATE, FALSE, strEventName);
    if (NULL == hEvent)
    {
        if (lpszMsgBoxTitle)
        {
            MessageBox(NULL, _T("Cannot open an existing named event object!"), lpszMsgBoxTitle, MB_ICONERROR | MB_OK);
        }
        return false;
    }

    SetEvent(hEvent);
    CloseHandle(hEvent);

    return true;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    // TODO: Place code here.
    OutputDebugString(lpCmdLine);

    // Initialize global strings
    LoadString(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);

    int nArgs;
    LPWSTR* szArglistW = CommandLineToArgvW(lpCmdLine, &nArgs);
    if (NULL == szArglistW) {
        MessageBox(NULL, _T("Cannot parse command line!"), szTitle, MB_ICONERROR | MB_OK);
        return FALSE;
    }
    if (nArgs < 2) {
        MessageBox(NULL, _T("iploop event_name ip1 [ip2 [...]] [/tia] [/parent process_id] [/window parent_wnd] [/begin-standalone | /end-standalone]"), szTitle, MB_ICONERROR | MB_OK);
        LocalFree(szArglistW);
        return FALSE;
    }

    parameters.strEventNameBase = szArglistW[0];
    parameters.dwGUIThreadId    = GetCurrentThreadId();

    for (int i = 1; i < nArgs; ++i)
    {
        if (!lstrcmpi(szArglistW[i], _T("/begin-standalone")))
        {
            parameters.bStandaloneMode = true;
        }
        else if (!lstrcmpi(szArglistW[i], _T("/end-standalone")))
        {
            bool const bResult = RaiseEndEvent(parameters.strEventNameBase.c_str(), szTitle);
            LocalFree(szArglistW);
            return bResult ? TRUE : FALSE;
        }
        else if (!lstrcmpi(szArglistW[i], _T("/parent")))
        {
            if (i < nArgs - 1)
            {
                ++i;

                std::wistringstream iss(szArglistW[i]);
                DWORD dwParentId = 0;
                iss >> dwParentId;
                parameters.hParentProcess = OpenProcess(SYNCHRONIZE, FALSE, dwParentId);
            }
            else
            {
                MessageBox(NULL, _T("Please provide handle of parent process!"), szTitle, MB_ICONERROR | MB_OK);
                LocalFree(szArglistW);
                return FALSE;
            }
        }
        else if (!lstrcmpi(szArglistW[i], _T("/tia")))
        {
            OutputDebugStringW(L"_tWinMain(): Enable TIA portal support.");

            parameters.bTiaPortalSupport = true;
        }
        else if (!lstrcmpi(szArglistW[i], _T("/window")))
        {
            if (i < nArgs - 1)
            {
                ++i;

                std::wistringstream iss(szArglistW[i]);
                DWORD dwParentWnd = 0;
                iss >> dwParentWnd;
                hwndParent = reinterpret_cast<HWND>(dwParentWnd);
            }                
            else
            {
                MessageBox(NULL, _T("Please provide handle of parent window!"), szTitle, MB_ICONERROR | MB_OK);
                LocalFree(szArglistW);
                return FALSE;
            }
        }
        else
        {
            parameters.vecstrIPs.emplace_back(szArglistW[i]);
        }
    }


    LocalFree(szArglistW);

    LoadString(hInstance, IDC_IPLOOP, szWindowClass, MAX_LOADSTRING);

    MyRegisterClass(hInstance);

    // Perform application initialization:
    hwndMainFrame = InitInstance(hInstance,
        parameters.hParentProcess ? nCmdShow : SW_HIDE);
    if (!hwndMainFrame)
    {
        return FALSE;
    }

    InitializeCriticalSection(&csLogLines);

    if (!SetTimer(hwndMainFrame, IDT_LOGLINES, 500, NULL))
    {
        PostQuitMessage(0);
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_IPLOOP));

    SendLogLine(_T("_tWinMain(): IPLoop started."));

    HANDLE hIPLoopThread = CreateThread(NULL, 0, IPLoopThreadProc, &parameters, 0, NULL);
    if (!hIPLoopThread)
    {
        SendLogLine(_T("_tWinMain(): Failed to create worker thread!"));
    }

    // Main message loop:
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    KillTimer(hwndMainFrame, IDT_LOGLINES);

    DeleteCriticalSection(&csLogLines);

    if (parameters.hParentProcess)
    {
        CloseHandle(parameters.hParentProcess);
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex { 0 };

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_IPLOOP));
    wcex.hCursor        = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_3DFACE + 1);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_IPLOOP));

    return RegisterClassEx(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
HWND InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   HWND const hWnd = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
       CW_USEDEFAULT, CW_USEDEFAULT, 500, 300, NULL, NULL, hInstance, NULL);

   if (!hWnd)
   {
      return NULL;
   }

   EnableMenuItem(GetSystemMenu(hWnd, FALSE), SC_CLOSE,
       MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return hWnd;
}


//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int const wmId    = LOWORD(wParam);
            int const wmEvent = HIWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;

            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;

    case WM_CLOSE:
        break;

    case WM_CREATE:
        {
            HWND hwndEdit = CreateWindowEx(0, _T("EDIT"), _T(""),
                WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT | ES_MULTILINE | WS_VSCROLL | WS_HSCROLL | ES_READONLY,
                0, 0, 3200, 200,
                hWnd,
                (HMENU)nIdEdit, hInst, NULL);

            SendMessage(hwndEdit, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
        }

        break;

    case WM_ENDSESSION:
        {
            RaiseEndEvent(parameters.strEventNameBase.c_str(), nullptr);
        }
        break;

    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code here...
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_SIZE:
        {
            HWND hwndEdit = GetDlgItem(hWnd, nIdEdit);

            WORD const wWidth  = LOWORD(lParam);
            WORD const wHeight = HIWORD(lParam);

            int const nMarginWidthHeight = 10;

            if ((wWidth <= nMarginWidthHeight * 2) ||
                (wHeight <= nMarginWidthHeight * 2))
            {
                ShowWindow(hwndEdit, SW_HIDE);
            }
            else
            {
                SetWindowPos(hwndEdit, NULL, nMarginWidthHeight, nMarginWidthHeight, wWidth - nMarginWidthHeight * 2, wHeight - nMarginWidthHeight * 2, SWP_NOZORDER | SWP_SHOWWINDOW);
            }
        }
        break;

    case WM_TIMER:
        if (TryEnterCriticalSection(&csLogLines))
        {
            std::wstring strLogLinesTemp(std::move(strLogLines));

            LeaveCriticalSection(&csLogLines);

            HWND const hwndEdit = GetDlgItem(hWnd, nIdEdit);

            if (!strLogLinesTemp.empty())
            {
                int const nIndex = GetWindowTextLength(hwndEdit);

                SendMessage(hwndEdit, EM_SETSEL, nIndex, nIndex);
                SendMessage(hwndEdit, EM_REPLACESEL, 0, (LPARAM)strLogLinesTemp.c_str());

                SetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            }
        }

        if (hwndParent)
        {
            TCHAR szParentWindowTitle[512];
            GetWindowText(hwndParent, szParentWindowTitle, _countof(szParentWindowTitle));

            if (strParentWindowTitle.compare(szParentWindowTitle))
            {
                std::wstring strWindowTitle { szTitle };

                strWindowTitle.append(_T(" - "));
                strWindowTitle.append(szParentWindowTitle);

                SetWindowText(hWnd, strWindowTitle.c_str());

                strParentWindowTitle = szParentWindowTitle;
            }
        }
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

void SendLogLine(LPCTSTR lpszFormat, ...)
{
    TCHAR szLogLine[2048];

    va_list args;
    va_start(args, lpszFormat);

    _vsntprintf(szLogLine, _countof(szLogLine), lpszFormat, args);

    va_end(args);

    _tcscat(szLogLine, _T("\r\n"));

    EnterCriticalSection(&csLogLines);

    strLogLines.append(szLogLine);

    LeaveCriticalSection(&csLogLines);

    OutputDebugString(szLogLine);
}