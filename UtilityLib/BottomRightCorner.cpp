#include "StdAfx.h"
#include "BottomRightCorner.h"
#include "WebBrowser.h"
#include <Windows.h>
#include <tchar.h>
#include <process.h>
CHAR g_szUrl[1024] = {0};
CHAR g_szCaption[1024] = {0};
HMODULE g_hInstance = NULL;

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}

	return 0;
}

int APIENTRY _tWinMain_RightCornerWindow(_In_ HINSTANCE     hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPTSTR        lpCmdLine,
	_In_ int           nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	const LPCTSTR CLASS_NAME = _T("WebBrowserContainer");

	WNDCLASSEX wcex    = { sizeof(WNDCLASSEX) };
	wcex.style         = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc   = WndProc;
	wcex.cbClsExtra    = 0;
	wcex.cbWndExtra    = 0;
	wcex.hInstance     = hInstance;
	wcex.hCursor       = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszClassName = CLASS_NAME;

	RegisterClassEx(&wcex);

	int nWidth  = 500;
	int nHeight = 300;
	int xPos = GetSystemMetrics(SM_CXSCREEN) - nWidth;
	int yPos = GetSystemMetrics(SM_CYSCREEN) - nHeight;

	HWND hWnd = CreateWindow(CLASS_NAME,
		g_szCaption,
		WS_OVERLAPPEDWINDOW &~ WS_MAXIMIZEBOX &~ WS_MINIMIZEBOX &~WS_BORDER,
		xPos,
		yPos,
		nWidth,
		nHeight,
		nullptr,
		nullptr,
		hInstance,
		nullptr);

	if (hWnd == nullptr)
	{
		return 0;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);

	WebBrowser wb(hWnd);
	if (!wb.CreateWebBrowser())
	{
		return 0;
	}
	//wb.Navigate(_T("http://www.csdn.net/"));
	wb.Navigate(g_szUrl);

	//SetWindowPos(hWnd, 0, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE);  // ÷√∂•

	MSG msg = {};

	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, nullptr, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;
}

unsigned int _stdcall ThreadShowWeb(VOID* param)
{
	_tWinMain_RightCornerWindow(g_hInstance, NULL, NULL, SW_SHOWNORMAL);
	return 0;
}

VOID ShowRightCornerWindow(HINSTANCE hInstance, LPCSTR szUrl, LPCSTR szCaption)
{
	strcpy(g_szUrl, szUrl);
	strcpy(g_szCaption, szCaption);
	g_hInstance = hInstance;
	_beginthreadex(NULL, 0, ThreadShowWeb, NULL, 0, NULL);
}
