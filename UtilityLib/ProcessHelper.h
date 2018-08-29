#pragma once
#include <Windows.h>

DWORD GetProcessidFromProcessName(LPCTSTR szProcessName);

BOOL IsHaveProcess(TCHAR *szProcessName);
BOOL IsHaveProcessEx(DWORD dwPID);