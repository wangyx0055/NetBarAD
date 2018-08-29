#pragma once
#include <stdio.h>
#include <Windows.h>
#include <string>
#include <list>
using std::string;
using std::wstring;
using std::list;

BOOL CreateRemoteThreadLoadDll(string dllPath, DWORD dwPID);
BOOL InjectDll(DWORD dwPID, char *szDllName);