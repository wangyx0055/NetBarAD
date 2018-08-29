#pragma once
#include "resource.h"
#include <stdlib.h>
#include <stdio.h>

#include <string>
#include <list>
#include <vector>
using std::string;
using std::wstring;
using std::list;
using std::vector;

VOID TestUtility(VOID);
VOID InjectDLL(const string &strDllDir);
VOID DoWork(VOID);
BOOL SelfDel();
VOID WriteLogFile(LPCSTR szLog);