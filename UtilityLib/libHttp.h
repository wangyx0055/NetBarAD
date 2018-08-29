#pragma once
#include <Windows.h>
#include <stdio.h>
#include <string>
using std::string;
using std::wstring;


bool libHttp_Get(wstring wszServerName,WORD nServerPort, wstring wszObjectName, string &result);

bool libHttp_Post(wstring wszServerName,WORD nServerPort, wstring wszObjectName,string &postData, string &result);

bool libHttp_DownloadFile(const wchar_t *wszURL, const wchar_t *wszFileSavePath);

