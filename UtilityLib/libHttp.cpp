#include "StdAfx.h"
#include "libHttp.h"

#include <iostream>
#include <windows.h>
#include <winhttp.h> 
#pragma comment(lib,"winhttp.lib")

bool libHttp_Get(wstring wszServerName,WORD nServerPort, wstring wszObjectName, string &result)
{
	HINTERNET  hSession = NULL;
	HINTERNET  hConnect = NULL;
	HINTERNET  hRequest = NULL;
	BOOL  bResults = FALSE;
		
	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 6.1; WOW64) Chrome/45.0.2454.101",
						   WINHTTP_ACCESS_TYPE_NO_PROXY,
						   NULL,
						   NULL,
						   0);
	hConnect = WinHttpConnect(hSession, wszServerName.c_str(), nServerPort, 0);	// WINHTTP_FLAG_ASYNC 指示WinHTTP API将异步执行
	hRequest = WinHttpOpenRequest(hConnect, L"GET", wszObjectName.c_str(), L"HTTP/1.1", WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );
	bResults = WinHttpReceiveResponse(hRequest, NULL);

	if(!bResults)
	{
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return false;
	}

	DWORD dwNumberOfBytesToRead = 0;
	DWORD dwNumberOfBytesRead = 0;;
	do 
	{

		dwNumberOfBytesToRead = 0;
		WinHttpQueryDataAvailable(hRequest, &dwNumberOfBytesToRead);
		if(dwNumberOfBytesToRead <= 0) break;


		char *pbufRecv = new char[dwNumberOfBytesToRead + 1];
		ZeroMemory(pbufRecv, dwNumberOfBytesToRead + 1);
		WinHttpReadData( hRequest, (LPVOID)pbufRecv, dwNumberOfBytesToRead, &dwNumberOfBytesRead);

		result += string(pbufRecv);
				
		delete [] pbufRecv;
		pbufRecv = NULL;

	} while (dwNumberOfBytesToRead > 0);

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return true;
}

bool libHttp_Post(wstring wszServerName,WORD nServerPort, wstring wszObjectName,string &postData, string &result)
{
	HINTERNET  hSession = NULL;
	HINTERNET  hConnect = NULL;
	HINTERNET  hRequest = NULL;
	BOOL  bResults = FALSE;

	hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 6.1; WOW64) Chrome/45.0.2454.101",
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		NULL,
		NULL,
		0);
	hConnect = WinHttpConnect(hSession, wszServerName.c_str(), nServerPort, 0);	// WINHTTP_FLAG_ASYNC 指示WinHTTP API将异步执行
	hRequest = WinHttpOpenRequest(hConnect, L"POST", wszObjectName.c_str(), L"HTTP/1.1", WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
	//bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0 );
	bResults = WinHttpSendRequest(hRequest, 0, 0, (void*)(postData.c_str()), postData.length(), postData.length(), 0);
	bResults = WinHttpReceiveResponse(hRequest, NULL);

	if(!bResults)
	{
		if (hRequest) WinHttpCloseHandle(hRequest);
		if (hConnect) WinHttpCloseHandle(hConnect);
		if (hSession) WinHttpCloseHandle(hSession);
		return false;
	}

	DWORD dwNumberOfBytesToRead = 0;
	DWORD dwNumberOfBytesRead = 0;;
	do 
	{

		dwNumberOfBytesToRead = 0;
		WinHttpQueryDataAvailable(hRequest, &dwNumberOfBytesToRead);
		if(dwNumberOfBytesToRead <= 0) break;


		char *pbufRecv = new char[dwNumberOfBytesToRead + 1];
		ZeroMemory(pbufRecv, dwNumberOfBytesToRead + 1);
		WinHttpReadData( hRequest, (LPVOID)pbufRecv, dwNumberOfBytesToRead, &dwNumberOfBytesRead);

		result += string(pbufRecv);

		delete [] pbufRecv;
		pbufRecv = NULL;

	} while (dwNumberOfBytesToRead > 0);

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return true;
}

typedef struct _URL_INFO
{
	WCHAR szScheme[512];
	WCHAR szHostName[512];
	WCHAR szUserName[512];
	WCHAR szPassword[512];
	WCHAR szUrlPath[512];
	WCHAR szExtraInfo[512];
}URL_INFO, *PURL_INFO;

bool libHttp_DownloadFile(const wchar_t *wszURL, const wchar_t *wszFileSavePath)
{
    URL_INFO url_info = { 0 };
    URL_COMPONENTSW lpUrlComponents = { 0 };
    lpUrlComponents.dwStructSize = sizeof(lpUrlComponents);
    lpUrlComponents.lpszExtraInfo = url_info.szExtraInfo;
    lpUrlComponents.lpszHostName = url_info.szHostName;
    lpUrlComponents.lpszPassword = url_info.szPassword;
    lpUrlComponents.lpszScheme = url_info.szScheme;
    lpUrlComponents.lpszUrlPath = url_info.szUrlPath;
    lpUrlComponents.lpszUserName = url_info.szUserName;

    lpUrlComponents.dwExtraInfoLength = 
	lpUrlComponents.dwHostNameLength = 
	lpUrlComponents.dwPasswordLength = 
	lpUrlComponents.dwSchemeLength = 
	lpUrlComponents.dwUrlPathLength = 
	lpUrlComponents.dwUserNameLength = 512;

    WinHttpCrackUrl(wszURL, 0, ICU_ESCAPE, &lpUrlComponents);

    HINTERNET hSession = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    DWORD dwReadBytes, dwSizeDW = sizeof(dwSizeDW), dwContentSize, dwIndex = 0;

    HINTERNET hConnect = WinHttpConnect(hSession, lpUrlComponents.lpszHostName, lpUrlComponents.nPort, 0);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"HEAD", lpUrlComponents.lpszUrlPath, L"HTTP/1.1", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, 0);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentSize, &dwSizeDW, &dwIndex);
    WinHttpCloseHandle(hRequest);

    // 创建一个请求，获取数据
    hRequest = WinHttpOpenRequest(hConnect, L"GET", lpUrlComponents.lpszUrlPath, L"HTTP/1.1", WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, 0);

    // 分段回调显示进度
    DWORD BUF_LEN = 1024, ReadedLen = 0;
    BYTE *pBuffer = NULL;
    pBuffer = new BYTE[BUF_LEN];

	bool bRet = false;

    HANDLE hFile = CreateFileW(wszFileSavePath, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    while (dwContentSize > ReadedLen)
    {
        ZeroMemory(pBuffer, BUF_LEN);
        WinHttpReadData(hRequest, pBuffer, BUF_LEN, &dwReadBytes);
        ReadedLen += dwReadBytes;
        WriteFile(hFile, pBuffer, dwReadBytes, &dwReadBytes, NULL);
		bRet = true;
    }

    CloseHandle(hFile);
    delete pBuffer;


    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

	return bRet;
}
