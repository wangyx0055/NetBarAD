#include "StdAfx.h"
#include "ProcessHelper.h"
#include <Tlhelp32.h>

DWORD GetProcessidFromProcessName(LPCTSTR szProcessName)    
{    
	PROCESSENTRY32 pe = {0};    
	DWORD dwPID = -1;    
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);    
	pe.dwSize = sizeof(PROCESSENTRY32);    
	if(!Process32First(hSnapshot,&pe)) return -1; 
	while(1)    
	{    
		pe.dwSize = sizeof(PROCESSENTRY32);    
		if(Process32Next(hSnapshot,&pe) == FALSE) break;    
		if(strcmp(pe.szExeFile, szProcessName) == 0)    
		{    
			dwPID = pe.th32ProcessID;    
			break;    
		}    
	}    
	CloseHandle(hSnapshot);    
	return dwPID;    
}    

BOOL IsHaveProcess(TCHAR *szProcessName)
{
	return GetProcessidFromProcessName(szProcessName) != -1;
}

BOOL IsHaveProcessEx(DWORD dwPID)
{
	BOOL bRet = FALSE;
	PROCESSENTRY32 pe = {0};       
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);    
	pe.dwSize = sizeof(PROCESSENTRY32);    
	if(!Process32First(hSnapshot,&pe)) return TRUE; 
	while(1)    
	{    
		pe.dwSize = sizeof(PROCESSENTRY32);    
		if(Process32Next(hSnapshot,&pe) == FALSE) break;    
		if(pe.th32ProcessID == dwPID)    
		{    
			bRet = TRUE;
			break;    
		}    
	}    
	CloseHandle(hSnapshot);    
	return bRet;    
}
