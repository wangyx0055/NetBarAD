#include "StdAfx.h"
#include "Inject.h"

#include "tchar.h"
#pragma comment(lib,"Advapi32.lib")
#include <Tlhelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

BOOL CreateRemoteThreadLoadDll(string dllPath, DWORD dwPID)
{
	HANDLE hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |  PROCESS_VM_WRITE, FALSE, dwPID);   
	if (hProcess == NULL) return FALSE;
	
	DWORD dwSize, dwWritten;
	dwSize = dllPath.length() + 8;
	LPVOID lpBuf = VirtualAllocEx( hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE );
	if (lpBuf == NULL)
	{
		CloseHandle( hProcess );
		return FALSE;
	}

	WriteProcessMemory(hProcess, lpBuf, (LPVOID)dllPath.c_str(), dllPath.length(), &dwWritten);
	if (dwWritten != dllPath.length() )
	{
		VirtualFreeEx( hProcess, lpBuf, dwSize, MEM_DECOMMIT );
		CloseHandle( hProcess );
		return FALSE;
	}

	DWORD dwErrCode = 0;
	BOOL bRet =FALSE;
	
	// 使目标进程调用LoadLibrary，加载DLL
	DWORD dwID;
	LPVOID pFunc = LoadLibraryA;
	HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc, lpBuf, 0, &dwID );
	if (hThread == NULL)
	{
		dwErrCode = GetLastError();
	}
	else
	{
		WaitForSingleObject( hThread, 100);
		bRet = TRUE;
	}
	
	

	VirtualFreeEx( hProcess, lpBuf, dwSize, MEM_DECOMMIT );
	CloseHandle( hThread );
	CloseHandle( hProcess ); 

	return bRet;
}


typedef DWORD (WINAPI *PFNTCREATETHREADEX)
	( 
	PHANDLE                 ThreadHandle,	
	ACCESS_MASK             DesiredAccess,	
	LPVOID                  ObjectAttributes,	
	HANDLE                  ProcessHandle,	
	LPTHREAD_START_ROUTINE  lpStartAddress,	
	LPVOID                  lpParameter,	
	BOOL	                CreateSuspended,	
	DWORD                   dwStackSize,	
	DWORD                   dw1, 
	DWORD                   dw2, 
	LPVOID                  Unknown 
	); 
BOOL IsVistaOrLater()
{
	OSVERSIONINFO osvi;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	if( osvi.dwMajorVersion >= 6 )
		return TRUE;
	return FALSE;
}
BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE      hThread = NULL;
	FARPROC     pFunc = NULL;
	if( IsVistaOrLater() )    // Vista, 7, Server2008
	{
		pFunc = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
		if( pFunc == NULL )
		{
			return FALSE;
		}
		((PFNTCREATETHREADEX)pFunc)(&hThread,
			//0x1FFFFF,
			0x1FFFFF,
			NULL,
			hProcess,
			pThreadProc,
			pRemoteBuf,
			FALSE,
			NULL,
			NULL,
			NULL,
			NULL);
		if( hThread == NULL )
		{
			printf("MyCreateRemoteThread() : NtCreateThreadEx() 调用失败！错误代码: [%d]/n", GetLastError());
			return FALSE;
		}
	}
	else                    // 2000, XP, Server2003
	{
		hThread = CreateRemoteThread(hProcess, 
			NULL, 
			0, 
			pThreadProc, 
			pRemoteBuf, 
			0, 
			NULL);
		if( hThread == NULL )
		{
			printf("MyCreateRemoteThread() : CreateRemoteThread() 调用失败！错误代码: [%d]/n", GetLastError());
			return FALSE;
		}
	}
	if( WAIT_FAILED == WaitForSingleObject(hThread, 100) )
	{
		printf("MyCreateRemoteThread() : WaitForSingleObject() 调用失败！错误代码: [%d]/n", GetLastError());
		return FALSE;
	}
	return TRUE;
}
BOOL InjectDll(DWORD dwPID, char *szDllName)
{
	HANDLE hProcess = NULL;
	LPVOID pRemoteBuf = NULL;
	FARPROC pThreadProc = NULL;
	DWORD dwBufSize = strlen(szDllName)+1;
	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
	{
		printf("[错误] OpenProcess(%d) 调用失败！错误代码: [%d]/n", 
			dwPID, GetLastError());
		return FALSE;
	}
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, 
		MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);
	pThreadProc = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	DWORD dwErrCode = GetLastError();

	if( !MyCreateRemoteThread(hProcess, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf) )
	{
		printf("[错误] CreateRemoteThread() 调用失败！错误代码: [%d]/n", GetLastError());
		return FALSE;
	}
	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
}


