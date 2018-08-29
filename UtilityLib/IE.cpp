#include "StdAfx.h"
#include "IE.h"
#include <string>
using std::string;

struct ProcessWindow  
{  
	DWORD dwProcessId;  
	HWND hwndWindow;  
};  


// 查找进程主窗口的回调函数  
BOOL CALLBACK EnumWindowCallBack(HWND hWnd, LPARAM lParam)  
{  
	ProcessWindow *pProcessWindow = (ProcessWindow *)lParam;  

	DWORD dwProcessId;  
	GetWindowThreadProcessId(hWnd, &dwProcessId);  

	// 判断是否是指定进程的主窗口  
	if (pProcessWindow->dwProcessId == dwProcessId && IsWindowVisible(hWnd) && GetParent(hWnd) == NULL)  
	{  
		pProcessWindow->hwndWindow = hWnd;  
		SetWindowPos(hWnd,NULL,0,0,800,600,SWP_NOMOVE);
		return FALSE;  
	}  

	return TRUE;  
}  

BOOL IE_Run(char *szURL)
{
	string strUrl = "open ";
	strUrl += string(szURL);

	PROCESS_INFORMATION   pi;

	STARTUPINFO   si;   
	ZeroMemory(&si,   sizeof(si));   
	si.cb   =   sizeof(STARTUPINFO);   
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESIZE;
	si.wShowWindow = SW_MINIMIZE;
	si.dwXSize = 800;
	si.dwYSize = 600;

	TCHAR tszWindows[256];
	GetSystemDirectory(tszWindows, 256);
	char strExe[4096] = {0};
	sprintf(strExe, "%c:\\Program Files\\Internet Explorer\\IEXPLORE.EXE", tszWindows[0]);
	BOOL bRet = CreateProcess(strExe, (LPSTR)strUrl.c_str(), NULL,   NULL,   FALSE,   0,   NULL,   NULL,   &si,   &pi);
	if (bRet)
	{
		ProcessWindow procwin;  
		procwin.dwProcessId = pi.dwProcessId;  
		procwin.hwndWindow = NULL;  

		// 等待新进程初始化完毕  
		WaitForInputIdle(pi.hProcess, 5000);  
		Sleep(1000);

		// 查找主窗口  
		EnumWindows(EnumWindowCallBack, (LPARAM)&procwin);  
	}

	return bRet;
}

BOOL IE_SetHomePage(char *szURL, BOOL isLock)
{
	DWORD dwErr = ERROR_SUCCESS;

	// 修改IE主页  
	HKEY hkey;  
	dwErr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Internet Explorer\\Main", 0, KEY_WRITE, &hkey); 
	dwErr = RegSetValueEx(hkey, "Start Page", 0, REG_SZ, (LPBYTE)szURL, strlen(szURL));  
	RegCloseKey(hkey);  

	dwErr = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Internet Explorer\\Main", 0, KEY_WRITE, &hkey); 
	dwErr = RegSetValueEx(hkey, "Start Page", 0, REG_SZ, (LPBYTE)szURL, strlen(szURL));  
	RegCloseKey(hkey);  

	dwErr = RegOpenKeyEx(HKEY_USERS, "S-1-5-21-2126089656-2388721086-3373686180-500\\Software\\Microsoft\\Internet Explorer\\Main", 0, KEY_WRITE, &hkey); 
	dwErr = RegSetValueEx(hkey, "Start Page", 0, REG_SZ, (LPBYTE)szURL, strlen(szURL));  
	RegCloseKey(hkey); 



	// 屏蔽主页选项卡  
	LPCTSTR data_Set1 = "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel";   
	RegCreateKey(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Internet Explorer\\Control Panel", &hkey);     
	DWORD value = isLock ? 1 : 0;  
	RegOpenKeyEx(HKEY_CURRENT_USER, data_Set1, 0, KEY_WRITE, &hkey);  
	dwErr = RegSetValueEx(hkey, "HomePage", 0, REG_DWORD,(LPBYTE)&value, sizeof(value));  
	RegCloseKey(hkey);  

	return (dwErr == ERROR_SUCCESS);
}
