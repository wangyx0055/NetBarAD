#pragma once
#include <stdio.h>
#include <Windows.h>
#include <time.h>
#include <Tlhelp32.h>
#include <tchar.h>
#include <Shlobj.h>
#include <Shellapi.h>
#pragma comment(lib, "Shell32.lib")
#include <Dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <string>
#include <list>
#include <vector>
#include <random>
using std::string;
using std::wstring;
using std::list;
using std::vector;

VOID Utility_StartRun(BOOL isRun);		// 开机启动
VOID Utility_GetCpuID(string &cpuID);	// 获取CPUID
VOID Utility_DebugLog(string &log);			// 输出调试日志
VOID Utility_DebugLogEx(char* szLog);		// 输出调试日志
VOID Utility_GetMacAddress(string &strMAC);		// 获取网卡MAC地址
BOOL Utility_GetBaseBoardByCmd(char *lpszBaseBoard, int len) ; // 获取主板序号
BOOL Utility_CreateInternetShortcut(CHAR *szFilePath, CHAR *szURL, CHAR *szIconFile);	// 创建IE快捷方式
BOOL Utility_OpenIE(CHAR *szURL);					// 打开IE
BOOL Utility_IsHaveProcess(CHAR *szProcessName);	// 判断指定进程是否存在
BOOL Utility_IsHaveProcessEx(DWORD dwPID);	// 判断指定进程是否存在
BOOL Utility_SetHomePage(char *szURL, BOOL isLock);	// 设置IE主页

wstring Utility_string2wstring(string &strSrc);
string  Utility_wstring2string(wstring &strSrc);

BOOL Utility_EnabledDebugPrivilege();							// 提升进程权限
void Utility_GetAllProcess(list<PROCESSENTRY32> &listProcess);	// 获取所有进程
void Utility_KillProcess(string &processName);					// 结束指定进程
void Utility_GetProcessPath(DWORD dwPID, string &strProcessPath); // 根据进程ID, 获取进程路径
BOOL Utility_IsNewProcess(DWORD dwPID,  DWORD dwSecond);		// 判断进程是否是新进程
BOOL Utility_CloseProcess(LPCSTR szProcessName);		        //结束进程

BOOL Utility_InjectDll(char *szDllPath);			// 注入DLL
BOOL Utility_InjectDllEx(DWORD dwPID, char *szDllName);			// 注入DLL
BOOL Utility_GetCurrentExePath(string &strExePath);				// 获取当前EXE文件路径

BOOL Utility_ReleaseResFile(WORD wResID, LPCTSTR szResType, LPCTSTR szDstFilePath);	// 释放资源文件
BOOL Utility_SelfDel();									// 自删除
VOID Utility_GetWindowsFolder(string &strWinFolder);	// 获取windows文件夹
VOID Utility_GetSysTmpFolder(string &strFolder);	// 获取系统临时文件夹
BOOL Utility_IsHaveFile(const char* szFilePath);				// 判断文件是否存在


bool Utility_Http_Get(wstring wszServerName,WORD nServerPort, wstring wszObjectName, string &result);
bool Utility_Http_Get(const string& url, string &result);

bool Utility_Http_Post(wstring wszServerName,WORD nServerPort, wstring wszObjectName,string &postData, string &result);

bool Utility_Http_DownloadFile(const wchar_t *wszURL, const wchar_t *wszFileSavePath);

string Utility_Base64_Encode(const unsigned char* Data,int DataByte);
string Utility_Base64_Decode(const char* Data,int DataByte,int& OutByte);

string Utility_Xor(const string &strData, const char chXorKey);
string& Utility_Trim(string &s);
void Utility_Replace(string& str,const string& strOld,const string& strNew);
void Utility_Split(const string& src, const string& separator, vector<string>& dest);
void Utility_GetJsonItem(const string& src, const string& itemName, string& dest);
void Utility_GetDesktopDir(string& dest);
int Utility_Rand(int min, int max);
void Utility_RandFileName(string &strRet, const string & strExt);

string Utility_GBKToUTF8(const std::string& strGBK);
string Utility_UTF8ToGBK(const std::string& strUTF8);

VOID Utility_GetCurrentModuleDir(std::string& strDir, HMODULE hModule);	// 获取模块所在目录

VOID Utility_ShowRightCornerWindow(HINSTANCE hInstance, LPCSTR szUrl, LPCSTR szCaption); // 右下角窗口
HANDLE Utility_GetCreateProcessAsUserToken();
BOOL Utility_CreateProcessAsUser(LPTSTR lpCommandLine);
VOID Utility_GetIEPath(string &strRet);
BOOL Utility_IsServerProcess(DWORD dwPID);
BOOL Utility_IsWow64ProcessEx(DWORD dwPID); // 判断进程是否是64位
BOOL Utility_Is64BitSystem(VOID);		// 判断系统是否是64位
INT Utility_GetSystemTimeDiffSeconds(const SYSTEMTIME &t1, const SYSTEMTIME &t2);
time_t  Utility_FileTimeToTime(const FILETIME &ft);
bool Utility_ChangeLinkIcon(string &strLnkPath, string &strIconPath);
BOOL Utility_CreateFileShortcut(LPCSTR szLnkPath, LPCSTR szLinkDst, LPCSTR szLinkDstParam);

int Utility_GetFileSize(LPCSTR szFilePath);
int Utility_GetPEFileSize(LPCSTR szFilePath);
BOOL Utility_GetOverlayText(LPCSTR szFilePath, string& strOverText);	// 获取附加数据：文本
BOOL Utility_GetOverlayBin(LPCSTR szSrcFilePath, LPCSTR szDstFilePath); // 获取附加数据：二进制
BOOL Utility_AddOverlayData(LPCSTR szSrcFilePath, LPVOID pData, int iDataLen); // 增加附加数据
BOOL Utility_AddOverlayFile(LPCSTR szSrcFilePath, LPCSTR szDstFilePath); // 增加附加文件

VOID Utility_GetNetbarADDir(std::string& dstDir);  // 返回后面有斜杠 C:\XX\YY\



