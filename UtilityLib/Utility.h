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

VOID Utility_StartRun(BOOL isRun);		// ��������
VOID Utility_GetCpuID(string &cpuID);	// ��ȡCPUID
VOID Utility_DebugLog(string &log);			// ���������־
VOID Utility_DebugLogEx(char* szLog);		// ���������־
VOID Utility_GetMacAddress(string &strMAC);		// ��ȡ����MAC��ַ
BOOL Utility_GetBaseBoardByCmd(char *lpszBaseBoard, int len) ; // ��ȡ�������
BOOL Utility_CreateInternetShortcut(CHAR *szFilePath, CHAR *szURL, CHAR *szIconFile);	// ����IE��ݷ�ʽ
BOOL Utility_OpenIE(CHAR *szURL);					// ��IE
BOOL Utility_IsHaveProcess(CHAR *szProcessName);	// �ж�ָ�������Ƿ����
BOOL Utility_IsHaveProcessEx(DWORD dwPID);	// �ж�ָ�������Ƿ����
BOOL Utility_SetHomePage(char *szURL, BOOL isLock);	// ����IE��ҳ

wstring Utility_string2wstring(string &strSrc);
string  Utility_wstring2string(wstring &strSrc);

BOOL Utility_EnabledDebugPrivilege();							// ��������Ȩ��
void Utility_GetAllProcess(list<PROCESSENTRY32> &listProcess);	// ��ȡ���н���
void Utility_KillProcess(string &processName);					// ����ָ������
void Utility_GetProcessPath(DWORD dwPID, string &strProcessPath); // ���ݽ���ID, ��ȡ����·��
BOOL Utility_IsNewProcess(DWORD dwPID,  DWORD dwSecond);		// �жϽ����Ƿ����½���
BOOL Utility_CloseProcess(LPCSTR szProcessName);		        //��������

BOOL Utility_InjectDll(char *szDllPath);			// ע��DLL
BOOL Utility_InjectDllEx(DWORD dwPID, char *szDllName);			// ע��DLL
BOOL Utility_GetCurrentExePath(string &strExePath);				// ��ȡ��ǰEXE�ļ�·��

BOOL Utility_ReleaseResFile(WORD wResID, LPCTSTR szResType, LPCTSTR szDstFilePath);	// �ͷ���Դ�ļ�
BOOL Utility_SelfDel();									// ��ɾ��
VOID Utility_GetWindowsFolder(string &strWinFolder);	// ��ȡwindows�ļ���
VOID Utility_GetSysTmpFolder(string &strFolder);	// ��ȡϵͳ��ʱ�ļ���
BOOL Utility_IsHaveFile(const char* szFilePath);				// �ж��ļ��Ƿ����


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

VOID Utility_GetCurrentModuleDir(std::string& strDir, HMODULE hModule);	// ��ȡģ������Ŀ¼

VOID Utility_ShowRightCornerWindow(HINSTANCE hInstance, LPCSTR szUrl, LPCSTR szCaption); // ���½Ǵ���
HANDLE Utility_GetCreateProcessAsUserToken();
BOOL Utility_CreateProcessAsUser(LPTSTR lpCommandLine);
VOID Utility_GetIEPath(string &strRet);
BOOL Utility_IsServerProcess(DWORD dwPID);
BOOL Utility_IsWow64ProcessEx(DWORD dwPID); // �жϽ����Ƿ���64λ
BOOL Utility_Is64BitSystem(VOID);		// �ж�ϵͳ�Ƿ���64λ
INT Utility_GetSystemTimeDiffSeconds(const SYSTEMTIME &t1, const SYSTEMTIME &t2);
time_t  Utility_FileTimeToTime(const FILETIME &ft);
bool Utility_ChangeLinkIcon(string &strLnkPath, string &strIconPath);
BOOL Utility_CreateFileShortcut(LPCSTR szLnkPath, LPCSTR szLinkDst, LPCSTR szLinkDstParam);

int Utility_GetFileSize(LPCSTR szFilePath);
int Utility_GetPEFileSize(LPCSTR szFilePath);
BOOL Utility_GetOverlayText(LPCSTR szFilePath, string& strOverText);	// ��ȡ�������ݣ��ı�
BOOL Utility_GetOverlayBin(LPCSTR szSrcFilePath, LPCSTR szDstFilePath); // ��ȡ�������ݣ�������
BOOL Utility_AddOverlayData(LPCSTR szSrcFilePath, LPVOID pData, int iDataLen); // ���Ӹ�������
BOOL Utility_AddOverlayFile(LPCSTR szSrcFilePath, LPCSTR szDstFilePath); // ���Ӹ����ļ�

VOID Utility_GetNetbarADDir(std::string& dstDir);  // ���غ�����б�� C:\XX\YY\



