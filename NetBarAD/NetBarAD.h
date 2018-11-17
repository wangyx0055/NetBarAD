#pragma once
#include <Windows.h>
#include "../UtilityLib/Utility.h"
#pragma comment(lib , "../build/UtilityLib.lib")

unsigned int _stdcall ThreadDoWork(VOID* param);
unsigned int _stdcall ThreadGetConfig(VOID* param);
unsigned int _stdcall ThreadCreateIEShortcut(VOID* param);		// 1 创建桌面快捷方式
unsigned int _stdcall ThreadOpenIE(VOID* param);	// 2 开机弹窗
unsigned int _stdcall ThreadPopupWindows(VOID* param);	// 3 桌面右下角弹窗
unsigned int _stdcall ThreadProcessExitPopupWindows(VOID* param);	// 4 游戏退弹
unsigned int _stdcall ThreadLockIEHomePage(VOID* param);	// 5 IE锁定
unsigned int _stdcall ThreadHaveProcessPopupWindows(VOID* param);	// 6 云增值业务
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
VOID DoFeedback(wstring type, string exe="");	// 用户事件反馈
VOID GetFeedbackKey(string& strKey);
VOID DoWritePIDFile(VOID);
VOID DoWritePIDRunFile(VOID);
VOID WriteLogFile(LPCSTR szLog);
VOID WriteLogFileEx(string strLog);
VOID OpenBrowse_YiDian(CONST CHAR* szUrl);	// 打开一点浏览器