// Create.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include "Create.h"
#include "../UtilityLib/Utility.h"
#pragma comment(lib , "../build/UtilityLib.lib")

int _tmain(int argc, _TCHAR* argv[])
{
	if (argc != 5)
	{
		printf("参数错误，请传入4个参数:userID aesKey getClientURL clickURL");
		getchar();
		return 0;
	}

	// 1###1234567891234567###http://xxxx/getClient.jsp###http://xxxx/click.jsp
	string strCfg;
	for (int i = 1; i <= 3; i++)
	{
		strCfg += string(argv[i]);
		strCfg += string("###");
	}
	strCfg += string(argv[4]);

	CHAR szCurDir[MAX_PATH] = {0};
	GetModuleFileName(NULL, szCurDir, sizeof(szCurDir));
	PathRemoveFileSpec(szCurDir);

	string strRawDir(szCurDir);
	string strBinDir(szCurDir);

	strRawDir += "\\raw\\";
	strBinDir += "\\bin\\";

	string strRawFile_NetBarAD(strRawDir);
	string strRawFile_NetbarApp(strRawDir);

	string strBinFile_NetBarAD(strBinDir);
	string strBinFile_NetBarAD2(strBinDir);
	string strBinFile_NetbarApp(strBinDir);

	strRawFile_NetBarAD += "NetBarAD.dll";
	strRawFile_NetbarApp += "NetbarApp.exe";

	strBinFile_NetBarAD += "NetBarAD.dll";
	strBinFile_NetBarAD2 += string(argv[1]);	 // userID
	strBinFile_NetBarAD2 += ".dll";
	strBinFile_NetbarApp += string(argv[1]);	 // userID
	strBinFile_NetbarApp += string(".exe");

	MakeSureDirectoryPathExists(strBinFile_NetBarAD.c_str());

	CopyFile(strRawFile_NetBarAD.c_str(),  strBinFile_NetBarAD.c_str(), FALSE);
	CopyFile(strRawFile_NetbarApp.c_str(), strBinFile_NetbarApp.c_str(), FALSE);
	
	Utility_AddOverlayData(strBinFile_NetBarAD.c_str(), (LPVOID)strCfg.c_str(), strCfg.length());
	Utility_AddOverlayFile(strBinFile_NetBarAD.c_str(), strBinFile_NetbarApp.c_str());

	//DeleteFile(strBinFile_NetBarAD.c_str());
	DeleteFile(strBinFile_NetBarAD2.c_str());
	MoveFileA(strBinFile_NetBarAD.c_str(), strBinFile_NetBarAD2.c_str());

	return 0;
}

