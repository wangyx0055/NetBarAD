// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "NetBarAD.h"
#include "../UtilityLib/Utility.h"
#include "VMProtectSDK.h"
#pragma comment(lib, "VMProtectSDK32.lib")
#include <process.h>
BOOL g_isExit = FALSE;
HMODULE g_hDLLModule = NULL;

#pragma optimize("g", off )
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	
	VMProtectBegin("DllMain");

	g_hDLLModule = hModule;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			Utility_DebugLogEx("DLL_PROCESS_ATTACH...");
			g_isExit = FALSE;
			_beginthreadex(NULL, 0, ThreadDoWork, NULL, 0, NULL);
			break;
		}
	case DLL_THREAD_ATTACH:
		{
			Utility_DebugLogEx("DLL_THREAD_ATTACH...");
			/*g_isExit = FALSE;
			_beginthreadex(NULL, 0, ThreadDoWork, NULL, 0, NULL);
			break;*/
		}
	case DLL_THREAD_DETACH:
		{
			Utility_DebugLogEx("DLL_THREAD_DETACH...");
			//g_isExit = TRUE;
			break;
		}
	case DLL_PROCESS_DETACH:
		{
			Utility_DebugLogEx("DLL_PROCESS_DETACH...");
			g_isExit = TRUE;
			Sleep(1000*20);		// 确保所有线程安全退出
			break;
		}
	}

	VMProtectEnd();
	

	return TRUE;
}
#pragma optimize( "g", on )

