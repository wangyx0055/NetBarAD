#include "StdAfx.h"
#include "MAC.h"

#include <windows.h>
#include <iphlpapi.h>       // API GetAdaptersInfo 头文件
#include <shlwapi.h>        // API StrCmpIA 头文件
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")
#include <Strsafe.h>        // API StringCbPrintfA 头文件
#include <shellapi.h>       // API lstrcpyA 头文件

#define BUF_SIZE 4096
#define MAX_SIZE 4096

//////////////////////////////////////
// 功能：获取适配器特性
// 参数： 
//   adapter_name 适配器 ID
// 返回值：成功则返回由参数指定的适配器的特性标志，是一个 DWORD 值，失败返回 0
//
UINT GetAdapterCharacteristics(char* adapter_name)
{
	if(adapter_name == NULL || adapter_name[0] == 0)
		return 0;

	HKEY root = NULL;
	// 打开存储适配器信息的注册表根键
	if(ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &root))
		return 0;

	DWORD subkeys = 0;
	// 获取该键下的子键数
	if(ERROR_SUCCESS != RegQueryInfoKeyA(root, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
		subkeys = 100;

	DWORD ret_value = 0;
	for(DWORD i = 0; i < subkeys; i++)
	{
		// 每个适配器用一个子键存储，子键名为从 0 开始的 4 位数
		char subkey[MAX_SIZE];
		memset(subkey, 0, MAX_SIZE);
		StringCbPrintfA(subkey, MAX_SIZE, "%04u", i);

		// 打开该子键
		HKEY hKey = NULL;
		if(ERROR_SUCCESS != RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey))
			continue;

		// 获取该子键对应的适配器 ID，存于 name 中
		char name[MAX_PATH];
		DWORD type = 0;
		DWORD size = MAX_PATH;
		if(ERROR_SUCCESS != RegQueryValueExA(hKey, "NetCfgInstanceId", NULL, &type, (LPBYTE)name, &size))
		{
			RegCloseKey(hKey);
			continue;
		}

		// 对比该适配器 ID 是不是要获取特性的适配器 ID
		if(StrCmpIA(name, adapter_name) != 0)
		{
			RegCloseKey(hKey);
			continue;
		}

		// 读取该适配器的特性标志，该标志存储于值 Characteristics 中
		DWORD val = 0;
		size = 4;
		LSTATUS ls = RegQueryValueExA(hKey, "Characteristics", NULL, &type, (LPBYTE)&val, &size);
		RegCloseKey(hKey);

		if(ERROR_SUCCESS == ls)
		{
			ret_value = val;
			break;
		}
	}

	RegCloseKey(root);
	return ret_value;
}

//////////////////////////////////////
// 功能：获取 Mac 地址的二进制数据
// 参数：
//   mac 用于输出 Mac 地址的二进制数据的缓冲区指针
// 返回值：成功返回 mac 地址的长度，失败返回 0，失败时 mac 中保存一些简单的错误信息，可适当修改，用于调试
//
int GetMAC(BYTE mac[BUF_SIZE])
{
#define NCF_PHYSICAL 0x4
	DWORD AdapterInfoSize = 0;
	if(ERROR_BUFFER_OVERFLOW != GetAdaptersInfo(NULL, &AdapterInfoSize))
	{
		StringCbPrintfA((LPSTR)mac, BUF_SIZE, "GetMAC Failed! ErrorCode: %d", GetLastError());
		return 0;
	}

	void* buffer = malloc(AdapterInfoSize);
	if(buffer == NULL)
	{
		lstrcpyA((LPSTR)mac, "GetMAC Failed! Because malloc failed!");
		return 0;
	}

	PIP_ADAPTER_INFO pAdapt = (PIP_ADAPTER_INFO)buffer;
	if(ERROR_SUCCESS != GetAdaptersInfo(pAdapt, &AdapterInfoSize))
	{
		StringCbPrintfA((LPSTR)mac, BUF_SIZE, "GetMAC Failed! ErrorCode: %d", GetLastError());
		free(buffer);
		return 0;
	}

	int mac_length = 0;
	while(pAdapt)
	{
		if(pAdapt->AddressLength >= 6 && pAdapt->AddressLength <= 8)
		{
			memcpy(mac, pAdapt->Address, pAdapt->AddressLength);
			mac_length = pAdapt->AddressLength;

			UINT flag = GetAdapterCharacteristics(pAdapt->AdapterName);
			bool is_physical = ((flag & NCF_PHYSICAL) == NCF_PHYSICAL);
			if(is_physical)
				break;
		}
		pAdapt = pAdapt->Next;
	}
	free(buffer);
	return mac_length;
}

//////////////////////////////////////
// 功能：获取 Mac 地址，使用时直接调用此函数即可
// 参数：
//   mac 用于存储 Mac 地址的缓冲区指针
// 返回值：无返回值，函数执行完后会把 Mac 地址以16进制的形式存于参数指定的缓冲区中，若有错误，缓冲区中保存的是错误信息
//
void GetMacAddress( char* mac )
{
	BYTE buf[BUF_SIZE];
	memset(buf, 0, BUF_SIZE);

	int len = GetMAC(buf);
	if(len <= 0)
	{
		lstrcpyA(mac, (LPCSTR)buf);
		return;
	}

	if(len == 6)
		StringCbPrintfA(mac, BUF_SIZE, "%02X-%02X-%02X-%02X-%02X-%02X", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	else
		StringCbPrintfA(mac, BUF_SIZE, "%02X-%02X-%02X-%02X-%02X-%02X-%02X-%02X", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
}