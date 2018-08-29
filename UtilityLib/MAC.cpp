#include "StdAfx.h"
#include "MAC.h"

#include <windows.h>
#include <iphlpapi.h>       // API GetAdaptersInfo ͷ�ļ�
#include <shlwapi.h>        // API StrCmpIA ͷ�ļ�
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")
#include <Strsafe.h>        // API StringCbPrintfA ͷ�ļ�
#include <shellapi.h>       // API lstrcpyA ͷ�ļ�

#define BUF_SIZE 4096
#define MAX_SIZE 4096

//////////////////////////////////////
// ���ܣ���ȡ����������
// ������ 
//   adapter_name ������ ID
// ����ֵ���ɹ��򷵻��ɲ���ָ���������������Ա�־����һ�� DWORD ֵ��ʧ�ܷ��� 0
//
UINT GetAdapterCharacteristics(char* adapter_name)
{
	if(adapter_name == NULL || adapter_name[0] == 0)
		return 0;

	HKEY root = NULL;
	// �򿪴洢��������Ϣ��ע������
	if(ERROR_SUCCESS != RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &root))
		return 0;

	DWORD subkeys = 0;
	// ��ȡ�ü��µ��Ӽ���
	if(ERROR_SUCCESS != RegQueryInfoKeyA(root, NULL, NULL, NULL, &subkeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
		subkeys = 100;

	DWORD ret_value = 0;
	for(DWORD i = 0; i < subkeys; i++)
	{
		// ÿ����������һ���Ӽ��洢���Ӽ���Ϊ�� 0 ��ʼ�� 4 λ��
		char subkey[MAX_SIZE];
		memset(subkey, 0, MAX_SIZE);
		StringCbPrintfA(subkey, MAX_SIZE, "%04u", i);

		// �򿪸��Ӽ�
		HKEY hKey = NULL;
		if(ERROR_SUCCESS != RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey))
			continue;

		// ��ȡ���Ӽ���Ӧ�������� ID������ name ��
		char name[MAX_PATH];
		DWORD type = 0;
		DWORD size = MAX_PATH;
		if(ERROR_SUCCESS != RegQueryValueExA(hKey, "NetCfgInstanceId", NULL, &type, (LPBYTE)name, &size))
		{
			RegCloseKey(hKey);
			continue;
		}

		// �Աȸ������� ID �ǲ���Ҫ��ȡ���Ե������� ID
		if(StrCmpIA(name, adapter_name) != 0)
		{
			RegCloseKey(hKey);
			continue;
		}

		// ��ȡ�������������Ա�־���ñ�־�洢��ֵ Characteristics ��
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
// ���ܣ���ȡ Mac ��ַ�Ķ���������
// ������
//   mac ������� Mac ��ַ�Ķ��������ݵĻ�����ָ��
// ����ֵ���ɹ����� mac ��ַ�ĳ��ȣ�ʧ�ܷ��� 0��ʧ��ʱ mac �б���һЩ�򵥵Ĵ�����Ϣ�����ʵ��޸ģ����ڵ���
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
// ���ܣ���ȡ Mac ��ַ��ʹ��ʱֱ�ӵ��ô˺�������
// ������
//   mac ���ڴ洢 Mac ��ַ�Ļ�����ָ��
// ����ֵ���޷���ֵ������ִ������� Mac ��ַ��16���Ƶ���ʽ���ڲ���ָ���Ļ������У����д��󣬻������б�����Ǵ�����Ϣ
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