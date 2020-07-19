#pragma warning(disable: 4018)//<> unsigned
//==============================================================
//  Copyright (C) 2020 Steeliest Org.. All rights reserved.
//  The information contained herein is confidential, proprietary
//  to Jeteam Inc. Use of this information by anyone other than 
//  authorized employees of Jeteam Inc is granted only under a 
//  written non-disclosure agreement, expressly prescribing the 
//  scope and manner of such use.
//==============================================================
//  Create by Steesha at 2020.7.19.
//  Version 1.0
//  Steesha [steesha@qq.com]
//  备注:
//  肝死我了。
//  用法：打开迷你世界，登录，然后打开本程序，即可获得账户信息。
//==============================================================
#include <windows.h>
#include <iostream>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <cmath>
#include <algorithm>
#include <cctype>
#include <vector>

using namespace std;

// 获取进程PID
bool getProcessId(LPCSTR ProcessName, DWORD& dwPid);

// 获取进程CommandLine
BOOL GetProcessCommandLine(HANDLE hProcess, LPTSTR pszCmdLine, DWORD cchCmdLine);

//进程提权
bool EnableDebugPrivilege();

//取文本中间的子文本
string GetSubText(string str, string lstr, string rstr);

//Base64解密
std::string decode_base64(const  std::string sourceData);

//字符串分割函数
std::vector<std::string> split(std::string str, std::string pattern)
{
	std::string::size_type pos;
	std::vector<std::string> result;
	str += pattern;//扩展字符串以方便操作
	int size = str.size();

	for (unsigned int i = 0; i < size; i++)
	{
		pos = str.find(pattern, i);
		if (pos < size)
		{
			std::string s = str.substr(i, pos - i);
			result.push_back(s);
			i = pos + pattern.size() - 1;
		}
	}
	return result;
}

int main(int argc, TCHAR* argv[])
{
	TCHAR szPath[1024];//1024长度够了吧...
	HANDLE hProcess;
	DWORD dwPID = 0;
	struct AccountInfo {
		string Uin;//用户名
		string PassWord;//密码
		string AuthTime;//登录时的时间戳
	};
	AccountInfo info;
	getProcessId("iworldpc3.exe", dwPID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess && dwPID != 0)
	{
		if (GetProcessCommandLine(hProcess, szPath, sizeof(szPath)))
		{
			string CommandLine = szPath;
			CommandLine = CommandLine + "[END]";
			CommandLine = decode_base64(GetSubText(CommandLine, "&baseinfo=", "[END]"));
			CommandLine = decode_base64(GetSubText(CommandLine, "&openstring=", "*&apiid"));
			CommandLine = GetSubText(CommandLine, "&token=", "&sign=");
			//切割字符串 [(1).(2).(3)]
			std::vector<std::string> result = split(CommandLine, ".");
			if (result.size() != 3) {
				cout << "failed" << endl;
				return -1;
			}
			CommandLine = decode_base64(result[1]);
			info.Uin = GetSubText(CommandLine, "{\"Uin\":", ",\"env");//懒得解析了，直接上取文本
			info.PassWord = GetSubText(CommandLine, "\"passwd\":\"", "\",\"apiid\"");
			info.AuthTime = GetSubText(CommandLine, "\"ts\":", ",\"pass");

			cout
				<< "Uin:" << info.Uin << endl
				<< "PassWord:" << info.PassWord << endl
				<< "AuthTime:" << info.AuthTime << endl;

		}
		CloseHandle(hProcess);
	}
	return 0;
}

//取进程命令行
BOOL GetProcessCommandLine(HANDLE hProcess, LPTSTR pszCmdLine, DWORD cchCmdLine)
{
	BOOL			bRet;
	DWORD			dwPos;
	LPBYTE			lpAddr;
	DWORD			dwRetLen;

	bRet = FALSE;

	dwPos = 0;
	lpAddr = (LPBYTE)GetCommandLine;
	if (lpAddr[dwPos] == 0xeb && lpAddr[dwPos + 1] == 0x05)
	{
		dwPos += 2;
		dwPos += 5;
	Win8:
		if (lpAddr[dwPos] == 0xff && lpAddr[dwPos + 1] == 0x25)
		{
			dwPos += 2;
			lpAddr = *(LPBYTE*)(lpAddr + dwPos);

			dwPos = 0;
			lpAddr = *(LPBYTE*)lpAddr;
		WinXp:
			if (lpAddr[dwPos] == 0xa1)
			{
				dwPos += 1;
				lpAddr = *(LPBYTE*)(lpAddr + dwPos);
				bRet = ReadProcessMemory(hProcess,
					lpAddr,
					&lpAddr,
					sizeof(LPBYTE),
					&dwRetLen);
				if (bRet)
				{
					bRet = ReadProcessMemory(hProcess,
						lpAddr,
						pszCmdLine,
						cchCmdLine,
						&dwRetLen);
				}
			}
		}
		else
		{
			goto WinXp;
		}
	}
	else
	{
		goto Win8;
	}

	return bRet;
}

// 获取进程PID
bool getProcessId(LPCSTR ProcessName, DWORD& dwPid)
{
	EnableDebugPrivilege();
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}
	BOOL bRet = FALSE;
	do
	{
		if (!strcmp(ProcessName, pe32.szExeFile))
		{
			dwPid = pe32.th32ProcessID;
			bRet = TRUE;
			break;
		}

	} while (Process32Next(hProcessSnap, &pe32));
	CloseHandle(hProcessSnap);
	return bRet;
}

//进程提权
bool EnableDebugPrivilege()//进程提权
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return   FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return false;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return false;
	}
	return true;
}

//取文本中间的子文本 
string GetSubText(string str, string lstr, string rstr)
{
	int p_l = str.find(lstr);
	if (p_l < 0)return "";
	p_l += lstr.length();
	int p_r = str.find(rstr);
	if (p_r < 0)return str.substr(p_l, str.length() - p_l);
	return str.substr(p_l, p_r - p_l);
}

//Base64解密
std::string decode_base64(const  std::string sourceData)
{
	unsigned int buf = 0;
	int nbits = 0;
	std::string tmp;
	tmp.resize((sourceData.size() * 3) / 4);

	int offset = 0;
	for (unsigned int i = 0; i < sourceData.size(); ++i) {
		int ch = sourceData.at(i);
		int d;

		if (ch >= 'A' && ch <= 'Z')
			d = ch - 'A';
		else if (ch >= 'a' && ch <= 'z')
			d = ch - 'a' + 26;
		else if (ch >= '0' && ch <= '9')
			d = ch - '0' + 52;
		else if (ch == '+')
			d = 62;
		else
			d = -1;

		if (d != -1) {
			buf = (buf << 6) | d;
			nbits += 6;
			if (nbits >= 8) {
				nbits -= 8;
				tmp[offset++] = buf >> nbits;
				buf &= (1 << nbits) - 1;
			}
		}
	}

	tmp.resize(offset);
	return tmp;
}