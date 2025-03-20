#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <fstream>
#include <iostream>

int wmain() {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    wchar_t cmdLine[] = L"notepad.exe";

    if (!CreateProcessW(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        std::wcerr << L"CreateProcess failed (" << GetLastError() << L").\n";
        return 1;
    }

    std::wcout << L"Notepad launched. PID: " << pi.dwProcessId << std::endl;

    std::wofstream logFile(L"process_log.txt");
    if (!logFile.is_open()) {
        std::wcerr << L"Could not open log file.\n";
        return 1;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to take process snapshot.\n";
        return 1;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            logFile << L"PID: " << pe.th32ProcessID << L" | Executable: " << pe.szExeFile << L"\n";
        } while (Process32NextW(hSnapshot, &pe));
    } else {
        std::wcerr << L"Process32First failed.\n";
    }

    CloseHandle(hSnapshot);
    logFile.close();
    std::wcout << L"Process list saved to process_log.txt.\n";

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
