#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <fstream>
#include <iostream>

void CreateNotepadProcess() {
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
        return;
    }

    std::wcout << L"Notepad launched. Process handle: " << pi.hProcess << std::endl;
    std::wcout << L"Notepad launched. PID: " << pi.dwProcessId << std::endl;

    std::wofstream logFile(L"process_log.txt");
    if (!logFile.is_open()) {
        std::wcerr << L"Could not open log file.\n";
        return;
    }

    logFile << L"Notepad PID: " << pi.dwProcessId << L"\n";
    logFile.close();

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void EnumerateProcessesAndThreads() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take process snapshot. Error: " << GetLastError() << std::endl;
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    std::cout << "Process Name\t\tPID\tThread Count" << std::endl;
    std::cout << "-----------------------------------------------" << std::endl;

    if (Process32First(hSnapshot, &pe)) {
        do {
            int threadCount = 0;
            HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hThreadSnap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te;
                te.dwSize = sizeof(THREADENTRY32);
                if (Thread32First(hThreadSnap, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pe.th32ProcessID) {
                            threadCount++;
                        }
                    } while (Thread32Next(hThreadSnap, &te));
                }
                CloseHandle(hThreadSnap);
            }
            std::wcout << pe.szExeFile << "\t" << pe.th32ProcessID << "\t" << threadCount << std::endl;
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

int wmain() {
    CreateNotepadProcess();
    EnumerateProcessesAndThreads();
    return 0;
}
