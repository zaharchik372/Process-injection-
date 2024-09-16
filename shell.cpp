#include "Windows.h"
#include <iostream>

int main(int argc, char* argv[])
{
    // Проверяем, был ли передан PID
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    HANDLE processHandle;
    HANDLE remoteThread;
    PVOID remoteBuffer;

    // Используем cout для вывода PID
    std::cout << "Injecting to PID: " << atoi(argv[1]) << std::endl;

    // Открываем процесс с полным доступом
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    if (processHandle == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Получаем адрес функции WinExec в kernel32.dll
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "WinExec");
    if (loadLibraryAddr == NULL) {
        std::cerr << "Failed to get WinExec address. Error: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    // Выделяем память в удаленном процессе для аргумента "calc.exe"
    remoteBuffer = VirtualAllocEx(processHandle, NULL, strlen("calc.exe") + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remoteBuffer == NULL) {
        std::cerr << "Failed to allocate memory in remote process. Error: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    // Пишем строку "calc.exe" в удаленный процесс
    if (!WriteProcessMemory(processHandle, remoteBuffer, "calc.exe", strlen("calc.exe") + 1, NULL)) {
        std::cerr << "Failed to write memory in remote process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    // Создаем удаленный поток, который вызывает WinExec("calc.exe", SW_SHOW)
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteBuffer, 0, NULL);
    if (remoteThread == NULL) {
        std::cerr << "Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    // Ждем завершения потока
    WaitForSingleObject(remoteThread, INFINITE);

    // Освобождаем память и закрываем дескрипторы
    VirtualFreeEx(processHandle, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    std::cout << "Calculator launched in target process!" << std::endl;

    return 0;
}
