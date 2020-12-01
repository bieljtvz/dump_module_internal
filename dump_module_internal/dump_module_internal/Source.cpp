#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <Psapi.h>

#include "funcs.h"




VOID WINAPI Thread_Inicial(void)
{   

    static int status = 1;
    do 
    {
        printf("[+] Tecla F9 para listar os modulos: \n");
        printf("[+] Tecla F10 dumpar um modulo: \n");
        printf("[+] Tecla F11 para sair: \n");

        if (GetAsyncKeyState(VK_F9))
        {
            system("cls");
            printf("[+] Modulos carregados nesse processo: \n");
            funcs::PrintModules();
            system("pause");
        }

        if (GetAsyncKeyState(VK_F10))
        {
            system("cls");
            printf("[+] Digite o nome do modulo a ser dumpado: ");

            static char module_name[99];

            scanf("%s", module_name);

            if (funcs::dump_user_module(module_name))
            {
                printf("\n[+] Deseja dumpar mais algum modulo: (1=Sim || 0= Nao) \n");
                scanf("%i", &status);
            }

            Sleep(2000);
            system("cls");
        }

        if (GetAsyncKeyState(VK_F11))
        {
            FreeConsole();
            FreeLibraryAndExitThread(GetModuleHandleA(NULL), 0);
        }   
        system("pause");
        system("cls");
       

    } while (status == 1); 
   
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {

        AllocConsole();             
        freopen("CON", "w", stdout);
        freopen("CON", "r", stdin);

        DisableThreadLibraryCalls(hModule);
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Thread_Inicial, hModule, 0, 0);         
        
    }

    return TRUE;
}