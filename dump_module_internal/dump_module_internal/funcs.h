#pragma once

namespace funcs
{
    bool GetModuleInfo(const char* ModuleName,  LPMODULEINFO ModuleInfoOut);
    bool dump_user_module(const char* module);
    int PrintModules();

};

const wchar_t* get_wc(const char* c)
{
    const size_t cSize = strlen(c) + 1;
    wchar_t* wc = new wchar_t[cSize];
    mbstowcs(wc, c, cSize);

    return wc;
}

int funcs::PrintModules()
{
    HMODULE hMods[1024];

    DWORD cbNeeded;
    unsigned int i;

    // Get a list of all the modules in this process.
    HANDLE hProcess = GetCurrentProcess();
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            //Get the full path to the module's file.

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.
                printf("%ws\n", szModName);
            }
        }
    }

    // Release the handle to the process.

    CloseHandle(hProcess);

    return 0;
}
bool funcs::GetModuleInfo(const char* ModuleName, LPMODULEINFO ModuleInfoOut)
{
    const auto hmodule = GetModuleHandleA(ModuleName);

    if (!hmodule)
    {
        printf("[-] Modulo nao disponivel: \n");
        return 0;
    }

    MODULEINFO module_info = { 0 };   
    GetModuleInformation(GetCurrentProcess(), hmodule, &module_info, sizeof(module_info));

    if (!module_info.SizeOfImage)
    {
        printf("Algo esta errado");
        return 0;
    }

    *ModuleInfoOut = module_info;

    return 1;
}
bool funcs::dump_user_module(const char* module)
{
    MODULEINFO module_info;
    if (!funcs::GetModuleInfo(module, &module_info))
        return 0;


    printf("[+] EntryPoint: %p \n", (DWORD_PTR)module_info.EntryPoint);
    printf("[+] lpBaseOfDll: %p \n", (DWORD_PTR)module_info.lpBaseOfDll);
    printf("[+] Module th32ModuleID: %X \n", (DWORD)module_info.SizeOfImage);


    // Alocar um buffer suficientemente grande para o m�dulo
    //
    auto buf = new char[(DWORD_PTR)module_info.SizeOfImage];

    if (!buf)
        return 0;

    // Copiar o m�dulo da mem�ria para o nosso buffer rec�m-alocado
    //
    SIZE_T bytes_read = 0;
    ReadProcessMemory(GetCurrentProcess(), (PVOID)module_info.lpBaseOfDll, buf, module_info.SizeOfImage, &bytes_read);

    if (!bytes_read)
    {
        printf("[-] Erro ao ler bytes...\n");
        delete[] buf;
        return 0;
    }

    //Obter as informa��es a partir dos cabe�alos no PE (se n�o foram apagados como uma forma de anti-dumping)

    auto pimage_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buf);
    auto pimage_nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buf + pimage_dos_header->e_lfanew);

    // Este � um PE 64. Utilizar a vers�o em 64 bits dos nt headers
    //
    if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        // Obter o ponteiro para o primeiro section header
        //
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers + 1);

        for (WORD i = 0; i < pimage_nt_headers->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            // Converter as se��es deste PE para sua forma "unmapped" ao deixar o file offset igual ao RVA (VirtualAddress), assim como o raw size (SizeOfRawData)
            // igual ao virtual size (VirtualSize). Isso nos permite carregar o bin�rio de maneira limpa em ferramentas para an�lise est�tica
            //
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
        }

        // Arrumar o image base para a base do m�dulo que ser� dumpado
        //
        pimage_nt_headers->OptionalHeader.ImageBase = (DWORD_PTR)module_info.lpBaseOfDll;
    }

    // Este � um PE 32. Utilizar a vers�o em 32 bits dos nt headers
    //
    else if (pimage_nt_headers->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        auto pimage_nt_headers32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(pimage_nt_headers);
        auto pimage_section_header = reinterpret_cast<PIMAGE_SECTION_HEADER>(pimage_nt_headers32 + 1);

        for (WORD i = 0; i < pimage_nt_headers32->FileHeader.NumberOfSections; ++i, ++pimage_section_header)
        {
            // Converter as se��es deste PE para sua forma "unmapped" ao deixar o file offset igual ao RVA (VirtualAddress), assim como o raw size (SizeOfRawData)
            // igual ao virtual size (VirtualSize). Isso nos permite carregar o bin�rio de maneira limpa em ferramentas para an�lise est�tica
            //
            pimage_section_header->PointerToRawData = pimage_section_header->VirtualAddress;
            pimage_section_header->SizeOfRawData = pimage_section_header->Misc.VirtualSize;
            // printf("pimage_section_header = %X\n", (DWORD)pimage_section_header);
             //system("pause");
        }

        // Arrumar o image base para a base do m�dulo que ser� dumpado
        //
        pimage_nt_headers32->OptionalHeader.ImageBase = (DWORD_PTR)(module_info.lpBaseOfDll);
    }

    // N�o suportado
    //
    else
    {
        delete[] buf;
        return 0;
    }

    // Montar o nome do m�dulo dumpado. Exemplo: "dump_kernel32.dll"
    //
    wchar_t bufName[MAX_PATH] = { 0 };
    wcscpy_s(bufName, L"dump_");
    wcscat_s(bufName, get_wc(module));

    // Criar o arquivo no diret�rio atual (voc� pode mudar para outro diret�rio se quiser)
    //
    HANDLE hFile = CreateFileW(bufName, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Erro ao iniciar CreateFile: \n");
        return 0;
    }

    // Escrever os conte�dos do buffer para o arquivo
        //
    DWORD Ip1, Ip2;
    WriteFile(hFile, buf, (DWORD_PTR)bytes_read, &Ip1, nullptr);

    // Fechar o handle aberto para o arquivo. Por mais que o Windows garante que n�o ter�o leak de recursos ap�s o encerramento do processo, � uma boa pr�tica liberar tudo
    //
    CloseHandle(hFile);
    //CloseHandle(hProc);
    printf("[+] Modulo dumpado com sucesso...\n\n ");

    // Liberar o buffer
    //
    delete[] buf;

    return 1;
}