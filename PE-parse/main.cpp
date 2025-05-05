#include <iostream>
#include <fstream>
#include <windows.h>
#include <string>

uint32_t rvaToOffset(uint32_t rva, IMAGE_SECTION_HEADER* secs, int count) {
    for (int i = 0; i < count; ++i)
        if (rva >= secs[i].VirtualAddress && rva < secs[i].VirtualAddress + secs[i].Misc.VirtualSize)
            return rva - secs[i].VirtualAddress + secs[i].PointerToRawData;
    return 0;
}

void printImportTable(const uint8_t* buf, IMAGE_OPTIONAL_HEADER64& optHdr,
    IMAGE_SECTION_HEADER* secs, int count) {
    DWORD rva = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return std::cout << "No Import Table.\n", void();

    auto impDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(buf + rvaToOffset(rva, secs, count));
    std::cout << "\n=== Import Table ===\n";
    while (impDesc->Name) {
        std::cout << "DLL: " << (char*)(buf + rvaToOffset(impDesc->Name, secs, count)) << "\n";
        auto thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
            buf + rvaToOffset(impDesc->OriginalFirstThunk ? impDesc->OriginalFirstThunk : impDesc->FirstThunk, secs, count));
        while (thunk->u1.AddressOfData) {
            auto imp = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(buf + rvaToOffset(thunk->u1.AddressOfData, secs, count));
            std::cout << "  - " << imp->Name << "\n";
            ++thunk;
        }
        ++impDesc;
    }
}

void printExportTable(const uint8_t* buf, IMAGE_OPTIONAL_HEADER64& optHdr,
    IMAGE_SECTION_HEADER* secs, int count) {
    DWORD rva = optHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return std::cout << "No Export Table.\n", void();

    auto expDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buf + rvaToOffset(rva, secs, count));
    std::cout << "\n=== Export Table (DLL: "
        << (char*)(buf + rvaToOffset(expDir->Name, secs, count)) << ") ===\n";

    auto names = reinterpret_cast<const DWORD*>(buf + rvaToOffset(expDir->AddressOfNames, secs, count));
    for (DWORD i = 0; i < expDir->NumberOfNames; ++i)
        std::cout << "Exported Function: " << (char*)(buf + rvaToOffset(names[i], secs, count)) << "\n";
}

int main() {
    char windir[MAX_PATH];
    GetEnvironmentVariableA("WINDIR", windir, MAX_PATH);
    std::ifstream file(std::string(windir) + "\\system32\\notepad.exe", std::ios::binary);
    if (!file) return std::cerr << "Cannot open file.\n", 1;

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0);
    auto* buf = new uint8_t[size];
    file.read((char*)buf, size);

    auto dos = (IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return std::cerr << "Not a valid PE file.\n", delete[] buf, 1;

    auto nt = (IMAGE_NT_HEADERS64*)(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return std::cerr << "Invalid PE signature.\n", delete[] buf, 1;

    std::cout << "[+] PE32+ (x64)\nEntry Point: 0x" << std::hex << nt->OptionalHeader.AddressOfEntryPoint
        << "\nImage Base: 0x" << nt->OptionalHeader.ImageBase
        << "\nNumber of Sections: " << std::dec << nt->FileHeader.NumberOfSections << "\n";

    auto* secs = IMAGE_FIRST_SECTION(nt);
    std::cout << "\n=== Sections ===\n";
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        std::cout << "Section: " << std::string((char*)secs[i].Name, 8)
        << ", VA: 0x" << std::hex << secs[i].VirtualAddress
        << ", Size: 0x" << secs[i].Misc.VirtualSize << "\n";

    printImportTable(buf, nt->OptionalHeader, secs, nt->FileHeader.NumberOfSections);
    printExportTable(buf, nt->OptionalHeader, secs, nt->FileHeader.NumberOfSections);

    delete[] buf;
    return 0;
}
