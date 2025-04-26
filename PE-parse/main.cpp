#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h> 

int main() {
    std::ifstream file(R"(C:\Windows\SysWOW64\calc.exe)", std::ios::binary);
    if (!file) {
        std::cerr << "Cannot open file.\n";
        return 1;
    }

    // Load all content
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(file), {});

    // Check MZ header
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid PE file.\n";
        return 1;
    }

    // Move to NT headers
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature.\n";
        return 1;
    }

    // Print basic info
    std::cout << "Entry Point: 0x" << std::hex << ntHeaders->OptionalHeader.AddressOfEntryPoint << "\n";
    std::cout << "Image Base: 0x" << std::hex << ntHeaders->OptionalHeader.ImageBase << "\n";
    std::cout << "Number of Sections: " << ntHeaders->FileHeader.NumberOfSections << "\n";

    // List Sections
    auto section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        std::cout << "Section: " << section->Name << ", VA: 0x"
            << std::hex << section->VirtualAddress
            << ", Size: 0x" << section->Misc.VirtualSize << "\n";
    }

    return 0;
}
