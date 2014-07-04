#ifndef STEALTH_INJECT_H
#define STEALTH_INJECT_H

void StealthLoadLibrary(void* hProcess, const char* path);
bool StealthLoadLibraryMemory(void* hProcess, void* address);

#endif //STEALTH_INJECT_H