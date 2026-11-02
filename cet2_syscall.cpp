#include "cet2_syscall.h"

#include "cet2_gadget.h"

#include <Windows.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

namespace cet2
{
namespace
{

struct SyscallInfo
{
    std::string Name;
    std::uint32_t Ssn = 0;
    std::uint8_t* Stub = nullptr;
};

using SyscallMap = std::unordered_map<std::string, SyscallInfo>;

bool ParseStub(const char* name, std::uint8_t* stub, SyscallInfo& out)
{
    // Windows 10/11 x64 stub shapes:
    //   4C 8B D1                     mov r10, rcx
    //   B8 xx xx xx xx               mov eax, <SSN>
    //   F6 04 25 08 03 FE 7F 01      test byte ptr [0x7FFE0308], 1
    //   75 03                         jne +3
    //   0F 05                         syscall
    //   C3                             ret
    // Some exports are user-mode fast paths (jmp thunks); follow one jmp.
    for (int attempt = 0; attempt < 2; ++attempt)
    {
        if (stub[0] == 0xE9)
        {
            const auto rel = *reinterpret_cast<std::int32_t*>(stub + 1);
            stub += 5 + rel;
            continue;
        }
        if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1)
        {
            return false;
        }
        for (int j = 3; j < 16; ++j)
        {
            if (stub[j] == 0xB8)
            {
                out.Ssn = *reinterpret_cast<std::uint32_t*>(stub + j + 1);
                break;
            }
        }
        for (int k = 3; k < 48; ++k)
        {
            if (stub[k] == 0x0F && stub[k + 1] == 0x05)
            {
                out.Stub = stub;
                out.Name = name;
                return true;
            }
        }
        return false;
    }
    return false;
}

SyscallMap& SyscallTable()
{
    static SyscallMap table;
    return table;
}

bool EnsureSyscallTable()
{
    static bool initialized = false;
    static bool ok = false;
    if (initialized)
    {
        return ok;
    }
    initialized = true;

    auto* ntdll = detail::GetNtdllBase();
    if (!ntdll)
    {
        return false;
    }
    const auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    const auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ntdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    const auto& exportDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.VirtualAddress || !exportDir.Size)
    {
        return false;
    }
    const auto* exp =
        reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(ntdll + exportDir.VirtualAddress);
    const auto* names = reinterpret_cast<DWORD*>(ntdll + exp->AddressOfNames);
    const auto* ordinals = reinterpret_cast<WORD*>(ntdll + exp->AddressOfNameOrdinals);
    const auto* functions = reinterpret_cast<DWORD*>(ntdll + exp->AddressOfFunctions);

    auto& table = SyscallTable();
    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        const char* name = reinterpret_cast<const char*>(ntdll + names[i]);
        const bool ntOrZw = (name[0] == 'N' && name[1] == 't') ||
                            (name[0] == 'Z' && name[1] == 'w');
        if (!ntOrZw || !name[2])
        {
            continue;
        }
        const WORD ordinal = ordinals[i];
        auto* stub = ntdll + functions[ordinal];
        SyscallInfo info;
        if (ParseStub(name, stub, info))
        {
            table[name] = info;
        }
    }
    ok = !table.empty();
    return ok;
}

const SyscallInfo* FindSyscall(const char* name)
{
    if (!EnsureSyscallTable())
    {
        return nullptr;
    }
    const auto& table = SyscallTable();
    const auto it = table.find(name);
    return it == table.end() ? nullptr : &it->second;
}

Result RunSyscallChain(const SyscallInfo* si, std::uint32_t ssn,
                       std::initializer_list<std::uint64_t> args, int frames)
{
    void* target = nullptr;
    const std::size_t count = args.size();
    if (count <= 4 && si)
    {
        // Real ntdll stub: the visible syscall frame is ntdll itself.
        target = si->Stub;
    }
    else
    {
        // Our private stub forwards args 1..12 from the request / its own
        // frame. Used for 5+ args and for caller-supplied syscall numbers.
        target = reinterpret_cast<void*>(&Cet2SyscallStub);
    }

    std::uint64_t buffer[12] = {};
    std::size_t i = 0;
    for (const auto value : args)
    {
        if (i < 12)
        {
            buffer[i++] = value;
        }
    }
    if (frames == 2)
    {
        return detail::RunChain2(target, ssn, buffer, count);
    }
    return detail::RunChain3(target, ssn, buffer, count);
}

} // namespace

std::size_t SyscallCount()
{
    return EnsureSyscallTable() ? SyscallTable().size() : 0;
}

bool SyscallAvailable(const char* name)
{
    return FindSyscall(name) != nullptr;
}

Result Syscall(const char* name, std::initializer_list<std::uint64_t> args)
{
    const SyscallInfo* si = FindSyscall(name);
    if (!si)
    {
        return {};
    }
    return RunSyscallChain(si, si->Ssn, args, 2);
}

Result Syscall3(const char* name, std::initializer_list<std::uint64_t> args)
{
    const SyscallInfo* si = FindSyscall(name);
    if (!si)
    {
        return {};
    }
    return RunSyscallChain(si, si->Ssn, args, 3);
}

Result SyscallRaw(std::uint32_t ssn, std::initializer_list<std::uint64_t> args)
{
    return RunSyscallChain(nullptr, ssn, args, 2);
}

Result SyscallRaw3(std::uint32_t ssn, std::initializer_list<std::uint64_t> args)
{
    return RunSyscallChain(nullptr, ssn, args, 3);
}

} // namespace cet2
