#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "cet2_backtrace.h"

#include <dbghelp.h>
#include <intrin.h>
#include <winternl.h>

#include <cstdio>

#pragma comment(lib, "dbghelp.lib")

namespace
{

struct ModuleTableEntry
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

bool IsUsableSsp(std::uint64_t ssp)
{
    return ssp >= 0x10000 && (ssp >> 48) == 0;
}

int WalkShadowRaw(std::uint64_t ssp, std::uint64_t* out, int maxEntries)
{
    int count = 0;
    __try
    {
        for (int i = 0; i < maxEntries; ++i)
        {
            if ((ssp & 0xFFF) == 0)
            {
                break;
            }
            const auto value =
                *reinterpret_cast<const volatile std::uint64_t*>(ssp);
            out[count++] = value;
            if (value == 0)
            {
                break;
            }
            ssp += sizeof(std::uint64_t);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return count;
}

std::string WideToUtf8(const wchar_t* wide)
{
    if (!wide || !*wide)
    {
        return {};
    }
    const int size =
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0)
    {
        return {};
    }
    std::string out(static_cast<size_t>(size) - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), size, nullptr, nullptr);
    return out;
}

bool g_symbolsReady = false;

bool EnsureSymbols()
{
    if (g_symbolsReady)
    {
        return true;
    }
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    if (!SymInitializeW(GetCurrentProcess(), nullptr, TRUE))
    {
        // ERROR_INVALID_PARAMETER means DbgHelp was already initialized by
        // another module (e.g. the bypass package); that is fine, symbols
        // still work.
        if (GetLastError() != ERROR_INVALID_PARAMETER)
        {
            return false;
        }
    }
    g_symbolsReady = true;
    return g_symbolsReady;
}

constexpr DWORD kSymbolNameChars = 256;
struct SymbolBuffer
{
    SYMBOL_INFOW Sym;
    wchar_t Name[kSymbolNameChars];
};

std::string Hex64(std::uint64_t value)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(value));
    return buf;
}

std::string ProtectName(DWORD protect)
{
    const DWORD base = protect & 0xFF;
    const char* name = "?";
    switch (base)
    {
    case PAGE_NOACCESS:          name = "NOACCESS"; break;
    case PAGE_READONLY:          name = "R"; break;
    case PAGE_READWRITE:         name = "RW"; break;
    case PAGE_WRITECOPY:         name = "WC"; break;
    case PAGE_EXECUTE:           name = "X"; break;
    case PAGE_EXECUTE_READ:      name = "RX"; break;
    case PAGE_EXECUTE_READWRITE: name = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: name = "XWC"; break;
    default:                     break;
    }
    std::string out = name;
    if (protect & PAGE_GUARD)
    {
        out += "+GUARD";
    }
    if (protect & PAGE_NOCACHE)
    {
        out += "+NOCACHE";
    }
    return out;
}

const ModuleTableEntry* FindModule(std::uint64_t address)
{
    const auto* teb = NtCurrentTeb();
    if (!teb || !teb->ProcessEnvironmentBlock || !teb->ProcessEnvironmentBlock->Ldr)
    {
        return nullptr;
    }
    const auto* head = &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    for (auto* entry = head->Flink; entry != head; entry = entry->Flink)
    {
        const auto* module = CONTAINING_RECORD(entry, ModuleTableEntry, InMemoryOrderLinks);
        const auto base = reinterpret_cast<std::uintptr_t>(module->DllBase);
        const auto size = static_cast<std::uintptr_t>(module->SizeOfImage);
        if (address >= base && address < base + size)
        {
            return module;
        }
    }
    return nullptr;
}

} // namespace

namespace cet2stack
{

std::string ResolveAddress(std::uint64_t address)
{
    const auto* module = FindModule(address);
    std::string moduleName = module ? WideToUtf8(module->BaseDllName.Buffer) : "";

    if (EnsureSymbols())
    {
        SymbolBuffer buffer{};
        buffer.Sym.SizeOfStruct = sizeof(SYMBOL_INFOW);
        buffer.Sym.MaxNameLen = kSymbolNameChars;
        DWORD64 displacement = 0;
        if (SymFromAddrW(GetCurrentProcess(), address, &displacement, &buffer.Sym))
        {
            std::string symbol = WideToUtf8(buffer.Sym.Name);
            if (!symbol.empty())
            {
                std::string out;
                if (!moduleName.empty())
                {
                    out = moduleName + "!";
                }
                out += symbol;
                if (displacement)
                {
                    out += " + 0x" + Hex64(displacement);
                }
                return out;
            }
        }
    }

    if (module)
    {
        const auto base = reinterpret_cast<std::uintptr_t>(module->DllBase);
        return moduleName + "+0x" + Hex64(address - base);
    }
    return "0x" + Hex64(address);
}

std::string DescribeMemory(std::uint64_t address)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
    {
        return "?";
    }

    std::string out;
    switch (mbi.State)
    {
    case MEM_COMMIT:  out = "COMMIT"; break;
    case MEM_RESERVE: out = "RESERVE"; break;
    case MEM_FREE:    out = "FREE"; break;
    default:          out = "?"; break;
    }
    switch (mbi.Type)
    {
    case MEM_IMAGE:   out += ",IMAGE"; break;
    case MEM_MAPPED:  out += ",MAPPED"; break;
    case MEM_PRIVATE: out += ",PRIVATE"; break;
    default:          out += ",?"; break;
    }
    out += "," + ProtectName(mbi.Protect);
    return out;
}

bool IsShadowStackArmed()
{
    return (GetEnabledXStateFeatures() & XSTATE_MASK_CET_U) != 0;
}

std::vector<std::uint64_t> CaptureCETBacktrace(std::uint32_t maxFrames)
{
    std::vector<std::uint64_t> frames;
    const std::uint64_t ssp = _rdsspq();
    if (!IsUsableSsp(ssp) || maxFrames == 0)
    {
        return frames;
    }
    if (maxFrames > 64)
    {
        maxFrames = 64;
    }
    std::uint64_t buffer[64];
    const int count = WalkShadowRaw(ssp, buffer, static_cast<int>(maxFrames));
    frames.assign(buffer, buffer + count);
    return frames;
}

std::vector<std::uint64_t> CaptureNormalBacktrace(std::uint32_t maxFrames)
{
    std::vector<std::uint64_t> frames;
    if (maxFrames == 0)
    {
        return frames;
    }
    if (maxFrames > 64)
    {
        maxFrames = 64;
    }
    PVOID buffer[64];
    const USHORT count =
        CaptureStackBackTrace(1, maxFrames, buffer, nullptr);
    frames.reserve(count);
    for (USHORT i = 0; i < count; ++i)
    {
        frames.push_back(reinterpret_cast<std::uint64_t>(buffer[i]));
    }
    return frames;
}

void PrintBacktrace(const char* label,
                    const std::vector<std::uint64_t>& frames,
                    std::size_t skip)
{
    std::printf("[bt2] %s (%zu frames)\n", label, frames.size());
    if (frames.empty() || skip >= frames.size())
    {
        std::printf("[bt2]   (empty)\n");
        return;
    }
    for (std::size_t i = skip; i < frames.size(); ++i)
    {
        std::printf("[bt2]   [%02zu] %-52s %s\n", i,
                    ResolveAddress(frames[i]).c_str(),
                    DescribeMemory(frames[i]).c_str());
    }
}

bool BacktracesMatch(const std::vector<std::uint64_t>& normal,
                     const std::vector<std::uint64_t>& cet)
{
    if (normal.empty() || cet.empty())
    {
        return false;
    }
    // Both walks should already start at the same first return address
    // (the ntdll epilogue). Tolerate one extra leading entry in either list
    // (capture skip differences) but otherwise require exact equality.
    const auto equalFrom = [](const std::vector<std::uint64_t>& a,
                              const std::vector<std::uint64_t>& b,
                              std::size_t shift)
    {
        if (shift > b.size() || a.size() > b.size() - shift)
        {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (a[i] != b[i + shift])
            {
                return false;
            }
        }
        return true;
    };
    return equalFrom(normal, cet, 0) ||
           equalFrom(normal, cet, 1) ||
           equalFrom(cet, normal, 1);
}

} // namespace cet2stack
