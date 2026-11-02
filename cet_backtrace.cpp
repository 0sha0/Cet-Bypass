#include "cet_backtrace.h"

#include <dbghelp.h>
#include <intrin.h>
#include <winternl.h>

#include <cstdio>
#include <unordered_set>

#pragma comment(lib, "dbghelp.lib")

namespace
{

// Stable user-mode LDR_DATA_TABLE_ENTRY layout for module+offset resolution.
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
    if (ssp < 0x10000)
    {
        return false;
    }
    const std::uint64_t top = ssp >> 48;
    return top == 0; // user-mode canonical address
}

// Raw SEH-guarded shadow-stack reader. No C++ objects here so __try is legal.
int WalkShadowRaw(std::uint64_t ssp, std::uint64_t* out, int maxEntries)
{
    int count = 0;
    __try
    {
        for (int i = 0; i < maxEntries; ++i)
        {
            if ((ssp & 0xFFF) == 0) // don't cross into a guard page
            {
                break;
            }
            const auto value = *reinterpret_cast<const volatile std::uint64_t*>(ssp);
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

// Raw SEH-guarded normal-stack reader: return addresses found at/above RSP.
int WalkStackRaw(std::uint64_t rsp, std::uint64_t* out, int maxEntries)
{
    int count = 0;
    __try
    {
        for (int i = 0; i < maxEntries; ++i)
        {
            if ((rsp & 0xFFF) == 0)
            {
                break;
            }
            out[count++] = *reinterpret_cast<const volatile std::uint64_t*>(rsp);
            rsp += sizeof(std::uint64_t);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return count;
}

bool IsExecutableCodeAddress(std::uint64_t address)
{
    if ((address >> 48) != 0)
    {
        return false;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
    {
        return false;
    }
    if (mbi.State != MEM_COMMIT)
    {
        return false;
    }
    const DWORD protect = mbi.Protect & 0xFF;
    return protect == PAGE_EXECUTE || protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE || protect == PAGE_EXECUTE_WRITECOPY;
}

// Elastic ShadowStackWalk-style SSP read for a (suspended) thread:
// GetThreadContext + CONTEXT_XSTATE -> CET_U -> IA32_PL3_SSP.
std::uint64_t GetSspViaThreadContext(HANDLE hThread)
{
    const DWORD64 cetMask = XSTATE_MASK_CET_U;
    if (!(GetEnabledXStateFeatures() & cetMask))
    {
        return 0;
    }
    DWORD contextLength = 0;
    (void)InitializeContext2(nullptr, CONTEXT_XSTATE, nullptr, &contextLength, cetMask);
    if (contextLength == 0)
    {
        return 0;
    }
    std::vector<BYTE> buffer(contextLength);
    PCONTEXT context = nullptr;
    if (!InitializeContext2(buffer.data(), CONTEXT_XSTATE, &context, &contextLength, cetMask))
    {
        return 0;
    }
    if (!GetThreadContext(hThread, context))
    {
        return 0;
    }
    DWORD64 featureMask = 0;
    if (!GetXStateFeaturesMask(context, &featureMask) || !(featureMask & cetMask))
    {
        return 0;
    }
    DWORD cetLength = 0;
    const auto* cet = static_cast<PXSAVE_CET_U_FORMAT>(
        LocateXStateFeature(context, XSTATE_CET_U, &cetLength));
    if (!cet || cetLength != sizeof(*cet))
    {
        return 0;
    }
    return cet->Ia32Pl3SspMsr;
}

std::string WideToUtf8(const wchar_t* wide)
{
    if (!wide || !*wide)
    {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
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
    g_symbolsReady = SymInitializeW(GetCurrentProcess(), nullptr, TRUE) != FALSE;
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

std::string FindModuleName(std::uint64_t address)
{
    const auto* teb = NtCurrentTeb();
    if (!teb || !teb->ProcessEnvironmentBlock || !teb->ProcessEnvironmentBlock->Ldr)
    {
        return {};
    }
    const auto* head = &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    for (auto* entry = head->Flink; entry != head; entry = entry->Flink)
    {
        const auto* module = CONTAINING_RECORD(entry, ModuleTableEntry, InMemoryOrderLinks);
        const auto base = reinterpret_cast<std::uintptr_t>(module->DllBase);
        const auto size = static_cast<std::uintptr_t>(module->SizeOfImage);
        if (address >= base && address < base + size)
        {
            return WideToUtf8(module->BaseDllName.Buffer);
        }
    }
    return {};
}

} // namespace

namespace cetstack
{

std::string ResolveAddress(std::uint64_t address)
{
    const std::string module = FindModuleName(address);

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
                if (!module.empty())
                {
                    out = module + "!";
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

    if (!module.empty())
    {
        const auto* teb = NtCurrentTeb();
        if (teb && teb->ProcessEnvironmentBlock && teb->ProcessEnvironmentBlock->Ldr)
        {
            const auto* head = &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
            for (auto* entry = head->Flink; entry != head; entry = entry->Flink)
            {
                const auto* mod = CONTAINING_RECORD(entry, ModuleTableEntry, InMemoryOrderLinks);
                const auto base = reinterpret_cast<std::uintptr_t>(mod->DllBase);
                const auto size = static_cast<std::uintptr_t>(mod->SizeOfImage);
                if (address >= base && address < base + size)
                {
                    return module + "+0x" + Hex64(address - base);
                }
            }
        }
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
    const USHORT count = CaptureStackBackTrace(1, maxFrames, buffer, nullptr);
    frames.reserve(count);
    for (USHORT i = 0; i < count; ++i)
    {
        frames.push_back(reinterpret_cast<std::uint64_t>(buffer[i]));
    }
    return frames;
}

std::vector<std::uint64_t> CaptureCETBacktrace(HANDLE hThread, std::uint32_t maxFrames)
{
    std::vector<std::uint64_t> frames;
    if (!hThread || maxFrames == 0)
    {
        return frames;
    }
    if (maxFrames > 64)
    {
        maxFrames = 64;
    }
    if (SuspendThread(hThread) == static_cast<DWORD>(-1))
    {
        return frames;
    }
    const std::uint64_t ssp = GetSspViaThreadContext(hThread);
    ResumeThread(hThread);

    if (!IsUsableSsp(ssp))
    {
        return frames;
    }
    std::uint64_t buffer[64];
    const int count = WalkShadowRaw(ssp, buffer, static_cast<int>(maxFrames));
    frames.assign(buffer, buffer + count);
    return frames;
}

std::vector<std::uint64_t> CaptureNormalBacktrace(HANDLE hThread, std::uint32_t maxFrames)
{
    std::vector<std::uint64_t> frames;
    if (!hThread || maxFrames == 0)
    {
        return frames;
    }
    if (maxFrames > 64)
    {
        maxFrames = 64;
    }
    if (SuspendThread(hThread) == static_cast<DWORD>(-1))
    {
        return frames;
    }
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;
    const bool ok = GetThreadContext(hThread, &context) != FALSE;
    if (ok)
    {
        if (IsExecutableCodeAddress(context.Rip))
        {
            frames.push_back(context.Rip);
        }
        std::uint64_t buffer[256];
        const int count = WalkStackRaw(context.Rsp, buffer, 256);
        for (int i = 0; i < count && frames.size() < maxFrames; ++i)
        {
            if (IsExecutableCodeAddress(buffer[i]))
            {
                frames.push_back(buffer[i]);
            }
        }
    }
    ResumeThread(hThread);
    return frames;
}

void PrintBacktrace(const char* label, const std::vector<std::uint64_t>& frames,
                    std::size_t skip)
{
    std::printf("[bt] %s (%zu frames)\n", label, frames.size());
    if (frames.empty() || skip >= frames.size())
    {
        std::printf("[bt]   (empty)\n");
        return;
    }
    for (std::size_t i = skip; i < frames.size(); ++i)
    {
        std::printf("[bt]   [%02zu] %-48s %s\n", i,
                    ResolveAddress(frames[i]).c_str(),
                    DescribeMemory(frames[i]).c_str());
    }
}

std::vector<std::uint64_t> FramesNotIn(const std::vector<std::uint64_t>& current,
                                       const std::vector<std::uint64_t>& previous)
{
    std::unordered_set<std::uint64_t> seen(previous.begin(), previous.end());
    std::vector<std::uint64_t> fresh;
    for (const auto frame : current)
    {
        if (!seen.count(frame))
        {
            fresh.push_back(frame);
        }
    }
    return fresh;
}

} // namespace cetstack
