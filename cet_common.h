#pragma once

// ---------------------------------------------------------------------------
// Shared plumbing for the CET shadow-stack bypass package (x64 only).
//
// cet_common.h is intentionally header-only: it defines the request/result
// structures shared by the syscall and arbitrary-function spoofers, declares
// the two MASM trampolines (cet_trampoline.asm), and runs the hidden worker
// thread. All of this is plain C++ - the only assembly in the package is the
// JMP trampoline itself.
// ---------------------------------------------------------------------------

#include <Windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtCreateThreadEx(PHANDLE ThreadHandle,
                                           ACCESS_MASK DesiredAccess,
                                           PVOID ObjectAttributes,
                                           HANDLE ProcessHandle,
                                           PVOID StartRoutine,
                                           PVOID Argument,
                                           ULONG CreateFlags,
                                           SIZE_T ZeroBits,
                                           SIZE_T StackSize,
                                           SIZE_T StackReserve,
                                           PVOID AttributeList);

// Implemented in bypass/cet_trampoline.asm (the ONLY required assembly).
extern "C" void CetHiddenSyscallStart(void* request);
extern "C" void CetHiddenFunctionStart(void* request);

namespace cethidden
{

// Layout must match cet_trampoline.asm byte for byte.
struct Request
{
    std::uint32_t Ssn = 0;             // +0x00
    std::uint32_t Pad = 0;             // +0x04
    void* Target = nullptr;            // +0x08
    std::uint64_t A1 = 0;              // +0x10
    std::uint64_t A2 = 0;              // +0x18
    std::uint64_t A3 = 0;              // +0x20
    std::uint64_t A4 = 0;              // +0x28
    std::uint64_t A5 = 0;              // +0x30
    std::uint64_t A6 = 0;              // +0x38
    std::uint64_t A7 = 0;              // +0x40
    std::uint64_t A8 = 0;              // +0x48
    std::uint64_t A9 = 0;              // +0x50
    std::uint64_t A10 = 0;             // +0x58
    std::uint64_t A11 = 0;             // +0x60
    std::uint64_t A12 = 0;             // +0x68
    std::uint64_t SspSnapshot = 0;     // +0x70
    std::uint64_t RspSnapshot = 0;     // +0x78
    std::uint64_t RetAddrSnapshot = 0; // +0x80
    std::uint64_t ShadowCount = 0;     // +0x88
    std::uint64_t Shadow[8] = {};      // +0x90
    std::uint64_t NormalCount = 0;     // +0xD0
    std::uint64_t Normal[8] = {};      // +0xD8
};
static_assert(sizeof(Request) == 0x118, "cethidden::Request layout mismatch");

struct Result
{
    NTSTATUS Status = 0;               // thread exit code = syscall/function EAX
    bool Ok = false;                   // worker thread was created and ran
    std::uint64_t SspAtEntry = 0;      // shadow stack pointer at JMP boundary
    std::uint64_t RspAtEntry = 0;      // normal stack pointer at JMP boundary
    std::uint64_t RetAddrAtEntry = 0;  // [RSP] at JMP boundary (kernel32+0x14)
    std::vector<std::uint64_t> CETFrames;    // real shadow-stack snapshot
    std::vector<std::uint64_t> NormalFrames; // normal-stack snapshot (filtered)
};

// True when the process actually gets user-mode shadow stacks (CET_U in the
// enabled XState features).
inline bool IsShadowStackArmed()
{
    return (GetEnabledXStateFeatures() & XSTATE_MASK_CET_U) != 0;
}

namespace detail
{

inline bool IsExecutableAddress(std::uint64_t address)
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

} // namespace detail

// Starts a hidden worker thread whose StartRoutine is one of the MASM
// trampolines. The trampoline JMPs to `target`; the thread exits with the
// target's EAX as its exit code. Maximum 12 x64 integer arguments.
inline Result RunHidden(void* startProc, void* target, std::uint32_t ssn,
                        const std::uint64_t* args, std::size_t count)
{
    Result result;
    if (!startProc || !target || count > 12)
    {
        return result;
    }

    Request request{};
    request.Ssn = ssn;
    request.Target = target;
    std::uint64_t* slot = &request.A1;
    for (std::size_t i = 0; i < count; ++i)
    {
        slot[i] = args[i];
    }

    HANDLE thread = nullptr;
    const NTSTATUS st = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, nullptr,
                                         GetCurrentProcess(), startProc, &request,
                                         0, 0, 0, 0, nullptr);
    if (st < 0)
    {
        result.Status = st;
        return result;
    }
    result.Ok = true;

    WaitForSingleObject(thread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(thread, &exitCode);
    CloseHandle(thread);

    result.Status = static_cast<NTSTATUS>(static_cast<LONG>(exitCode));
    result.SspAtEntry = request.SspSnapshot;
    result.RspAtEntry = request.RspSnapshot;
    result.RetAddrAtEntry = request.RetAddrSnapshot;

    const std::size_t shadowCount = request.ShadowCount > 8 ? 8 : request.ShadowCount;
    result.CETFrames.assign(request.Shadow, request.Shadow + shadowCount);

    // Normal-stack raw values include our fake stack args and scratch data;
    // keep only values that point into committed executable memory.
    const std::size_t normalCount = request.NormalCount > 8 ? 8 : request.NormalCount;
    for (std::size_t i = 0; i < normalCount; ++i)
    {
        if (detail::IsExecutableAddress(request.Normal[i]))
        {
            result.NormalFrames.push_back(request.Normal[i]);
        }
    }
    return result;
}

} // namespace cethidden
