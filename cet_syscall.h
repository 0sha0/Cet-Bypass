#pragma once

// ---------------------------------------------------------------------------
// CET-invisible indirect syscall module (x64, C++ + cet_trampoline.asm).
//
// Resolves every Nt*/Zw* syscall stub in ntdll, then invokes the requested
// syscall in a fresh worker thread through CetHiddenSyscallStart. At syscall
// time the worker's real CET shadow stack contains only the legitimate
// thread-start chain (kernel32!BaseThreadInitThunk / ntdll!RtlUserThreadStart)
// - never a frame from the caller's module.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <initializer_list>

#include "cet_common.h"

namespace cethidden
{

// Number of Nt*/Zw* stubs resolved from ntdll's export table.
std::size_t SyscallCount();

// True when `name` was resolved to a real `syscall`-terminated stub.
bool SyscallAvailable(const char* name);

// Hidden indirect syscall by name, up to 12 raw x64 arguments.
//   Syscall("NtYieldExecution", {});
//   Syscall("NtDelayExecution", {0, (uint64_t)&delay});
Result Syscall(const char* name, std::initializer_list<std::uint64_t> args);

// Same, but with a caller-resolved syscall instruction address + SSN.
Result SyscallRaw(void* syscallInstruction, std::uint32_t ssn,
                  std::initializer_list<std::uint64_t> args);

} // namespace cethidden
