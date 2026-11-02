#pragma once

// ---------------------------------------------------------------------------
// CET-invisible indirect syscall module (x64, C++ + cet2_trampoline.asm).
//
// Stays on the calling thread. The syscall is executed through the legal
// ntdll call-site chain:
//
//   ntdll call site A --CALL--> PE continuation --JMP--> ntdll call site B
//   --CALL--> (ntdll Nt* stub | Cet2SyscallStub) -> syscall -> RET -> epilogues
//
// With 0..4 arguments the target is the real ntdll Nt*/Zw* stub, so the whole
// visible frame list is ntdll. With 5..12 arguments Cet2SyscallStub is used:
// it gives itself a private frame and hands args 5..12 to the kernel from its
// own stack, so the chain's return addresses are never touched.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <initializer_list>

#include "cet2_common.h"

namespace cet2
{

// Number of Nt*/Zw* stubs resolved from ntdll's export table.
std::size_t SyscallCount();

// True when `name` was resolved to a real syscall stub.
bool SyscallAvailable(const char* name);

// Hidden indirect syscall by name (2 ntdll frames), up to 12 raw x64 args.
//   Syscall("NtYieldExecution", {});
//   Syscall("NtDelayExecution", {0, (uint64_t)&delay});
//   Syscall("NtQueryInformationProcess", {h, 0, &pbi, sizeof(pbi), &len});
Result Syscall(const char* name, std::initializer_list<std::uint64_t> args);

// Same, with three ntdll frames in the fake backtrace.
Result Syscall3(const char* name, std::initializer_list<std::uint64_t> args);

// Same, but with a caller-supplied syscall number (undocumented syscalls).
Result SyscallRaw(std::uint32_t ssn,
                  std::initializer_list<std::uint64_t> args);

// Three-frame variant of SyscallRaw.
Result SyscallRaw3(std::uint32_t ssn,
                   std::initializer_list<std::uint64_t> args);

} // namespace cet2
