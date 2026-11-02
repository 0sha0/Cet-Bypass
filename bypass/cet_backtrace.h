#pragma once

#include <Windows.h>

// ---------------------------------------------------------------------------
// Stack backtrace pair (x64): normal unwind-based backtrace and CET hardware
// shadow-stack backtrace, plus module+offset address resolution. Used to
// verify the bypass: with CET armed, a shadow-stack walk shows every CALLer
// that a normal stack scan would also show - unless the call was made through
// the JMP trampoline in cet_trampoline.asm.
//
// CET backtrace: rdsspq -> walk the read-only shadow stack upward
// (Elastic ShadowStackWalk style, stops at page boundaries).
// Normal backtrace: CaptureStackBackTrace (kernel32, unwind-based), or
// suspend + context + raw stack scan for another thread.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cetstack
{

// "ntdll.dll+0x1234" style resolution using the PEB module list + DbgHelp.
std::string ResolveAddress(std::uint64_t address);

// Memory attributes of the page containing `address`
// (VirtualQuery: COMMIT/RESERVE/FREE + IMAGE/MAPPED/PRIVATE + PAGE_*).
std::string DescribeMemory(std::uint64_t address);

// Real CET shadow-stack backtrace of the current thread. Empty when CET is
// not armed (rdsspq returns garbage on such systems).
std::vector<std::uint64_t> CaptureCETBacktrace(std::uint32_t maxFrames = 64);

// Unwind-based normal backtrace of the current thread.
std::vector<std::uint64_t> CaptureNormalBacktrace(std::uint32_t maxFrames = 64);

// Same, but for another thread: suspend it, grab CONTEXT (RSP/RIP or
// XState CET_U SSP) and walk its stacks.
std::vector<std::uint64_t> CaptureCETBacktrace(HANDLE hThread,
                                               std::uint32_t maxFrames = 64);
std::vector<std::uint64_t> CaptureNormalBacktrace(HANDLE hThread,
                                                  std::uint32_t maxFrames = 64);

// Print frames, optionally skipping the first `skip` entries.
void PrintBacktrace(const char* label, const std::vector<std::uint64_t>& frames,
                    std::size_t skip = 0);

// Frames in `current` that did not appear in `previous`.
std::vector<std::uint64_t> FramesNotIn(const std::vector<std::uint64_t>& current,
                                       const std::vector<std::uint64_t>& previous);

} // namespace cetstack
