#pragma once

#include <Windows.h>

// ---------------------------------------------------------------------------
// Backtrace verification pair for bypass2: normal unwind-based backtrace and
// CET hardware shadow-stack backtrace, plus module+offset resolution.
//
// The point of bypass2 is that the two walks are identical: every frame is a
// real return address produced by an architectural CALL, so the read-only
// shadow stack contains exactly the same addresses as the normal stack.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace cet2stack
{

std::string ResolveAddress(std::uint64_t address);

// Memory attributes of the page containing `address`
// (VirtualQuery: COMMIT/RESERVE/FREE + IMAGE/MAPPED/PRIVATE + PAGE_*).
std::string DescribeMemory(std::uint64_t address);

// Real CET shadow-stack backtrace of the current thread. Empty when CET is
// not armed (rdsspq is not usable on such systems).
std::vector<std::uint64_t> CaptureCETBacktrace(std::uint32_t maxFrames = 64);

// Unwind-based normal backtrace of the current thread.
std::vector<std::uint64_t> CaptureNormalBacktrace(std::uint32_t maxFrames = 64);

// True when the process actually runs with user-mode shadow stacks armed.
bool IsShadowStackArmed();

void PrintBacktrace(const char* label,
                    const std::vector<std::uint64_t>& frames,
                    std::size_t skip = 0);

// Whether both backtraces contain exactly the same return addresses
// (allowing the first entry to differ: the normal walk starts with the
// current RIP while the shadow walk starts with the first return address).
bool BacktracesMatch(const std::vector<std::uint64_t>& normal,
                     const std::vector<std::uint64_t>& cet);

} // namespace cet2stack
