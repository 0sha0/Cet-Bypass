#pragma once

// ---------------------------------------------------------------------------
// CET-invisible arbitrary-function spoofing (x64, C++ + cet2_trampoline.asm).
//
// Calls any plain x64 function on the CURRENT thread through the legal ntdll
// call-site chain:
//
//   ntdll call site A --CALL--> PE continuation --JMP--> ntdll call site B
//   --CALL--> target -> RET -> ntdll epilogue B -> RET -> ntdll epilogue A
//   -> RET -> caller
//
// The target's RAX survives the pure `add rsp, K; ret` epilogues, so 64-bit
// results are returned through Result::Value.
//
// Argument limit: 5 (RCX/RDX/R8/R9 + one stack argument). The chain's frames
// are the two legal ntdll sites with K == 0x28; the 6th stack argument slot
// would land exactly on the previous ntdll epilogue's return address and is
// therefore rejected instead of silently corrupting the chain.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <initializer_list>

#include "cet2_common.h"

namespace cet2
{

// Hidden call of `function` with up to 5 x64 integer/pointer arguments
// (2 ntdll frames in the backtrace).
Result CallFunction(const void* function,
                    std::initializer_list<std::uint64_t> args);

// Same, with three ntdll frames in the fake backtrace.
Result CallFunction3(const void* function,
                     std::initializer_list<std::uint64_t> args);

} // namespace cet2
