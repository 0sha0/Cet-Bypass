#pragma once

// ---------------------------------------------------------------------------
// CET-invisible arbitrary-function spoofing (x64, C++ + cet_trampoline.asm).
//
// Calls any plain x64 function (integer/pointer arguments, default calling
// convention) in a fresh worker thread through CetHiddenFunctionStart. The
// function is entered with a JMP instead of a CALL, so at entry the real CET
// shadow stack contains only the legitimate thread-start chain - the caller's
// module never appears. The function's EAX becomes the thread exit code.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <initializer_list>

#include "cet_common.h"

namespace cethidden
{

// Hidden call of `function` with up to 12 x64 integer/pointer arguments.
// 32-bit result is returned through Result::Status (thread exit code).
// Example:
//   int AddMul(uint64_t a, uint64_t b, uint64_t c);
//   auto r = CallFunction((const void*)&AddMul, {6, 7, 8});
//   printf("%d\n", (int32_t)r.Status);   // 6*7+8
Result CallFunction(const void* function, std::initializer_list<std::uint64_t> args);

} // namespace cethidden
