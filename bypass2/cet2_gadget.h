#pragma once

// ---------------------------------------------------------------------------
// Runtime discovery of the ntdll "legal call site" gadgets used by bypass2.
//
// A legal call site is a real `call rax` instruction inside ntdll whose
// following bytes are a pure epilogue:
//
//   call rax                  FF D0
//   nop                      90
//   add rsp, K                48 83 C4 K
//   ret                       C3
//
// When such a site is entered with RAX = our target, the CALL pushes the
// epilogue address onto BOTH the normal stack and the CET shadow stack; the
// target's RET pops it from both, and the epilogue RET pops the caller's
// return address from both. Nothing is written, nothing is patched.
//
// Only the exact class of pure `add rsp, imm8; ret` epilogues is accepted
// (no `pop` sequences): those are the sites whose unwind behaviour is fully
// determined and whose stack math the chain is built around.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>

namespace cet2
{
namespace detail
{

struct CallSite
{
    std::uint8_t* Address = nullptr;  // ntdll `call rax` instruction
    std::uint32_t K = 0;              // epilogue fixup (add rsp, K)
};

// ntdll image base read from the PEB (no API call).
std::uint8_t* GetNtdllBase();

// Number of usable call sites found in the current ntdll (cached).
std::size_t CallSiteCount();

// Returns the cached call sites (up to `max` entries).
std::size_t GetCallSites(CallSite* out, std::size_t max);

// Whether the ntdll gadget database was successfully initialized.
bool CallSitesReady();

} // namespace detail
} // namespace cet2
