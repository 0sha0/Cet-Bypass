#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "cet2_gadget.h"

#include "cet2_common.h"

#include <winternl.h>
#include <intrin.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <vector>

namespace cet2
{
namespace detail
{
namespace
{

std::uint8_t* GetNtdllBaseImpl()
{
    // PEB -> Ldr -> InMemoryOrderModuleList, no API call involved.
    const auto* peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
    if (!peb || !peb->Ldr)
    {
        return nullptr;
    }
    struct ModuleEntry
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
    const auto* head = &peb->Ldr->InMemoryOrderModuleList;
    for (auto* link = head->Flink; link != head; link = link->Flink)
    {
        const auto* module = CONTAINING_RECORD(link, ModuleEntry, InMemoryOrderLinks);
        const auto& name = module->BaseDllName;
        if (name.Length == 9 * sizeof(wchar_t) && name.Buffer &&
            _wcsnicmp(name.Buffer, L"ntdll.dll", 9) == 0)
        {
            return static_cast<std::uint8_t*>(module->DllBase);
        }
    }
    return nullptr;
}

} // namespace

std::uint8_t* GetNtdllBase()
{
    return GetNtdllBaseImpl();
}

namespace
{

bool MatchEpilogue(const std::uint8_t* p, std::size_t remaining,
                   std::uint32_t& k)
{
    // Shapes accepted (call rax must be at p-2):
    //   [90] 48 83 C4 K C3              add rsp, imm8; ret
    //   [90] 48 81 C4 K0 K1 K2 K3 C3    add rsp, imm32; ret
    //   [90] C3                          ret
    std::size_t i = 0;
    if (remaining > i && p[i] == 0x90)
    {
        ++i;
    }
    if (remaining <= i)
    {
        return false;
    }
    if (p[i] == 0xC3)
    {
        k = 0;
        return true;
    }
    if (remaining >= i + 4 && p[i] == 0x48 && p[i + 1] == 0x83 &&
        p[i + 2] == 0xC4)
    {
        k = p[i + 3];
        return remaining >= i + 5 && p[i + 4] == 0xC3;
    }
    if (remaining >= i + 7 && p[i] == 0x48 && p[i + 1] == 0x81 &&
        p[i + 2] == 0xC4)
    {
        k = static_cast<std::uint32_t>(p[i + 3]) |
            (static_cast<std::uint32_t>(p[i + 4]) << 8) |
            (static_cast<std::uint32_t>(p[i + 5]) << 16) |
            (static_cast<std::uint32_t>(p[i + 6]) << 24);
        return remaining >= i + 8 && p[i + 7] == 0xC3;
    }
    return false;
}

std::vector<CallSite>& SiteTable()
{
    static std::vector<CallSite> sites;
    return sites;
}

bool EnsureSites()
{
    static bool initialized = false;
    static bool ok = false;
    if (initialized)
    {
        return ok;
    }
    initialized = true;

    auto* ntdll = GetNtdllBaseImpl();
    if (!ntdll)
    {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
        ntdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }
    const auto* section = IMAGE_FIRST_SECTION(nt);
    const std::uint8_t* text = nullptr;
    std::size_t textSize = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (std::memcmp(section[i].Name, ".text", 5) == 0)
        {
            text = ntdll + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text || textSize < 8)
    {
        return false;
    }

    auto& sites = SiteTable();
    for (std::size_t i = 0; i + 2 < textSize; ++i)
    {
        // `call rax` (FF D0) followed by a pure epilogue.
        if (text[i] != 0xFF || text[i + 1] != 0xD0)
        {
            continue;
        }
        std::uint32_t k = 0;
        if (!MatchEpilogue(text + i + 2, textSize - i - 2, k))
        {
            continue;
        }
        // The chain requires K ≡ 8 (mod 16) so every CALL stays 16-byte
        // aligned, and K >= 0x28 for the final site so the 5th argument
        // slot ([RSP+0x20]) never collides with the previous epilogue's
        // return address ([RSP+K]).
        if ((k & 0xF) != 0x8 || k < 0x28)
        {
            continue;
        }
        sites.push_back({const_cast<std::uint8_t*>(text + i), k});
    }

    std::stable_sort(sites.begin(), sites.end(),
        [](const CallSite& a, const CallSite& b)
        {
            if (a.K != b.K)
            {
                return a.K < b.K;
            }
            return a.Address < b.Address;
        });

    ok = !sites.empty();
    return ok;
}

} // namespace

std::size_t CallSiteCount()
{
    return EnsureSites() ? SiteTable().size() : 0;
}

bool CallSitesReady()
{
    return EnsureSites();
}

std::size_t GetCallSites(CallSite* out, std::size_t max)
{
    if (!out || max == 0 || !EnsureSites())
    {
        return 0;
    }
    const auto& sites = SiteTable();
    const std::size_t count = std::min(max, sites.size());
    for (std::size_t i = 0; i < count; ++i)
    {
        out[i] = sites[i];
    }
    return count;
}

bool PrepareChain(Request& request, int frames, void* target,
                  std::uint32_t ssn, const std::uint64_t* args,
                  std::size_t count)
{
    if (!target || (frames != 2 && frames != 3) || count > 12)
    {
        return false;
    }
    if (!EnsureSites())
    {
        return false;
    }
    const auto& sites = SiteTable();
    if (sites.empty())
    {
        return false;
    }

    const auto siteAt = [&sites](std::size_t index) -> const CallSite&
    {
        return sites[index % sites.size()];
    };
    request.CallSite1 = siteAt(0).Address;
    request.K1 = siteAt(0).K;
    request.CallSite2 = siteAt(1).Address;
    request.K2 = siteAt(1).K;
    request.CallSite3 = frames == 3 ? siteAt(2).Address : nullptr;
    request.K3 = frames == 3 ? siteAt(2).K : 0;
    request.Target = target;
    request.Ssn = ssn;
    for (std::size_t i = 0; i < count; ++i)
    {
        request.A[i] = args[i];
    }
    return true;
}

} // namespace detail
} // namespace cet2
