// ---------------------------------------------------------------------------
// CetBypass console demo: CET HIDDEN RUN + shadow-stack verification.
//
// Uses the existing bypass package (cet_trampoline.asm / cet_function.cpp /
// cet_syscall.cpp, namespace cethidden):
//   - each call runs on a fresh worker thread whose start routine is a MASM
//     trampoline entered through a REAL CALL from the thread-start chain;
//   - the trampoline then JMPs (never CALLs) into the target, so the real CET
//     shadow stack only ever contains the legitimate thread-start chain
//     (kernel32!BaseThreadInitThunk / ntdll!RtlUserThreadStart);
//   - the target's RET pops that legitimate frame from BOTH stacks, so
//     hardware validation always passes.
//
// Verification performed here:
//   1. CONTROL: normal + CET backtraces on the main thread (truthful).
//   2. cethidden::CallFunction runs a target in a hidden thread; the target
//      itself captures both backtraces, and the trampoline snapshots the
//      stacks at the JMP boundary.  We then check that no caller frames
//      (wmain / CallFunction / RunHidden) appear anywhere - the caller is
//      hidden from both the normal stack AND the CET shadow stack.
//   3. cethidden::Syscall runs an indirect syscall the same way.
// ---------------------------------------------------------------------------

#include "../bypass/cet_backtrace.h"
#include "../bypass/cet_function.h"
#include "../bypass/cet_syscall.h"
#include "../bypass2/cet2_backtrace.h"
#include "../bypass2/cet2_function.h"
#include "../bypass2/cet2_gadget.h"
#include "../bypass2/cet2_syscall.h"

#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace
{

constexpr const char* kCrashLog = "cet_crash.log";

LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep)
{
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const void* address = ep->ExceptionRecord->ExceptionAddress;

    std::printf("[cet] CRASH: code=0x%08X address=%p\n", code, address);
    FILE* log = nullptr;
    if (fopen_s(&log, kCrashLog, "a") == 0 && log)
    {
        std::fprintf(log, "code=0x%08X address=%p\n", code, address);
        std::fclose(log);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

std::string Hex64(std::uint64_t value)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llX", static_cast<unsigned long long>(value));
    return buf;
}

std::string DescribeFrame(std::uint64_t address)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)))
    {
        return "?";
    }
    if (mbi.State != MEM_COMMIT)
    {
        return "UNCOMMITTED " + Hex64(address);
    }
    switch (mbi.Type)
    {
    case MEM_IMAGE:
    {
        const std::string resolved = cetstack::ResolveAddress(address);
        return resolved.empty() ? ("IMAGE " + Hex64(address)) : resolved;
    }
    case MEM_MAPPED:
        return "MAPPED " + Hex64(address);
    case MEM_PRIVATE:
        return "UNBACKED " + Hex64(address);
    default:
        return "UNKNOWN " + Hex64(address);
    }
}

void PrintFrames(const char* label, const std::vector<std::uint64_t>& frames)
{
    std::printf("[cet] === %s (%zu frames) ===\n", label, frames.size());
    for (std::size_t i = 0; i < frames.size(); ++i)
    {
        std::printf("[cet] %02zu: %s\n", i, DescribeFrame(frames[i]).c_str());
    }
}

std::vector<std::uint64_t> CaptureNormal()
{
    std::vector<void*> buffer(64);
    const USHORT count =
        CaptureStackBackTrace(1, static_cast<DWORD>(buffer.size()),
                              buffer.data(), nullptr);
    std::vector<std::uint64_t> frames;
    frames.reserve(count);
    for (USHORT i = 0; i < count; ++i)
    {
        frames.push_back(reinterpret_cast<std::uint64_t>(buffer[i]));
    }
    return frames;
}

// Any frame whose symbol resolves into CetBypass.exe / wmain / the hidden-run
// plumbing would mean the caller leaked onto the stack.
bool ContainsCallerFrame(const std::vector<std::uint64_t>& frames)
{
    for (const auto frame : frames)
    {
        const std::string resolved = cetstack::ResolveAddress(frame);
        if (resolved.find("wmain") != std::string::npos ||
            resolved.find("CetShellcodeLoader") != std::string::npos ||
            resolved.find("RunHidden") != std::string::npos ||
            resolved.find("CallFunction") != std::string::npos ||
            resolved.find("Syscall") != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

bool IsShadowStackArmed();

void PrintCetStatus()
{
    std::printf("[cet] posture check\n");
    const DWORD64 xstate = GetEnabledXStateFeatures();
    std::printf("[cet] xstate  : mask=0x%llX CET_U_bit=%d\n",
                static_cast<unsigned long long>(xstate),
                (xstate & XSTATE_MASK_CET_U) ? 1 : 0);
    std::printf("[cet] xstate  : CET_U armed=%d\n", IsShadowStackArmed() ? 1 : 0);

    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 7, 0);
    const bool cpuShadowStack = ((cpuInfo[2] >> 7) & 1) != 0;  // ECX[7]
    const bool cpuIbt = ((cpuInfo[3] >> 20) & 1) != 0;         // EDX[20]
    std::printf("[cet] cpu     : CET_SS=%d CET_IBT=%d\n",
                cpuShadowStack ? 1 : 0, cpuIbt ? 1 : 0);
}

// True when the current thread actually runs with SHSTK_EN set.
bool IsShadowStackArmed()
{
    constexpr DWORD64 kCetMask = XSTATE_MASK_CET_U;
    if (!(GetEnabledXStateFeatures() & kCetMask))
    {
        return false;
    }
    DWORD length = 0;
    // The first call is a size query and returns FALSE by design.
    (void)InitializeContext2(nullptr, CONTEXT_XSTATE, nullptr, &length, kCetMask);
    if (length == 0)
    {
        return false;
    }
    std::vector<std::uint8_t> buffer(length);
    PCONTEXT context = nullptr;
    if (!InitializeContext2(buffer.data(), CONTEXT_XSTATE, &context, &length,
                            kCetMask))
    {
        return false;
    }
    if (!GetThreadContext(GetCurrentThread(), context))
    {
        return false;
    }
    DWORD64 mask = 0;
    if (!GetXStateFeaturesMask(context, &mask) || !(mask & kCetMask))
    {
        return false;
    }
    DWORD cetLength = 0;
    const auto* cet = static_cast<PXSAVE_CET_U_FORMAT>(
        LocateXStateFeature(context, XSTATE_CET_U, &cetLength));
    if (!cet || cetLength != sizeof(XSAVE_CET_U_FORMAT))
    {
        return false;
    }
    return (cet->Ia32CetUMsr & 1) != 0 && cet->Ia32Pl3SspMsr != 0;
}

// Target executed inside the hidden worker thread via cethidden::CallFunction.
// It captures its own views: the caller (wmain / plumbing) must be absent.
__declspec(noinline) std::int32_t HiddenTarget(std::uint64_t a,
                                               std::uint64_t b,
                                               std::uint64_t c)
{
    std::printf("[cet][hidden] target entered: args=%llu,%llu,%llu\n",
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b),
                static_cast<unsigned long long>(c));

    PrintFrames("INSIDE-HIDDEN normal stack", CaptureNormal());
    PrintFrames("INSIDE-HIDDEN CET shadow stack",
                cetstack::CaptureCETBacktrace(64));

    return static_cast<std::int32_t>(a * b + c);
}

// Target executed on the SAME thread through the bypass2 ntdll call-site
// chain. It captures both backtraces: the normal stack and the CET shadow
// stack must contain exactly the same return addresses (ntdll epilogue B,
// ntdll epilogue A, then the wrapper/caller).
__declspec(noinline) std::int64_t HiddenTarget2(std::uint64_t a,
                                                std::uint64_t b,
                                                std::uint64_t c,
                                                std::uint64_t d,
                                                std::uint64_t e)
{
    std::printf("[cet2][hidden] target entered on the calling thread: "
                "args=%llu,%llu,%llu,%llu,%llu\n",
                static_cast<unsigned long long>(a),
                static_cast<unsigned long long>(b),
                static_cast<unsigned long long>(c),
                static_cast<unsigned long long>(d),
                static_cast<unsigned long long>(e));

    const auto normal = cet2stack::CaptureNormalBacktrace(64);
    const auto cet = cet2stack::CaptureCETBacktrace(64);
    cet2stack::PrintBacktrace("INSIDE-BYPASS2 normal", normal);
    cet2stack::PrintBacktrace("INSIDE-BYPASS2 CET", cet);

    if (cet2stack::IsShadowStackArmed())
    {
        std::printf("[cet2] normal==CET backtrace: %s\n",
                    cet2stack::BacktracesMatch(normal, cet) ? "YES" : "NO");
    }
    else
    {
        std::printf("[cet2] CET not armed on this machine; shadow-stack "
                    "equivalence cannot be measured (normal frames above "
                    "already show the ntdll epilogue chain).\n");
    }

    return static_cast<std::int64_t>(a * b + c * d + e);
}

__declspec(noinline) std::int64_t HiddenTarget3(std::uint64_t a,
                                                std::uint64_t b,
                                                std::uint64_t c)
{
    std::printf("[cet2][hidden3] target entered on the calling thread "
                "(3-frame chain)\n");
    const auto normal = cet2stack::CaptureNormalBacktrace(64);
    const auto cet = cet2stack::CaptureCETBacktrace(64);
    cet2stack::PrintBacktrace("INSIDE-BYPASS2-3F normal", normal);
    cet2stack::PrintBacktrace("INSIDE-BYPASS2-3F CET", cet);
    if (cet2stack::IsShadowStackArmed())
    {
        std::printf("[cet2] 3-frame normal==CET backtrace: %s\n",
                    cet2stack::BacktracesMatch(normal, cet) ? "YES" : "NO");
    }
    return static_cast<std::int64_t>(a * b + c);
}

void PrintHiddenResult(const char* what, const cethidden::Result& result)
{
    std::printf("[cet] %s status=0x%08X ok=%d\n", what,
                static_cast<unsigned int>(result.Status), result.Ok ? 1 : 0);
    std::printf("[cet] %s boundary: SSP=%s RSP=%s ret=%s\n", what,
                Hex64(result.SspAtEntry).c_str(),
                Hex64(result.RspAtEntry).c_str(),
                Hex64(result.RetAddrAtEntry).c_str());

    PrintFrames((std::string(what) + " CET frames @JMP boundary").c_str(),
                result.CETFrames);
    PrintFrames((std::string(what) + " normal frames @JMP boundary").c_str(),
                result.NormalFrames);

    const bool callerLeaked =
        ContainsCallerFrame(result.CETFrames) ||
        ContainsCallerFrame(result.NormalFrames);
    std::printf("[cet] %s caller hidden from both stacks: %s\n", what,
                callerLeaked ? "NO (LEAKED)" : "YES");
}

} // namespace

int wmain()
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetUnhandledExceptionFilter(CrashHandler);
    PrintCetStatus();

    // ---- CONTROL: truthful views on the main thread ----------------------
    std::printf("[cet] --- CONTROL (main thread) ---\n");
    PrintFrames("CONTROL normal stack", CaptureNormal());
    PrintFrames("CONTROL CET shadow stack",
                cetstack::CaptureCETBacktrace(64));

    // ---- CET HIDDEN RUN 1: arbitrary function ----------------------------
    std::printf("[cet] --- cethidden::CallFunction(HiddenTarget, 6,7,8) ---\n");
    const auto hiddenFunction =
        cethidden::CallFunction(reinterpret_cast<const void*>(&HiddenTarget),
                                {6, 7, 8});
    PrintHiddenResult("hidden function", hiddenFunction);
    std::printf("[cet] hidden function result (thread exit code = EAX): %d "
                "(expected 6*7+8=%d)\n",
                static_cast<std::int32_t>(hiddenFunction.Status),
                static_cast<std::int32_t>(6 * 7 + 8));

    // ---- CET HIDDEN RUN 2: indirect syscall -------------------------------
    std::printf("[cet] --- cethidden::Syscall(NtYieldExecution) ---\n");
    const auto hiddenSyscall = cethidden::Syscall("NtYieldExecution", {});
    PrintHiddenResult("hidden syscall", hiddenSyscall);

    // ---- CET BYPASS 2: legal ntdll call-site chain on the SAME thread ----
    std::printf("[cet2] --- ntdll legal call sites ---\n");
    cet2::detail::CallSite sites[8] = {};
    const std::size_t siteCount = cet2::detail::GetCallSites(sites, 8);
    std::printf("[cet2] found %zu legal call site(s)\n", siteCount);
    for (std::size_t i = 0; i < siteCount; ++i)
    {
        std::printf("[cet2]   site[%zu] %-52s K=0x%X\n", i,
                    cet2stack::ResolveAddress(
                        reinterpret_cast<std::uint64_t>(sites[i].Address))
                        .c_str(),
                    sites[i].K);
    }
    std::printf("[cet2] CET_U armed=%d (empty CET backtrace expected on "
                "non-CET machines)\n",
                cet2stack::IsShadowStackArmed() ? 1 : 0);

    std::printf("[cet2] --- CallFunction(Compute5, 6,7,8,9,10) ---\n");
    const auto hiddenFn =
        cet2::CallFunction(reinterpret_cast<const void*>(&HiddenTarget2),
                           {6, 7, 8, 9, 10});
    std::printf("[cet2] ok=%d value=%llu status=0x%08X (expected "
                "6*7+8*9+10=%d)\n",
                hiddenFn.Ok ? 1 : 0,
                static_cast<unsigned long long>(hiddenFn.Value),
                static_cast<unsigned int>(hiddenFn.Status),
                static_cast<int>(6 * 7 + 8 * 9 + 10));
    if (hiddenFn.Ok)
    {
        std::printf("[cet2] chain sites: %s -> %s\n",
                    cet2stack::ResolveAddress(
                        reinterpret_cast<std::uint64_t>(hiddenFn.CallSite1))
                        .c_str(),
                    cet2stack::ResolveAddress(
                        reinterpret_cast<std::uint64_t>(hiddenFn.CallSite2))
                        .c_str());
    }

    std::printf("[cet2] --- CallFunction3(Compute3, 6,7,8) ---\n");
    const auto hiddenFn3 =
        cet2::CallFunction3(reinterpret_cast<const void*>(&HiddenTarget3),
                            {6, 7, 8});
    std::printf("[cet2] ok=%d value=%llu (expected 6*7+8=%d)\n",
                hiddenFn3.Ok ? 1 : 0,
                static_cast<unsigned long long>(hiddenFn3.Value),
                static_cast<int>(6 * 7 + 8));

    std::printf("[cet2] --- Syscall(NtYieldExecution) ---\n");
    const auto hiddenSc1 = cet2::Syscall("NtYieldExecution", {});
    std::printf("[cet2] ok=%d status=0x%08X\n", hiddenSc1.Ok ? 1 : 0,
                static_cast<unsigned int>(hiddenSc1.Status));

    std::printf("[cet2] --- Syscall(NtDelayExecution, 10ms) ---\n");
    LARGE_INTEGER delay{};
    delay.QuadPart = -100000LL;
    const auto hiddenSc2 =
        cet2::Syscall("NtDelayExecution", {0,
                                           reinterpret_cast<std::uint64_t>(&delay)});
    std::printf("[cet2] ok=%d status=0x%08X\n", hiddenSc2.Ok ? 1 : 0,
                static_cast<unsigned int>(hiddenSc2.Status));

    std::printf("[cet2] --- Syscall(NtQueryInformationProcess, 5 args) ---\n");
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG retLen = 0;
    const auto hiddenSc3 = cet2::Syscall(
        "NtQueryInformationProcess",
        {reinterpret_cast<std::uint64_t>(GetCurrentProcess()), 0,
         reinterpret_cast<std::uint64_t>(&pbi), sizeof(pbi),
         reinterpret_cast<std::uint64_t>(&retLen)});
    std::printf("[cet2] ok=%d status=0x%08X pbi.UniqueProcessId=0x%p retLen=%lu\n",
                hiddenSc3.Ok ? 1 : 0,
                static_cast<unsigned int>(hiddenSc3.Status),
                reinterpret_cast<void*>(pbi.UniqueProcessId),
                static_cast<unsigned long>(retLen));

    std::printf("[cet2] --- Syscall3(NtYieldExecution) ---\n");
    const auto hiddenSc4 = cet2::Syscall3("NtYieldExecution", {});
    std::printf("[cet2] ok=%d status=0x%08X\n", hiddenSc4.Ok ? 1 : 0,
                static_cast<unsigned int>(hiddenSc4.Status));

    // Keep the console visible when launched by double-click; skip the pause
    // when the window is hidden or stdin is redirected.
    const HWND consoleWindow = GetConsoleWindow();
    const HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    if (consoleWindow && IsWindowVisible(consoleWindow) &&
        GetFileType(stdinHandle) == FILE_TYPE_CHAR)
    {
        std::printf("[cet] press Enter to exit...");
        std::fflush(stdout);
        (void)std::getchar();
    }
    return 0;
}
