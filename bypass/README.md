# bypass - CET 影子栈绕过复用包（x64 / VS2022）

本目录是“不加载 shellcode”的 CET 影子栈绕过实现。`cet_trampoline.asm` 是
**唯一必须的汇编**：MSVC x64 没有 naked 函数也没有内联汇编，JMP 跳板无法用
C++ 表达；其余（SSN 解析、线程创建、参数搬运、结果回收、回溯对比）全部是 C++。

## 文件

| 文件 | 作用 |
| --- | --- |
| `cet_trampoline.asm` | 两个裸跳板：`CetHiddenSyscallStart` / `CetHiddenFunctionStart` |
| `cet_common.h` | 请求/结果结构 + 隐藏线程运行器（header-only） |
| `cet_syscall.h / .cpp` | 隐藏 indirect syscall（任意 `Nt*`/`Zw*`，最多 12 参） |
| `cet_function.h / .cpp` | 隐藏任意普通函数调用（x64 整数/指针参数，最多 12 参） |
| `cet_backtrace.h / .cpp` | 普通回溯 + CET 影子栈回溯 + 地址解析（验证用） |

## 在别的工程里引用

1. 拷贝整个 `bypass` 目录到你的工程；
2. 把 `cet_syscall.cpp`、`cet_function.cpp`、`cet_backtrace.cpp` 加入
   `ClCompile`，把 `cet_trampoline.asm` 加入 `MASM` 项：

```xml
<ImportGroup Label="ExtensionSettings">
  <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.props" />
</ImportGroup>
...
<ItemGroup>
  <MASM Include="bypass\cet_trampoline.asm" />
</ItemGroup>
...
<ImportGroup Label="ExtensionTargets">
  <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.targets" />
</ImportGroup>
```

3. 目标必须是 x64，且链接器打开 `/CETCOMPAT`；建议同时打开
   `/guard:cf`、`/guard:ehcont`（严格 HSP 配置会要求）；
4. `ntdll.lib` 由 `cet_common.h` 里的 `#pragma comment` 自动链接。

## 用法

```cpp
#include "bypass/cet_syscall.h"
#include "bypass/cet_function.h"

// 1) 隐藏 syscall（在 syscall 时刻，CET 影子栈只剩合法线程启动链）
cethidden::Result r1 = cethidden::Syscall("NtYieldExecution", {});

LARGE_INTEGER delay{};
delay.QuadPart = -100000LL; // 10ms
cethidden::Result r2 = cethidden::Syscall("NtDelayExecution",
                                          {0, (uint64_t)&delay});

// 2) 隐藏任意普通函数（JMP 进入，影子栈无调用者帧）
int32_t Compute(uint64_t a, uint64_t b, uint64_t c);
cethidden::Result r3 = cethidden::CallFunction((const void*)&Compute, {6, 7, 8});
// r3.Status 是线程退出码 = 函数的 EAX（32 位结果）
```

`cethidden::Result` 字段：

- `Status`：syscall 返回的 NTSTATUS / 函数 EAX（32 位）；
- `SspAtEntry` / `RspAtEntry` / `RetAddrAtEntry`：JMP 边界处的 SSP、RSP、
  `[RSP]`（正常应为 `kernel32!BaseThreadInitThunk+0x14`）；
- `CETFrames`：JMP 边界处真实影子栈快照（应为合法线程启动链，无调用者模块帧）；
- `NormalFrames`：普通栈快照（已过滤成可执行地址）。

## 原理

每次调用创建一条新线程，`StartRoutine` 是编译进 exe 的 MASM 跳板。线程启动链
`ntdll!RtlUserThreadStart -> kernel32!BaseThreadInitThunk -> call guard_dispatch_icall`
会以**真实 CALL** 进入跳板，因此影子栈顶部天然是合法的
`kernel32!BaseThreadInitThunk+0x14`。跳板装好参数、拍下两种栈快照后，用
**JMP**（不是 CALL）进入目标：

- syscall：JMP 到 ntdll 桩内部的 `syscall` 指令；
- 函数：JMP 到任意用户函数。

目标的 `RET` 会把 `kernel32+0x14` 从普通栈和影子栈同时弹出，硬件校验永远通过；
线程随后以 EAX 作为退出码结束。因为全程没有我们的 CALL，CET 影子栈回溯
（Elastic ShadowStackWalk 风格）看不到调用者模块的任何帧。

## 限制

- 一次调用 = 一条线程，开销大于普通函数调用；调用方需 `WaitForSingleObject`；
- 结果只有 32 位（线程退出码）；64 位结果请通过 out 参数指针带回；
- 参数只支持 x64 整数/指针（RCX/RDX/R8/R9 + 8 个栈参数），不支持浮点/结构体参数；
- 仅 x64；WOW64 不支持 HSP；
- 影子栈未武装的机器上 `rdsspq` 可能产生 #UD，调用前可用
  `cethidden::IsShadowStackArmed()` 判断；
- 若未来 Windows 启用 Intel IBT，跳板入口已有 `endbr64`，但直接 JMP 进 ntdll
  桩内部的 `syscall` 指令需要重新评估。

## CET HIDDEN RUN + 验证（src/main.cpp）

直接调用本包已有的 `cethidden::CallFunction` / `cethidden::Syscall`
（`cet_trampoline.asm` JMP 跳板 + 隐藏工作线程），并用 CET 影子栈回溯验证
调用者确实被隐藏：

1. `CONTROL`：主线程普通栈与 CET 影子栈都显示真实链（wmain / CRT /
   kernel32 / ntdll）；
2. `cethidden::CallFunction(HiddenTarget, 6,7,8)`：目标函数在隐藏线程内
   执行，入口经真实 CALL（线程启动链）进入跳板后 **JMP** 进目标；目标内部
   自己抓普通栈与 CET 回溯，跳板同时在 JMP 边界快照两套栈；
3. 验证结果：边界 CET 帧 = `kernel32!BaseThreadInitThunk+0x14` +
   `ntdll!RtlUserThreadStart+0x21`，普通帧同样只有合法启动链——
   **wmain/调用方零泄漏**，且目标 RET 弹回合法帧，CET 校验始终通过；
4. `cethidden::Syscall("NtYieldExecution")` 同样验证。

实测输出：

```text
=== hidden function CET frames @JMP boundary (2 frames) ===
00: KERNEL32.DLL!BaseThreadInitThunk + 0x14
01: ntdll.dll!RtlUserThreadStart + 0x21
hidden function caller hidden from both stacks: YES
hidden function result: 50 (6*7+8)
```
