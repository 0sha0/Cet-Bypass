# bypass2 - CET 绕过第二种方式：ntdll 合法 call site + PE continuation（x64 / VS2022）

与 `bypass/`（独立线程 + JMP 进目标）不同，`bypass2` **不创建线程、不调用其它 API、
不修改任何内存来伪造返回地址**。它停留在调用线程上，用 ntdll 里真实的 `call`
指令构建整条调用链，因此普通栈和 CET 硬件影子栈由 CPU 自己保持完全同步。

## 原理（调用链）

运行时在 ntdll 的 `.text` 里扫描“合法 call site”：

```asm
call rax                  ; FF D0  真实 CALL，同时压普通栈 + 影子栈
nop                       ; 90
add rsp, 0x28             ; 48 83 C4 28
ret                       ; C3
```

这是 ntdll 内部一个完整函数的尾部形态（本机位于 `ntdll+0xA296D` 与
`ntdll+0xA29ED`）。只要跳进 `call rax` 这一条指令并把 RAX 设成我们的目标，
CPU 就会用一次**真实 CALL** 把 epilogue 地址同时压入普通栈和 CET 影子栈。

第二条链路完全按你给的骨架执行：

```text
调用方 --真实 CALL--> Cet2ChainEntry2          （R 入双栈）
   sub rsp, K1; jmp
ntdll 合法 call site A --真实 CALL--> PE continuation   （E1 入双栈）
PE continuation --jmp--> ntdll 合法 call site B
ntdll 合法 call site B --真实 CALL--> 目标 API / syscall stub（E2 入双栈）
目标 API --ret--> ntdll epilogue B（add rsp,K; ret）     （E2 出双栈）
ntdll epilogue B --ret--> ntdll epilogue A              （E1 出双栈）
ntdll epilogue A --ret--> 调用方                        （R 出双栈）
```

关键点：

- **PE continuation 只 JMP，绝不 RET**，所以它不会出现在任何一种回溯里；
- 每个 RET 从普通栈和影子栈弹出的是**同一个地址**，CET 校验永远通过；
- 普通栈回溯（`RtlCaptureStackBackTrace` 风格）和 CET 影子栈回溯（
  `rdsspq` 走读）逐帧一致：`目标 API -> ntdll epilogue B -> ntdll epilogue A
  -> 调用方 -> ...`；
- 全程没有 `incsspq`/`rdsspq` 修补、没有栈顶覆盖、没有 `VirtualProtect`、
  没有 `NtSetInformationThread`、没有写 ntdll。

## 文件

| 文件 | 作用 |
| --- | --- |
| `cet2_trampoline.asm` | 唯一的汇编：链入口、PE continuation、syscall stub |
| `cet2_gadget.h / .cpp` | 运行时扫描 ntdll 合法 call site（读 PEB，无 API） |
| `cet2_common.h` | Request/Result 结构 + 链执行器（header-only） |
| `cet2_syscall.h / .cpp` | 任意 `Nt*`/`Zw*` indirect syscall（≤12 参数） |
| `cet2_function.h / .cpp` | 任意普通函数堆栈欺骗（≤5 参数，见“限制”） |
| `cet2_backtrace.h / .cpp` | 普通回溯 vs CET 影子栈回溯验证工具 |

## 在别的工程里引用

1. 复制整个 `bypass2` 目录；
2. 把 `cet2_gadget.cpp`、`cet2_syscall.cpp`、`cet2_function.cpp`、
   `cet2_backtrace.cpp` 加入 `ClCompile`，把 `cet2_trampoline.asm` 加入
   `MASM`（和 bypass 相同）：

```xml
<ImportGroup Label="ExtensionSettings">
  <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.props" />
</ImportGroup>
<ItemGroup>
  <MASM Include="bypass2\cet2_trampoline.asm" />
</ItemGroup>
<ImportGroup Label="ExtensionTargets">
  <Import Project="$(VCTargetsPath)\BuildCustomizations\masm.targets" />
</ImportGroup>
```

3. 目标必须是 **x64**，链接器打开 `/CETCOMPAT`（建议同时 `/guard:cf`、
   `/guard:ehcont`）。

## 用法

```cpp
#include "bypass2/cet2_syscall.h"
#include "bypass2/cet2_function.h"

// 1) 任意 syscall（≤4 参数时直接调用真实 ntdll stub，栈上只有 ntdll 帧）
cet2::Result r1 = cet2::Syscall("NtYieldExecution", {});

LARGE_INTEGER delay{};
delay.QuadPart = -100000LL;                 // 10ms
cet2::Result r2 = cet2::Syscall("NtDelayExecution", {0, (uint64_t)&delay});

// 5 参数 syscall（自动换用自带 stub，参数 5..12 由 stub 自己的帧转发）
PROCESS_BASIC_INFORMATION pbi{};
ULONG retLen = 0;
cet2::Result r3 = cet2::Syscall(
    "NtQueryInformationProcess",
    {(uint64_t)GetCurrentProcess(), 0, (uint64_t)&pbi, sizeof(pbi),
     (uint64_t)&retLen});

// 2) 任意普通函数（结果走 Result::Value，64 位也保留）
int64_t Compute(uint64_t a, uint64_t b, uint64_t c);
cet2::Result r4 = cet2::CallFunction((const void*)&Compute, {6, 7, 8});

// 3) 想要更深的假栈：3 个 ntdll 帧版本
cet2::Result r5 = cet2::CallFunction3((const void*)&Compute, {1, 2, 3});
cet2::Result r6 = cet2::Syscall3("NtYieldExecution", {});
```

## 与 bypass 的差异

| | bypass（第一种） | bypass2（第二种） |
| --- | --- | --- |
| 线程 | 每次调用新建隐藏线程 | 不建线程，留在当前线程 |
| 进入目标 | JMP，影子栈只剩线程启动链 | 真实 CALL 链，影子栈 = ntdll 帧 |
| 普通栈/影子栈一致性 | 刻意不一致（JMP 无帧） | **完全一致**，逐帧相同 |
| 内存写 | 新线程栈上摆参数 | 只写当前栈的参数槽（call/ret 本身） |
| 结果 | 线程退出码（32 位） | RAX 原样返回（64 位） |

## 本机实测（CET 已武装）

测试环境：CPUID 显示 `CET_SS=1 CET_IBT=1`，进程 `CET_U armed=1`
（xstate mask=0x807）。本机系统未强制 Intel IBT，间接跳转进 ntdll 正常。

找到的合法 call site：

```text
site[0] ntdll.dll+0xA296D   K=0x28
site[1] ntdll.dll+0xA29ED   K=0x28
```

在目标函数内部同时抓普通栈与 CET 影子栈回溯（2 帧链）：

```text
INSIDE-BYPASS2 normal (8 frames)                  ; 每帧带符号 + 内存属性
  [00] CetBypass.exe!`anonymous namespace'::HiddenTarget2 + 0x81  COMMIT,IMAGE,RX
  [01] ntdll.dll!_chkstk + 0x19F                  COMMIT,IMAGE,RX   ; E2
  [02] ntdll.dll!_chkstk + 0x11F                  COMMIT,IMAGE,RX   ; E1
  [03] CetBypass.exe!cet2::detail::RunChain2 + 0x19B  COMMIT,IMAGE,RX
  ...
INSIDE-BYPASS2 CET (7 frames)
  [00] ntdll.dll!_chkstk + 0x19F                  COMMIT,IMAGE,RX   ; E2
  [01] ntdll.dll!_chkstk + 0x11F                  COMMIT,IMAGE,RX   ; E1
  [02] CetBypass.exe!cet2::detail::RunChain2 + 0x19B  COMMIT,IMAGE,RX
  ...
normal==CET backtrace: YES
```

每个帧都打印符号（DbgHelp 解析）和对应内存属性（`VirtualQuery`：
COMMIT/RESERVE/FREE + IMAGE/MAPPED/PRIVATE + PAGE_*，全部帧均为
`COMMIT,IMAGE,RX`，即 ntdll/自身 PE 的可执行映像页）。3 帧链同样验证：
`normal==CET backtrace: YES`（ntdll 三个 epilogue 帧逐帧相同）。

功能实测全部通过：

```text
CallFunction(Compute5, 6,7,8,9,10)              -> value=124  ✓
CallFunction3(Compute3, 6,7,8)                  -> value=50   ✓
Syscall("NtYieldExecution")                     -> ok=1       ✓
Syscall("NtDelayExecution", {0, &delay})        -> status=0   ✓
Syscall("NtQueryInformationProcess", 5 参数)     -> status=0, retLen=48 ✓
Syscall3("NtYieldExecution")                    -> ok=1       ✓
```

## 限制与说明

- **普通函数最多 5 个整数参数**（RCX/RDX/R8/R9 + 1 个栈参数）。原因是本机
  ntdll 只有 `K=0x28` 的合法 call site：第 6 个栈参数槽正好落在上一个
  ntdll epilogue 返回地址上。若强行写会覆盖它，普通栈与影子栈立刻不一致，
  所以代码直接拒绝而不是破坏链。syscall 不受此限（≤12 参数，stub 自带帧）。
- 若 ntdll 版本里找不到 `call rax; [nop] add rsp, imm8; ret` 且
  `K ≡ 8 (mod 16)、K ≥ 0x28` 的形态，`Result::Ok` 为 false，不会硬跑。
- 需要 CPU/系统开启 CET 时验证；没有 CET 的机器上普通栈回溯同样可测，
  `rdsspq` 会返回不可用值（代码有保护）。
- 与第一种方式相同的 IBT 注意事项：若系统强制 Intel IBT，间接 JMP 进入
  ntdll 函数中间（无 `endbr64`）会 #CP。PE continuation 入口和 syscall
  stub 已带 `endbr64`；ntdll 内部 call site 无法带。
