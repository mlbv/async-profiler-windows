; Copyright 2026 movblock
; SPDX-License-Identifier: Apache-2.0
OPTION CASEMAP:NONE
.code
; Non-leaf PE row with a certified nonfaulting displaced stack allocation.
SoftwareEntryWork PROC FRAME
    sub rsp, 40
    .allocstack 40
    .endprolog
    lea rax, [rcx+rdx]
    add rsp, 40
    ret
SoftwareEntryWork ENDP
; Prolog PUSH; a displaced stack fault is reported at the source.
SoftwareEntryPush PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    lea rax, [rcx+rdx]
    pop rbx
    ret
SoftwareEntryPush ENDP
; Entry metadata with the ordinary Windows language-handler bit must reject.
END
