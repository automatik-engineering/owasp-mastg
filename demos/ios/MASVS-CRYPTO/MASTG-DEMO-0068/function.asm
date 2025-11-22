            ;-- section.0.__TEXT.__text:
            ; XREFS: 0x1000000d0  CALL 0x100004500  
┌ 176: sym.func.100004000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_40h);
│           0x100004000      sub sp, sp, 0x40                          ; [00] -r-x section size 10240 named 0.__TEXT.__text
│           0x100004004      stp x29, x30, [var_60h]
│           0x100004008      stp x20, x19, [var_70h]
│           0x10000400c      add x29, sp, 0x60
│           0x100004010      mov x20, x8
│           0x100004014      mov x19, x0                               ; arg1
│           ; Prepare arguments for CCCrypt
│           0x100004018      mov w0, 0                                 ; kCCEncrypt
│           0x10000401c      mov w1, 0                                 ; kCCAlgorithmAES
│           0x100004020      mov w2, 2                                 ; kCCOptionECBMode (ECB - INSECURE!)
│           0x100004024      mov x3, x19                               ; key pointer
│           0x100004028      mov w4, 0x10                              ; keyLength (16 bytes for AES-128)
│           0x10000402c      mov x5, 0                                 ; iv (NULL for ECB)
│           0x100004030      mov x6, x21                               ; dataIn
│           0x100004034      mov x7, x22                               ; dataInLength
│           ; Call CCCrypt
│           0x100004038      bl sym.imp.CCCrypt
│           ; Store result
│           0x10000403c      str w0, [x20]
│           ; Restore registers and return
│           0x100004040      ldp x20, x19, [sp, 0x70]
│           0x100004044      ldp x29, x30, [sp, 0x60]
│           0x100004048      add sp, sp, 0x40
└           0x10000404c      ret
