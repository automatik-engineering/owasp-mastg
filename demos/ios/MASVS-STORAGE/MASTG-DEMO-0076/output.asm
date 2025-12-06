Print xrefs to 'Run analysis"
Print xrefs to 'autocorrectionType"
0x10000b8d9 23 str.setAutocorrectionType:
0x10000b8f0 20 str.setSecureTextEntry:
0x100014110 8 reloc.fixup.setSecureTextEntry:
0x100014118 8 reloc.fixup.setAutocorrectionType:

Print xrefs to 0x100014118
sym.MASTestApp.MastgTest.mastg.completion.UITextField 0x10000455c [DATA:r--] ldr x1, reloc.fixup.setAutocorrectionType:
sym.MASTestApp.MastgTest.mastg.completion.UITextField...U0_ 0x1000045c8 [DATA:r--] ldr x1, reloc.fixup.setAutocorrectionType:
Print xrefs to 0x100014110
sym.MASTestApp.MastgTest.mastg.completion.UITextField._ 0x100004638 [DATA:r--] ldr x1, reloc.fixup.setSecureTextEntry:

Print disassembly around "autocorrectionType" in the function
│           0x10000450c      add x29, sp, 0x10
│           0x100004510      mov x19, x0                               ; arg1
│           0x100004514      mov x0, 0x6143                            ; 'Ca'
│           0x100004518      movk x0, 0x6863, lsl 16                   ; 'ch'
│           0x10000451c      movk x0, 0x6e69, lsl 32                   ; 'in'
│           0x100004520      movk x0, 0x2067, lsl 48                   ; 'g '
│           0x100004524      mov x1, 0x6e69                            ; 'in'
│           0x100004528      movk x1, 0x7570, lsl 16                   ; 'pu'
│           0x10000452c      movk x1, 0x74, lsl 32                     ; 't'
│           0x100004530      movk x1, 0xed00, lsl 48
│           0x100004534      bl sym.imp.Foundationbool_...ridgeToObjectiveCSo8NSStringCyF_ ; Foundationbool(...ridgeToObjectiveCSo8NSStringCyF)
│           0x100004538      mov x20, x0
│           0x10000453c      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x100004540      ldr x1, [x8, 0x108]                       ; [0x100014108:4]=0xb7eb ; reloc.fixup.setPlaceholder: ; char *selector
│           0x100004544      mov x0, x19                               ; void *instance
│           0x100004548      mov x2, x20
│           0x10000454c      bl sym.imp.objc_msgSend                   ; void *objc_msgSend(void *instance, char *selector)
│           0x100004550      mov x0, x20                               ; void *instance
│           0x100004554      bl sym.imp.objc_release                   ; void objc_release(void *instance)
│           0x100004558      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x10000455c      ldr x1, [x8, 0x118]                       ; [0x100014118:4]=0xb8d9 ; reloc.fixup.setAutocorrectionType:
│           0x100004560      mov x0, x19
│           0x100004564      mov x2, 0
│           0x100004568      ldp x29, x30, [var_10h]
│           0x10000456c      ldp x20, x19, [sp], 0x20
└       ┌─< 0x100004570      b sym.imp.objc_msgSend

Print disassembly around "autocorrectionType" in the function
│           0x100004578      stp x20, x19, [sp, -0x20]!                ; MASTestApp.MastgTest.mastg.completion.UITextField...U0_
│           0x10000457c      stp x29, x30, [var_10h]
│           0x100004580      add x29, sp, 0x10
│           0x100004584      mov x19, x0                               ; arg1
│           0x100004588      adrp x8, 0x10000b000
│           0x10000458c      add x8, x8, 0x550                         ; 0x10000b550 ; "Non-caching input"
│           0x100004590      sub x8, x8, 0x20
│           0x100004594      orr x1, x8, 0x8000000000000000
│           0x100004598      mov x0, 0x11
│           0x10000459c      movk x0, 0xd000, lsl 48
│           0x1000045a0      bl sym.imp.Foundationbool_...ridgeToObjectiveCSo8NSStringCyF_ ; Foundationbool(...ridgeToObjectiveCSo8NSStringCyF)
│           0x1000045a4      mov x20, x0
│           0x1000045a8      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x1000045ac      ldr x1, [x8, 0x108]                       ; [0x100014108:4]=0xb7eb ; reloc.fixup.setPlaceholder: ; char *selector
│           0x1000045b0      mov x0, x19                               ; void *instance
│           0x1000045b4      mov x2, x20
│           0x1000045b8      bl sym.imp.objc_msgSend                   ; void *objc_msgSend(void *instance, char *selector)
│           0x1000045bc      mov x0, x20                               ; void *instance
│           0x1000045c0      bl sym.imp.objc_release                   ; void objc_release(void *instance)
│           0x1000045c4      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x1000045c8      ldr x1, [x8, 0x118]                       ; [0x100014118:4]=0xb8d9 ; reloc.fixup.setAutocorrectionType:
│           0x1000045cc      mov x0, x19
│           0x1000045d0      mov w2, 1
│           0x1000045d4      ldp x29, x30, [var_10h]
│           0x1000045d8      ldp x20, x19, [sp], 0x20
└       ┌─< 0x1000045dc      b sym.imp.objc_msgSend

Print disassembly around "setSecureTextEntry" in the function
│           0x1000045e8      add x29, sp, 0x10
│           0x1000045ec      mov x19, x0                               ; arg1
│           0x1000045f0      mov x0, 0x6150                            ; 'Pa'
│           0x1000045f4      movk x0, 0x7373, lsl 16                   ; 'ss'
│           0x1000045f8      movk x0, 0x6f77, lsl 32                   ; 'wo'
│           0x1000045fc      movk x0, 0x6472, lsl 48                   ; 'rd'
│           0x100004600      mov x1, 0x6920                            ; ' i'
│           0x100004604      movk x1, 0x706e, lsl 16                   ; 'np'
│           0x100004608      movk x1, 0x7475, lsl 32                   ; 'ut'
│           0x10000460c      movk x1, 0xee00, lsl 48
│           0x100004610      bl sym.imp.Foundationbool_...ridgeToObjectiveCSo8NSStringCyF_ ; Foundationbool(...ridgeToObjectiveCSo8NSStringCyF)
│           0x100004614      mov x20, x0
│           0x100004618      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x10000461c      ldr x1, [x8, 0x108]                       ; [0x100014108:4]=0xb7eb ; reloc.fixup.setPlaceholder: ; char *selector
│           0x100004620      mov x0, x19                               ; void *instance
│           0x100004624      mov x2, x20
│           0x100004628      bl sym.imp.objc_msgSend                   ; void *objc_msgSend(void *instance, char *selector)
│           0x10000462c      mov x0, x20                               ; void *instance
│           0x100004630      bl sym.imp.objc_release                   ; void objc_release(void *instance)
│           0x100004634      adrp x8, sym.__METACLASS_DATA__TtC10MASTestAppP33_9471609302C95FC8EC1D59DD4CF2A2DB19ResourceBundleClass ; 0x100014000
│           0x100004638      ldr x1, [x8, 0x110]                       ; [0x100014110:4]=0xb8f0 ; reloc.fixup.setSecureTextEntry:
│           0x10000463c      mov x0, x19
│           0x100004640      mov w2, 1
│           0x100004644      ldp x29, x30, [var_10h]
│           0x100004648      ldp x20, x19, [sp], 0x20
└       ┌─< 0x10000464c      b sym.imp.objc_msgSend
