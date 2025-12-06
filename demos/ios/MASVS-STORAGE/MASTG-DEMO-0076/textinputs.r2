e asm.bytes=false
e scr.color=false
e asm.var=false

?e Print xrefs to \'Run analysis\"
aaa

?e Print xrefs to \'autocorrectionType\"
f~+autocorrectionType,setSecureTextEntry

?e

?e Print xrefs to 0x100014118
axt @ 0x100014118

?e Print xrefs to 0x100014110
axt @ 0x100014110

?e

?e Print disassembly around \"autocorrectionType\" in the function
pdf @ 0x10000455c | grep -C 20 -i "autocorrectionType"

?e

?e Print disassembly around \"autocorrectionType\" in the function
pdf @ 0x1000045c8 | grep -C 20 -i "autocorrectionType"

?e

?e Print disassembly around \"setSecureTextEntry\" in the function
pdf @ 0x100004638 | grep -C 20 -i "setSecureTextEntry"