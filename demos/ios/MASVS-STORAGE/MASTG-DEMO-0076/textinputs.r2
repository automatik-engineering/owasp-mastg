e asm.bytes=false
e scr.color=false
e asm.var=false

?e Print xrefs to \'Run analysis\"
aaa

?e Print xrefs to \'autocorrectionType\"
f~+autocorrectionType

?e

?e Print xrefs to 0x100014118
axt @ 0x100014118

?e

?e Print disassembly around \"autocorrectionType\" in the function
pdf @ 0x10000455c | grep -C 20 -i "autocorrectionType"
