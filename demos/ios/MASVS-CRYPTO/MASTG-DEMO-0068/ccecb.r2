e asm.bytes=false
e scr.color=false
e asm.var=false

?e Uses of the CCCrypt function:
afl~CCCrypt

?e

?e xrefs to CCCrypt:
axt @ 0x1000076c4

?e

?e Use of CCCrypt with ECB mode:

# Seek to the function where CCCrypt is called with ECB mode
pd-- 9 @ 0x100004000

pdf @ sym.func.100004000 > function.asm
