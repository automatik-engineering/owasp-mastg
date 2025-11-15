?e;?e

?e Searching for insecure random number generation functions:
afl~rand,srand,random,srandom

?e

?e xrefs to rand:
axt @ sym.imp.rand

?e

?e xrefs to srand:
axt @ sym.imp.srand

?e

?e Disassembly of generateInsecureRandomToken function:
?e (showing calls to rand)
afl~generateInsecureRandomToken
s sym.MastgTest.generateInsecureRandomToken
pdf

?e

?e Disassembly of generateSecureRandomToken function:
?e (showing calls to SecRandomCopyBytes)
afl~generateSecureRandomToken
s sym.MastgTest.generateSecureRandomToken
pdf
