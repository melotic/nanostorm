# Exports dissasembly from Ghidra

from ghidra.program.model.listing import CodeUnit

prog = getCurrentProgram()
base = prog.getAddressMap().getImageBase().getOffset()
analyzeChanges(prog)
listing = prog.getListing()

for instr in listing.getCodeUnitIterator(CodeUnit.INSTRUCTION_PROPERTY, True):
    printf("%s", str(instr.getAddress().getOffset() - base)) 