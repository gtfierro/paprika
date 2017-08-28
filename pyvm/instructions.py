from collections import defaultdict
# INSTRUCTIONS

INSTRUCTIONS = {
    "and":      '00100110',
    "add":      '00000101',
    "ashl":     '00101000',
    "ashr":     '00101101',
    "beq":      '110000',
    "bge":      '110110',
    "bgeu":     '111000',
    "bgt":      '110011',
    "bgtu":     '110101',
    "ble":      '110111',
    "bleu":     '111001',
    "blt":      '110010',
    "bltu":     '110100',
    "bne":      '110001',
    "brk":      '00110101',
    "cmp":      '00001110',
    "dec":      '1001',
    "div":      '00110001',
    "gsr":      '1010',
    "inc":      '1000',
    "jmp":      '00100101',
    "jmpa":     '00011010',
    "jsr":      '00011001',
    "jsra":     '00000011',
    "ld.b":     '00011100',
    "ld.l":     '00001010',
    "ld.s":     '00100001',
    "lda.b":    '00011101',
    "lda.l":    '00001000',
    "lda.s":    '00100010',
    "ldi.l":    '00000001',
    "ldi.b":    '00011011',
    "ldi.s":    '00100000',
    "ldo.b":    '00110110',
    "ldo.l":    '00001100',
    "ldo.s":    '00111000',
    "lshr":     '00100111',
    "mod":      '00110011',
    "mov":      '00000010',
    "mul":      '00101111',
    "mul.x":    '00010101',
    "neg":      '00101010',
    "nop":      '00001111',
    "not":      '00101100',
    "or":       '00101011',
    "pop":      '00000111',
    "push":     '00000110',
    "ret":      '00000100',
    "sex.b":    '00010000',
    "sex.s":    '00010001',
    "ssr":      '1011',
    "st.b":     '00011110',
    "st.l":     '00001011',
    "st.s":     '00100011',
    "sta.b":    '00011111',
    "sta.l":    '00001001',
    "sta.s":    '00100100',
    "sto.b":    '00110111',
    "sto.l":    '00001101',
    "sto.s":    '00111001',
    "sub":      '00101001',
    "swi":      '00110000',
    "udiv":     '00110010',
    "umod":     '00110100',
    "umul.x":   '00010100',
    "xor":      '00101110',
    "zex.b":    '00010010',
    "zex.s":    '00010011',
}

OPCODES = dict(zip(INSTRUCTIONS.values(), INSTRUCTIONS.keys()))

def tree(): return defaultdict(tree)
class Decoder:
    """
    Assume 4-8 bit instructions
    """
    def __init__(self, instructions):
        self.root = tree()
        for inst, opcode in instructions.items():
            current = self.root
            for char in opcode:
                current = current[char]
            current["END"] = inst

    def get_instruction(self, opcode):
        current = self.root
        for char in opcode:
            if isinstance(current["END"], str):
                return current["END"]
            else:
                current = current[char]
        if isinstance(current["END"], str):
            return current["END"]
        else:
            return None
