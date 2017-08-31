import sys
import bitstring
from instructions import *

FP = 0
SP = 1

class VM:
    debug=True
    def __init__(self, contents):
        self.contents = contents
        # 0 is fp
        self.REG = {0: 1024, 1: 4096, 2: 0, 3: 0, 4: 0,
             5: 0,  6: 0, 7: 0, 8: 0, 9: 0, 10: 0,
             11: 0, 12: 0, 13: 0, 'fp': 0, 'sp': 0,
             'cmp': 0, 'cmpu': 0
        }
        self.MEM = bitstring.BitStream(length=8192*8)
        self.PC = 0

    def dump(self):
        print '[sp] = {0}       [fp] = {1}      [pc] = {2}      [cmp] = {3}'.format(self.REG[0],self.REG[1], self.PC, self.REG['cmp'])
        print '[r0] = {0}       [r1] = {1}      [r2] = {2}      [r3] = {3}'.format(self.REG[2],self.REG[3], self.REG[4], self.REG[5])
        print '[r4] = {0}       [r5] = {1}      [r6] = {2}      [r7] = {3}'.format(self.REG[6],self.REG[7], self.REG[8], self.REG[9])
        print '[r8] = {0}       [r9] = {1}      [r10] = {2}      [r11] = {3}'.format(self.REG[10],self.REG[11], self.REG[12], self.REG[13])
    def debug(self, inst, opcode, A=None, B=None, value=None, addr=None):
        if self.debug:
            print 'PC={0} inst={1} opcode={2}'.format(self.PC, inst, opcode)
            if A == SP:
                print ' $SP={0}'.format(self.REG[A]),
            elif A == FP:
                print ' $FP={0}'.format(self.REG[A]),
            elif A is not None:
                print ' RegA({0})={1} '.format(A, self.REG[A]),

            if B == SP:
                print ' $SP={0}'.format(self.REG[B]),
            elif B == FP:
                print ' $FP={0}'.format(self.REG[B]),
            elif B is not None:
                print ' RegB({0})={1} '.format(B, self.REG[B]),

            if value is not None:
                print ' value={0} '.format(bin(value)),
            if addr is not None:
                print ' addr={0} '.format(addr),
            print ' at {0}'.format(self.contents.bytepos)

    def write_memory(self, value, address, length=32):
        b = bitstring.Bits(int=value, length=length)
        self.MEM.overwrite(b, address*8)

    def read_memory(self, address, length=32):
        self.MEM.bytepos = address
        value = self.MEM.read(length)
        return value

    def parse_file(self, contents):
        """
        Get a bytearray from the file

        Want to read 2 bytes to get the opcode, then decide how much to read next
        """
        decoder  = Decoder(INSTRUCTIONS)
        while self.PC < len(self.contents)/8:
            self.contents.bytepos = self.PC
            opcode  = self.contents.read('bin:8')
            inst = decoder.get_instruction(opcode)
            if inst is None:
                print "UH OH", opcode, inst
                return
            self.decode(inst, opcode)
        self.dump()

    def decode(self, inst, opcode, debug=True):
        print inst
        if inst == 'and':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.debug(inst, opcode, regA, regB)
            self.REG[regA] = (self.REG[regA] & self.REG[regB])
            self.PC += 2
        elif inst == 'add':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.debug(inst, opcode, regA, regB)
            self.REG[regA] = (self.REG[regA] + self.REG[regB])
            self.PC += 2
        elif inst == 'ashl':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.debug(inst, opcode, regA, regB)
            self.REG[regA] = (self.REG[regA] << self.REG[regB])
            self.PC += 2
        elif inst == 'ashr':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.debug(inst, opcode, regA, regB)
            self.REG[regA] = (self.REG[regA] >> self.REG[regB])
            self.PC += 2
        elif inst == 'beq':
            self.PC += 2
            if self.REG['cmp'] == 0:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bge':
            self.PC += 2
            if self.REG['cmp'] >= 0:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bgeu':
            self.PC += 2
            if self.REG['cmpu'] >= 0:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bgt':
            self.PC += 2
            if self.REG['cmp'] == 1:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bgtu':
            self.PC += 2
            if self.REG['cmpu'] == 1:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'ble':
            self.PC += 2
            if self.REG['cmp'] <= 0:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bleu':
            self.PC += 2
            if self.REG['cmpu'] <= 0:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'blt':
            self.PC += 2
            if self.REG['cmp'] < -1:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bltu':
            self.PC += 2
            if self.REG['cmpu'] < -1:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
            pass
        elif inst == 'bne':
            print 'bne'
            self.PC += 2
            if self.REG['cmp'] != 0:
                self.contents.bitpos -= 2
                value = self.contents.read(10).int
                self.PC += (value << 1)
            else: value=None
            self.debug(inst, opcode, value=value)
        elif inst == 'brk':
            sys.exit(1)
            return
        elif inst == 'cmp':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            A = bitstring.Bits(int=self.REG[regA],length=32)
            B = bitstring.Bits(int=self.REG[regB],length=32)
            self.REG['cmp'] = cmp(A.int, B.int)
            self.REG['cmpu'] = cmp(A.uint, B.uint)
            self.debug( inst, opcode, regA, regB)
            self.PC += 2
        elif inst == 'dec':
            regA = int(opcode,2) & 0xf
            value = self.contents.read('int:8')
            self.REG[regA] -= value
            self.debug( inst, opcode, regA, value=value)
            self.PC += 2
        elif inst == 'div':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] = int(self.REG[regA] / self.REG[regB])
            self.debug( inst, opcode, regA, regB)
            self.PC += 2
        elif inst == 'gsr':
            return None
        elif inst == 'inc':
            regA = int(opcode,2) & 0xf
            value = self.contents.read('int:8')
            self.REG[regA] += value
            self.debug(inst, opcode, regA, value=value)
            self.PC += 2
        elif inst == 'jmp':
            regA = self.contents.read('int:4')
            _ = self.contents.read('int:4') # discard
            address = self.REG[regA]
            self.debug(inst, opcode, regA, value=value)
            self.PC += 2
        elif inst == 'jmpa':
            _ = self.contents.read('int:8') # discard
            address = self.contents.read('int:32')
            self.PC = address
            self.debug(inst, opcode, addr=address)
        elif inst == 'jsra':
            self.contents.read(8) # discard
            addr = self.contents.read(32).int
            # push return addr onto stack (next instruction)
            self.push_stack(self.PC+6)
            # push fp on the stack
            self.push_stack(self.REG[FP])
            # set pc to target address
            self.PC = addr
            self.debug(inst, opcode, addr=addr)
            return
        elif inst == 'ld.b':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            addr = self.REG[regB]
            value = self.read_memory(addr, 8)
            self.REG[regA] = value.int
            self.debug(inst, opcode, regA, regB, value=value, addr=addr)
            self.PC += 2
        elif inst == 'ld.l':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            addr = self.REG[regB]
            value = self.read_memory(addr, 32).int
            self.REG[regA] = value
            self.debug(inst, opcode, regA, regB, value=value, addr=addr)
            self.PC += 2
        elif inst == 'ld.s':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            addr = self.REG[regB]
            value = self.read_memory(addr, 16)
            self.REG[regA] = value.int
            self.debug(inst, opcode, regA, regB, value=value, addr=addr)
            self.PC += 2
        elif inst == 'lda.b':
            regA = self.contents.read('int:4')
            _ = self.contents.read('int:4') # discard
            address = self.contents.read('int:32')
            value = elf.read_memory(address, 8)
            self.debug(inst, opcode, regA, value=value, addr=address)
            self.PC += 6
        elif inst == 'lda.l':
            regA = self.contents.read('int:4')
            _ = self.contents.read('int:4') # discard
            address = self.contents.read('int:32')
            value = elf.read_memory(address, 32)
            self.debug(inst, opcode, regA, value=value, addr=address)
            self.PC += 6
        elif inst == 'lda.s':
            regA = self.contents.read('int:4')
            _ = self.contents.read('int:4') # discard
            address = self.contents.read('int:32')
            value = elf.read_memory(address, 16)
            self.debug(inst, opcode, regA, value=value, addr=address)
            self.PC += 6
        elif inst == 'ldi.b':
            regA = self.contents.read('int:4')
            _ = self.contents.read('int:4') # discard
            value = self.contents.read('int:32') >> 24
            self.REG[regA] = value
            self.debug(inst, opcode, regA, value=value)
            self.PC += 6
        elif inst == 'ldi.l':
            regA = self.contents.read('int:4')
            self.contents.read('int:4') # discard
            value = self.contents.read('int:32')
            self.REG[regA] = value
            self.debug(inst, opcode, regA, value=value)
            self.PC += 6
        elif inst == 'ldi.s':
            regA = self.contents.read('int:4')
            _ = self.contents.read('int:4') # discard
            value = self.contents.read('int:32') >> 16
            self.REG[regA] = value
            self.debug(inst, opcode, regA, value=value)
            self.PC += 6
        elif inst == 'ldo.b':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            address = self.REG[regB] + self.contents.read('int:16')
            value = self.read_memory(address, 32) >> 24
            self.REG[regA] = value.int
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 4
        elif inst == 'ldo.l':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            address = self.REG[regB] + self.contents.read('int:16')
            print address
            self.debug(inst, opcode, regA, regB, addr=address)
            value = self.read_memory(address, 32).int
            self.REG[regA] = value
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 4
        elif inst == 'ldo.b':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            address = self.REG[regB] + self.contents.read('int:16')
            value = self.read_memory(address, 32) >> 16
            self.REG[regA] = value.int
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 4
        elif inst == 'lshr':
            print 'LOGICAL SHIFT'
            #TODO
            self.PC += 2
        elif inst == 'mod':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regA] % self.REG[regB]
            self.REG[regA] = value
            self.debug(inst, opcode, regA, regB, value=value)
            self.PC += 2
        elif inst == 'mov':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] = self.REG[regB]
            self.debug(inst,opcode,regA,regB)
            self.PC += 2
        elif inst == 'mul':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regA] * self.REG[regB]
            value &= 0xffffffff
            self.REG[regA] = value
            self.debug(inst, opcode, regA, regB, value=value)
            self.PC += 2
        elif inst == 'mul.x':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regA] * self.REG[regB]
            value >>= 32
            self.REG[regA] = value
            self.debug(inst, opcode, regA, regB, value=value)
            self.PC += 2
        elif inst == 'neg':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] = -self.REG[regB]
            self.debug(inst, opcode, regA, regB)
            self.PC += 2
        elif inst == 'nop':
            self.PC += 2
        elif inst == 'not':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] = ~self.REG[regB]
            self.debug(inst, opcode, regA, regB)
            self.PC += 2
        elif inst == 'or':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] |= self.REG[regB]
            self.debug(inst, opcode, regA, regB)
            self.PC += 2
        elif inst == 'pop':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            address = self.REG[regB]
            value = self.read_memory(address, 32)
            self.REG[regA] = value
            self.REG[regB] -= 32
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 2
        elif inst == 'push':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            self.write_memory(value, address, 32)
            self.REG[regB] += 32
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 2
        elif inst == 'ret':
            # pop old frame pointer into $fp
            self.REG[FP] = self.pop_stack().int
            # pop return addr into pc
            self.PC = self.pop_stack().int
            self.debug(inst, opcode, FP, SP)
            print 'ret', self.REG[1], self.PC
        elif inst == 'sex.b' or inst == 'sex.s':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            self.REG[regA] = sign_extend(value, 32)
            self.PC += 2
        elif inst == 'ssr':
            print 'ssr'
            sys.exit(1)
        elif inst == 'st.b':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            self.write_memory(value, address, 8)
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 2
        elif inst == 'st.l':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            self.write_memory(value, address, 32)
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 2
        elif inst == 'st.s':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            self.write_memory(value, address, 16)
            self.debug(inst, opcode, regA, regB, value=value, addr=address)
            self.PC += 2
        elif inst == 'sta.b':
            regA = self.contents.read(4).int
            value = self.REG[regA]
            self.contents.read(4) # skip
            address = self.contents.read(32).int
            self.write_memory(value, address, 8)
            self.PC += 6
        elif inst == 'sta.l':
            regA = self.contents.read(4).int
            value = self.REG[regA]
            self.contents.read(4) # skip
            address = self.contents.read(32).int
            self.write_memory(value, address, 32)
            self.PC += 6
        elif inst == 'sta.s':
            regA = self.contents.read(4).int
            value = self.REG[regA]
            self.contents.read(4) # skip
            address = self.contents.read(32).int
            self.write_memory(value, address, 16)
            self.PC += 6
        elif inst == 'sto.b':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            address += self.contents.read(16).int
            self.write_memory(value, address, 16)
            self.debug(inst,opcode,regA,regB,value,address)
            self.PC += 4
        elif inst == 'sto.l':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            address += self.contents.read(16).int
            self.write_memory(value, address, 32)
            self.debug(inst,opcode,regA,regB,value,address)
            self.PC += 4
        elif inst == 'sto.s':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            value = self.REG[regB]
            address = self.REG[regA]
            address += self.contents.read(16).int
            self.write_memory(value, address, 8)
            self.debug(inst,opcode,regA,regB,value,address)
            self.PC += 4
        elif inst == 'sub':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] -= self.REG[regB]
            self.PC += 2
        elif inst == 'swi':
            print 'swi'
            self.PC += 6
        elif inst == 'udiv':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            A = bitstring.Bits(int=self.REG[regA], length=32)
            B = bitstring.Bits(int=self.REG[regB], length=32)
            value = int(A.uint / B.uint)
            self.REG[regA] = value
            self.debug(inst,opcode,regA,regB,value)
            self.PC += 2
        elif inst == 'umod':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            A = bitstring.Bits(int=self.REG[regA], length=32)
            B = bitstring.Bits(int=self.REG[regB], length=32)
            value = A.uint % B.uint
            self.REG[regA] = value
            self.debug(inst,opcode,regA,regB,value)
            self.PC += 2
        elif inst == 'umul.x':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            A = bitstring.Bits(int=self.REG[regA], length=32)
            B = bitstring.Bits(int=self.REG[regB], length=32)
            value = A.uint * B.uint
            value >>= 32
            self.REG[regA] = value
            self.debug(inst,opcode,regA,regB,value)
            self.PC += 2
        elif inst == 'xor':
            ex = self.contents.read('int:8')
            regA = ex >> 4
            regB = ex & 0xf
            self.REG[regA] = self.REG[regA] ^ self.REG[regB]
            self.debug(inst,opcode,regA,regB)
            self.PC += 2
        elif inst == 'zex.b':
            self.PC += 2
            pass
        elif inst == 'zex.s':
            self.PC += 2
            pass
        else:
            print inst, opcode

    def push_stack(self, value):
        sp = self.REG[SP]
        #print 'PUSH', value, 'at', sp
        self.write_memory(value, sp, 32)
        self.REG[SP] = sp-32

    def pop_stack(self):
        self.REG[SP] += 32
        sp = self.REG[SP]

        #print 'POP from', sp,
        value = self.read_memory(sp, 32)
        #print value
        return value


def cmp(A, B):
    if A == B:
        return 0
    elif A < B:
        return -1
    else:
        return 1

# https://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (signbit -1)) - (value & sign_bit)

if __name__ == '__main__':
    filename = sys.argv[1]

    s = bitstring.ConstBitStream(filename=filename)
    vm = VM(s)
    vm.parse_file(s)
    #instructions = parse_file(s)

