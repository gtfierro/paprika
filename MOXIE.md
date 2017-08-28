# Moxie

http://moxielogic.org/blog/pages/architecture.html

Notes on moxie architecture and instruction set

- bi-endian
- 16 32-bit general purpose registers

## Architecture

### Registers

`$fp`: frame pointer
`$sp`: stack pointer
`$r0` - `$r13`: general purpose

Special registers:
```
Reg        Description
0       status regsiter with the following bit values:
1       a pointer to the Exception Handler routine (invoked by swi, IRQs, Divide by Zero and illegal instructions (bad))
2       upon invocation of the Excecption Handler (see above), special register 2 will have one of four values..
3       the swi request number (by convention)
4       address of the supervisor mode stack on which exceptions are executed
5       return address upon entering the exception handler
6       reserved
7       reserved
8       reserved
9       an optional non-zero pointer to the Device Tree blob describing this device
```

### Instruction Set

```
and :   00100110AAAABBBB
add :   00000101AAAABBBB
ashl:   00101000AAAABBBB
ashr:   00101101AAAABBBB
beq:    110000vvvvvvvvvv
bge:    110110vvvvvvvvvv
bgeu:   111000vvvvvvvvvv
bgt:    110011vvvvvvvvvv
bgtu:   110101vvvvvvvvvv
ble:    110111vvvvvvvvvv
bleu:   111001vvvvvvvvvv
blt:    110010vvvvvvvvvv
bltu:   110100vvvvvvvvvv
bne:    110001vvvvvvvvvv
brk:    00110101xxxxxxxx
cmp:    00001110AAAABBBB
dec:    1001AAAAiiiiiiii
div:    00110001AAAABBBB
gsr:    1010AAAASSSSSSSS
inc:    1000AAAAiiiiiiii
jmp:    00100101AAAAxxxx
jmpa:   00011010xxxxxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
jsr:    00011001AAAAxxxx
jsra:   00000011xxxxxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
ld.b:   00011100AAAABBBB
ld.l:   00001010AAAABBBB
ld.s:   00100001AAAABBBB
lda.b:  00011101AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
lda.l:  00001000AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
lda.s:  00100010AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
ldi.l:  00000001AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
ldi.b:  00011011AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
ldi.s:  00100000AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
ldo.b:  00110110AAAABBBB iiiiiiiiiiiiiiii
ldo.l:  00001100AAAABBBB iiiiiiiiiiiiiiii
ldo.s:  00111000AAAABBBB iiiiiiiiiiiiiiii
lshr:   00100111AAAABBBB
mod:    00110011AAAABBBB
mov:    00000010AAAABBBB
mul:    00101111AAAABBBB
mul.x:  00010101AAAABBBB
neg:    00101010AAAABBBB
nop:    00001111xxxxxxxx
not:    00101100AAAABBBB
or:     00101011AAAABBBB
pop:    00000111AAAABBBB
push:   00000110AAAABBBB
ret:    00000100xxxxxxxx
sex.b:  00010000AAAABBBB
sex.s:  00010001AAAABBBB
ssr:    1011AAAASSSSSSSS
st.b:   00011110AAAABBBB
st.l:   00001011AAAABBBB
st.s:   00100011AAAABBBB
sta.b:  00011111AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
sta.l:  00001001AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
sta.s:  00100100AAAAxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
sto.b:  00110111AAAABBBB iiiiiiiiiiiiiiii
sto.l:  00001101AAAABBBB iiiiiiiiiiiiiiii
sto.s:  00111001AAAABBBB iiiiiiiiiiiiiiii
sub:    00101001AAAABBBB
swi:    00110000xxxxxxxx iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii
udiv:   00110010AAAABBBB
umod:   00110100AAAABBBB
umul.x: 00010100AAAABBBB
xor:    00101110AAAABBBB
zex.b:  00010010AAAABBBB
zex.s:  00010011AAAABBBB
