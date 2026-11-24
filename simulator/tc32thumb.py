"""Translate Telink TC32 machine code to ARMv4T Thumb so standard tools (capstone/Ghidra) can decode it.

TC32 is Thumb-1 with the opcode high byte remapped; the low byte and operand layout are unchanged.
Only halfwords discovered as code are translated; literal pools and data stay untouched.
"""
import struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

NOP = 0x46c0


def map_hi(h):
    """TC32 high byte -> Thumb high byte, or None for TC32-only/undefined."""
    if h <= 0x07: return 0x40 + h          # ALU / hi-reg / bx
    if h <= 0x0f: return 0x48 + (h - 0x08)  # ldr pc-rel
    if h <= 0x1f: return 0x50 + (h - 0x10)  # ldr/str reg offset
    if h <= 0x2f: return 0x80 + (h - 0x20)  # strh/ldrh imm
    if h <= 0x3f: return 0x90 + (h - 0x30)  # str/ldr sp
    if h <= 0x47: return 0x70 + (h - 0x40)  # strb imm
    if h <= 0x4f: return 0x78 + (h - 0x48)  # ldrb imm
    if h <= 0x5f: return 0x60 + (h - 0x50)  # str/ldr imm
    if h == 0x60: return 0xb0               # add/sub sp
    if h in (0x64, 0x65): return 0xb4 + (h - 0x64)  # push
    if h in (0x6c, 0x6d): return 0xbc + (h - 0x6c)  # pop
    if h in (0x68, 0x69): return 0xbc + (h - 0x68)  # treti -> pop (irq return)
    if 0x70 <= h <= 0x7f: return 0xa0 + (h - 0x70)  # add rd, pc/sp
    if 0x80 <= h <= 0x87: return 0xe0 + (h - 0x80)  # b
    if 0x90 <= h <= 0x9f: return 0xf0 + (h - 0x90)  # bl prefix/suffix
    if 0xa0 <= h <= 0xbf: return 0x20 + (h - 0xa0)  # mov/cmp/add/sub imm8
    if 0xc0 <= h <= 0xcf: return 0xd0 + (h - 0xc0)  # bcc / swi
    if 0xd0 <= h <= 0xdf: return 0xc0 + (h - 0xd0)  # stm/ldm
    if 0xe0 <= h <= 0xe7: return 0x10 + (h - 0xe0)  # asr imm
    if 0xe8 <= h <= 0xef: return 0x18 + (h - 0xe8)  # add/sub reg/imm3
    if 0xf0 <= h <= 0xf7: return 0x00 + (h - 0xf0)  # lsl imm
    if 0xf8 <= h <= 0xff: return 0x08 + (h - 0xf8)  # lsr imm
    return None


def xlate(hw):
    if hw == NOP:  # tnop shares the Thumb nop encoding
        return NOP
    t = map_hi(hw >> 8)
    return NOP if t is None else (t << 8) | (hw & 0xff)


class Translator:
    def __init__(self, data, code_end, code_start=0x20, extra_entries=()):
        self.d = data
        self.code_start, self.code_end = code_start, code_end
        self.code = set()       # halfword addresses that are code
        self.lit = set()        # word addresses used as literals
        self.entries = set()
        self.jt_targets = set()
        self.cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        self.cs.detail = True
        self.extra = set(extra_entries)

    def hw(self, a):
        return struct.unpack_from('<H', self.d, a)[0]

    def decode(self, a):
        h = self.hw(a)
        t = xlate(h)
        b = struct.pack('<H', t)
        if (t >> 11) == 0x1e and a + 2 < len(self.d):  # bl prefix
            b += struct.pack('<H', xlate(self.hw(a + 2)))
        ins = list(self.cs.disasm(b, a, 1))
        return (ins[0] if ins else None), h

    def in_code(self, a):
        return self.code_start <= a < self.code_end

    def walk(self, entry):
        stack = [entry]
        while stack:
            a = stack.pop()
            while self.in_code(a) and a not in self.code and a not in self.lit and (a & ~3) not in self.lit:
                ins, raw = self.decode(a)
                if ins is None:
                    break
                for k in range(0, ins.size, 2):
                    self.code.add(a + k)
                m = ins.mnemonic
                hi = raw >> 8
                op = ins.op_str
                nxt = a + ins.size
                if m == 'ldr' and 'pc' in op and '[' in op:
                    imm = (raw & 0xff) * 4
                    la = ((a + 4) & ~3) + imm
                    self.lit.add(la)
                if m == 'bl':
                    tgt = ins.operands[0].imm
                    if self.in_code(tgt):
                        stack.append(tgt); self.entries.add(tgt)
                elif m == 'b':
                    tgt = ins.operands[0].imm
                    if self.in_code(tgt): stack.append(tgt)
                    break
                elif m.startswith('b') and len(m) == 3 and m not in ('bic', 'bkp') or m in ('beq', 'bne', 'bhs', 'blo', 'bmi', 'bpl', 'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'bcs', 'bcc'):
                    tgt = ins.operands[0].imm
                    if self.in_code(tgt): stack.append(tgt)
                elif m == 'mov' and op.startswith('pc'):
                    stack.extend(self.jump_table(a))
                    break
                elif m == 'bx' or (m == 'pop' and 'pc' in op):
                    break
                if hi in (0x68, 0x69):  # treti
                    break
                a = nxt

    def jump_table(self, a):
        """Resolve `ldr rT,[pc]; ldr rX,[rT,rI]; mov pc,rX` switch: returns case targets."""
        table, count = None, None
        for back in range(2, 24, 2):
            b = a - back
            if b < self.code_start:
                break
            h = self.hw(b)
            if table is None and 0x08 <= (h >> 8) <= 0x0f:
                la = ((b + 4) & ~3) + (h & 0xff) * 4
                v = struct.unpack_from('<I', self.d, la)[0]
                if v < len(self.d):
                    table = v
                    self.lit.add(la)
            if count is None and 0xa8 <= (h >> 8) <= 0xaf:  # tcmp rN, #imm
                count = (h & 0xff) + 1
        if table is None:
            return []
        res = []
        for i in range(count or 64):
            p = table + 4 * i
            if p + 4 > len(self.d):
                break
            v = struct.unpack_from('<I', self.d, p)[0] & ~1
            if not self.in_code(v):
                break
            res.append(v)
        self.jt_targets.update(res)
        return res

    def run(self):
        # entries: reset vector targets + every literal/data word that looks like an odd code pointer
        seeds = {0x20, 0x50} | self.extra
        for a in range(0, len(self.d) - 3, 4):
            v = struct.unpack_from('<I', self.d, a)[0]
            if v & 1 and self.in_code(v & ~1):
                seeds.add(v & ~1)
        self.entries |= seeds
        for s in sorted(seeds):
            self.walk(s)
        # Phase 2: tpush {.., lr} prologues not inside known code/literal pools, iterated to a fixpoint
        tried = set()
        while True:
            new = [a for a in range(self.code_start, self.code_end, 2)
                   if (self.hw(a) >> 8) == 0x65 and a not in tried and a not in self.code and (a & ~3) not in self.lit]
            if not new:
                break
            for a in new:
                tried.add(a)
                if a in self.code or (a & ~3) in self.lit:
                    continue
                self.entries.add(a)
                self.walk(a)
        return self

    def image(self):
        out = bytearray(self.d)
        for a in self.code:
            if (a & ~3) in self.lit or ((a - 2) & ~3) in self.lit and (a - 2) in self.lit:
                continue
            struct.pack_into('<H', out, a, xlate(self.hw(a)))
        for la in self.lit:  # restore literal words exactly
            out[la:la + 4] = self.d[la:la + 4]
        return bytes(out)


if __name__ == '__main__':
    src, dst, end = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
    data = open(src, 'rb').read()
    tr = Translator(data, end).run()
    open(dst, 'wb').write(tr.image())
    with open(dst + '.entries', 'w') as f:
        for e in sorted(tr.entries):
            if e in tr.code:
                f.write(f'{e:#x}\n')
    print(f'code halfwords={len(tr.code)} literals={len(tr.lit)} entries={len(tr.entries)}')
