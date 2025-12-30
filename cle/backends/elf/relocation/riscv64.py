"""
Relocations for RISCV64

Reference:
1. https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#relocations
2. https://docs.riscv.org/reference/isa/_attachments/riscv-unprivileged.pdf

"""

from __future__ import annotations

import logging

from .elfreloc import ELFReloc
from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericIRelativeReloc,
    GenericJumpslotReloc,
)

log = logging.getLogger(name=__name__)

class R_RISCV_64(GenericAbsoluteAddendReloc):
    pass


class R_RISCV_COPY(GenericCopyReloc):
    pass


class R_RISCV_GLOB_DAT(GenericJumpslotReloc):
    pass


class R_RISCV_JUMP_SLOT(GenericJumpslotReloc):
    pass


class R_RISCV_IRELATIVE(GenericIRelativeReloc):
    pass

class R_RISCV_PCREL_HI20(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        hi20 = (val + 0x800) >> 12  # rounding per psABI

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= 0x00000FFF  # clear imm[31:12]
        instr |= (hi20 & 0xFFFFF) << 12

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True

class R_RISCV_PCREL_LO12_I(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        lo12 = val & 0xFFF

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~(0xFFF << 20)
        instr |= (lo12 & 0xFFF) << 20

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True

class R_RISCV_PCREL_LO12_S(ELFReloc):
  
    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        lo12 = val & 0xFFF
        
        imm_11_5 = (lo12 >> 5) & 0x7F
        imm_4_0 = lo12 & 0x1F

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~((0x7F << 25) | (0x1F << 7))
        instr |= (imm_11_5 << 25) | (imm_4_0 << 7)

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True
    
class R_RISCV_RELATIVE(ELFReloc):
    AUTO_HANDLE_NONE = True

    @property
    def value(self):
        return self.owner.mapped_base + self.addend
    
class R_RISCV_ADD32(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_SUB8(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_SUB16(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_SUB32(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_ALIGN(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self):
        return True
    
class R_RISCV_RVC_BRANCH(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value

        # C.B* offsets are multiples of 2
        if val & 0x1:
            log.warning("Unaligned RVC branch target")

        imm = val >> 1

        if not (-256 <= val < 256):
            log.warning("RVC branch out of range")

        instr = self.owner.memory.unpack_word(self.relative_addr, size=2)

        instr &= ~(
            (1 << 12) |  # imm[8]
            (1 << 11) |  # imm[4]
            (1 << 10) |  # imm[3]
            (1 << 6)  |  # imm[7]
            (1 << 5)  |  # imm[6]
            (1 << 4)  |  # imm[2]
            (1 << 3)  |  # imm[1]
            (1 << 2)     # imm[5]
        )

        instr |= (
            ((imm >> 8) & 1) << 12 |  # imm[8]
            ((imm >> 4) & 1) << 11 |  # imm[4]
            ((imm >> 3) & 1) << 10 |  # imm[3]
            ((imm >> 7) & 1) << 6  |  # imm[7]
            ((imm >> 6) & 1) << 5  |  # imm[6]
            ((imm >> 2) & 1) << 4  |  # imm[2]
            ((imm >> 1) & 1) << 3  |  # imm[1]
            ((imm >> 5) & 1) << 2     # imm[5]
        )

        self.owner.memory.pack_word(self.relative_addr, instr, size=2)
        return True


class R_RISCV_RVC_JUMP(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        imm = val >> 1

        instr = self.owner.memory.unpack_word(self.relative_addr, size=2)

        instr &= ~(
            (1 << 12)  | # imm[11]
            (1 << 11)  | # imm[4]
            (0x3 << 9) | # imm[9:8]
            (1 << 8)   | # imm[10]
            (1 << 7)   | # imm[6]
            (1 << 6)   | # imm[7]
            (0x7 << 3) | # imm[3:1]
            (1 << 2)     # imm[5]
        )

        instr |= (
            ((imm >> 11) & 1) << 12 | # imm[11]
            ((imm >> 4) & 1) << 11  | # imm[4]
            ((imm >> 8) & 0x3) << 9 | # imm[9:8]
            ((imm >> 10) & 1) << 8  | # imm[10]
            ((imm >> 6) & 1) << 7   | # imm[6]
            ((imm >> 7) & 1) << 6   | # imm[7]
            ((imm >> 1) & 0x7) << 3 | # imm[3:1]
            ((imm >> 5) & 1) << 2     # imm[5]
        )

        self.owner.memory.pack_word(self.relative_addr, instr, size=2)
        return True


class R_RISCV_RELAX(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self):
        return True
    
class R_RISCV_SUB6(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_SET6(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_SET8(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_SET16(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self): return True

class R_RISCV_HI20(ELFReloc):
    AUTO_HANDLE_NONE = True

    def relocate(self):
        return True


class R_RISCV_GOT_HI20(ELFReloc):
    AUTO_HANDLE_NONE = True

    def relocate(self):
        return True
    
class R_RISCV_LO12_I(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        lo12 = val & 0xFFF

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~(0xFFF << 20)
        instr |= lo12 << 20

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True

class R_RISCV_LO12_S(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        lo12 = val & 0xFFF

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~((0x7F << 25) | (0x1F << 7))
        instr |= ((lo12 >> 5) & 0x7F) << 25
        instr |= (lo12 & 0x1F) << 7

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True

class R_RISCV_32_PCREL(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        val = self.value
        self.owner.memory.pack_word(self.relative_addr, val & 0xFFFFFFFF, size=4)
        return True

class R_RISCV_CALL_PLT(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        # U + I Type instruction pair
        hi20 = (val + 0x800) >> 12
        lo12 = val & 0xFFF

        instr_hi = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr_hi &= 0x00000FFF
        instr_hi |= (hi20 & 0xFFFFF) << 12
        self.owner.memory.pack_word(self.relative_addr, instr_hi, size=4)

        instr_lo = self.owner.memory.unpack_word(self.relative_addr + 4, size=4)
        instr_lo &= 0x000FFFFF
        instr_lo |= (lo12 & 0xFFF) << 20
        self.owner.memory.pack_word(self.relative_addr + 4, instr_lo, size=4)

        return True

class R_RISCV_CALL(R_RISCV_CALL_PLT):
    def relocate(self):
        # NOTE: 
        log.debug("R_RISCV_CALL encountered, treating as CALL_PLT")
        return super().relocate()

class R_RISCV_BRANCH(ELFReloc):

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value

        if val & 0x1:
            log.warning("Unaligned BRANCH relocation")

        imm = val >> 1
        if not (-(1 << 12) <= imm < (1 << 12)):
            log.warning("BRANCH relocation out of range")

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)

        instr &= ~(
            (1 << 31)    | # imm[12]
            (0x3F << 25) | # imm[10:5]
            (0xF << 8)   | # imm[4:1]
            (1 << 7)       # imm[11]
        )

        instr |= (
            ((imm >> 11) & 0x1) << 31 | # imm[12]
            ((imm >> 5) & 0x3F) << 25 | # imm[10:5]
            ((imm >> 1) & 0xF) << 8   | # imm[4:1]
            ((imm >> 10) & 0x1) << 7    # imm[11]
        )

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_JAL(ELFReloc):
    AUTO_HANDLE_NONE = False

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        if not (-(1 << 20) <= val < (1 << 20)):
            log.warning("JAL relocation out of range")

        imm = val >> 1

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= 0xFFF  # keep rd/opcode

        instr |= (
            ((imm >> 19) & 0x1) << 31  | # imm[20]
            ((imm >> 9) & 0x3FF) << 21 | # imm[10:1]
            ((imm >> 8) & 0x1) << 20   | # imm[11]
            (imm & 0xFF) << 12           # imm[19:12]
        )

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True

class R_RISCV_SET_ULEB128(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self):
        return True


class R_RISCV_SUB_ULEB128(ELFReloc):
    AUTO_HANDLE_NONE = True
    def relocate(self):
        return True


relocation_table_riscv64 = {
    # 0: R_RISCV_NONE,
    # 1: R_RISCV_32,
    2: R_RISCV_64,
    3: R_RISCV_RELATIVE,
    # 4: R_RISCV_COPY,
    5: R_RISCV_JUMP_SLOT,
    # 6: R_RISCV_TLS_DTPMOD32,
    # 7: R_RISCV_TLS_DTPMOD64,
    # 8: R_RISCV_TLS_DTPREL32,
    # 9: R_RISCV_TLS_DTPREL64,
    # 10: R_RISCV_TLS_TPREL32,
    # 11: R_RISCV_TLS_TPREL64,
    # 12: R_RISCV_TLSDESC
    16: R_RISCV_BRANCH,
    17: R_RISCV_JAL,
    18: R_RISCV_CALL,
    19: R_RISCV_CALL_PLT,
    20: R_RISCV_GOT_HI20,
    # 21: R_RISCV_TLS_GOT_HI20,
    # 22: R_RISCV_TLS_GD_HI20,
    23: R_RISCV_PCREL_HI20,
    24: R_RISCV_PCREL_LO12_I,
    25: R_RISCV_PCREL_LO12_S,
    26: R_RISCV_HI20,
    27: R_RISCV_LO12_I,
    28: R_RISCV_LO12_S,
    # 29: R_RISCV_TPREL_HI20,
    # 30: R_RISCV_TPREL_LO12_I,
    # 31: R_RISCV_TPREL_LO12_S,
    # 32: R_RISCV_TPREL_ADD,
    # 33: R_RISCV_ADD8,
    # 34: R_RISCV_ADD16,
    35: R_RISCV_ADD32,
    # 36: R_RISCV_ADD64,
    37: R_RISCV_SUB8,
    38: R_RISCV_SUB16,
    39: R_RISCV_SUB32,
    # 40: R_RISCV_SUB64,
    # 41: R_RISCV_GOT32_PCREL,
    # 42: Reserved
    43: R_RISCV_ALIGN,
    44: R_RISCV_RVC_BRANCH,
    45: R_RISCV_RVC_JUMP,

    # 46-50: Reserved

    51: R_RISCV_RELAX,
    52: R_RISCV_SUB6,
    53: R_RISCV_SET6,
    54: R_RISCV_SET8,
    55: R_RISCV_SET16,
    # 56: R_RISCV_SET32,
    57: R_RISCV_32_PCREL,
    58: R_RISCV_IRELATIVE,
    # 59: R_RISCV_PLT32,
    60: R_RISCV_SET_ULEB128,
    61: R_RISCV_SUB_ULEB128,
    # 62: R_RISCV_TLSDESC_HI20,
    # 63: R_RISCV_TLSDESC_LOAD_LO12,
    # 64: R_RISCV_TLSDESC_ADD_LO12,
    # 65: R_RISCV_TLSDESC_CALL,

    # 66-190: Reserved

    # 191: R_RISCV_VENDOR,

    # 192-255: Reserved
}


__all__ = ("relocation_table_riscv64",)
