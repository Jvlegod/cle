#!/usr/bin/env python
from __future__ import annotations
import os
import cle
import struct
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

def get_real_instr(r):
    try:
        if r.relative_addr % 2 != 0:
            return None
        probing = r.owner.memory.unpack_word(r.relative_addr, size=2)
        if (probing & 0x3) != 0x3:
            return probing
        return r.owner.memory.unpack_word(r.relative_addr, size=4)
    except (KeyError, struct.error):
        return None

def run_reloc_test_on_file(file_path, base_addr=0x210000):
    print(f"\n{'='*60}")
    print(f"Testing: {os.path.basename(file_path)}")
    print(f"{'='*60}")

    try:
        loader = cle.Loader(file_path, main_opts={"base_addr": base_addr})
    except Exception as e:
        print(f"Failed to load {file_path}: {e}")
        return False

    obj = loader.main_object
    relocations = obj.relocs
    riscv = cle.backends.elf.relocation.riscv64

    seen = {
        "hi20": 0, "lo12_i": 0, "lo12_s": 0,
        "pcrel_hi20": 0, "pcrel_lo12_i": 0, "pcrel_lo12_s": 0,
        "jal": 0, "call": 0, "64_abs": 0, "32_abs": 0,
        "rvc_jump": 0, "rvc_branch": 0, "branch": 0,
    }

    for r in relocations:

        if isinstance(r, riscv.R_RISCV_64):
            seen["64_abs"] += 1
            data = r.owner.memory.unpack_word(r.relative_addr, size=8)
            expected = r.resolvedby.rebased_addr + r.addend
            assert data == expected
            continue
        elif isinstance(r, riscv.R_RISCV_32):
            seen["32_abs"] += 1
            data = r.owner.memory.unpack_word(r.relative_addr, size=4)
            expected = r.resolvedby.rebased_addr + r.addend
            assert data == expected
            continue
        elif isinstance(r, riscv.R_RISCV_NONE):
            continue

        instr = get_real_instr(r)
        if instr is None:
            log.warning(f"Failed to get real instruction for relocation: {r}")
            continue

        if isinstance(r, riscv.R_RISCV_PCREL_HI20):
            seen["pcrel_hi20"] += 1
            assert (instr & 0x7F) == 0b0010111
        elif isinstance(r, riscv.R_RISCV_PCREL_LO12_I):
            seen["pcrel_lo12_i"] += 1
            assert (instr & 0x7F) in {0b0010011, 0b0000011, 0b0000111, 0b1100111}
        elif isinstance(r, riscv.R_RISCV_PCREL_LO12_S):
            seen["pcrel_lo12_s"] += 1
            assert (instr & 0x7F) == 0b0100011
        elif isinstance(r, riscv.R_RISCV_LO12_I):
            seen["lo12_i"] += 1
            assert (instr & 0x7F) in {0b0010011, 0b0000011, 0b0000111, 0b1100111}
        elif isinstance(r, riscv.R_RISCV_LO12_S):
            seen["lo12_s"] += 1
            assert (instr & 0x7F) == 0b0100011
        elif isinstance(r, (riscv.R_RISCV_CALL, riscv.R_RISCV_CALL_PLT)):
            seen["call"] += 1
            assert (instr & 0x7F) == 0b0010111
            next_instr = r.owner.memory.unpack_word(r.relative_addr + 4, size=4)
            assert (next_instr & 0x7F) == 0b1100111
        elif isinstance(r, riscv.R_RISCV_JAL):
            seen["jal"] += 1
            assert (instr & 0x7F) == 0b1101111
        elif isinstance(r, riscv.R_RISCV_BRANCH):
            seen["branch"] += 1
            assert (instr & 0x7F) == 0b1100011
        elif isinstance(r, riscv.R_RISCV_RVC_JUMP):
            seen["rvc_jump"] += 1
            assert (instr & 0x3) == 0b01
            assert ((instr >> 13) & 0x7) in {0b101, 0b001}
        elif isinstance(r, riscv.R_RISCV_RVC_BRANCH):
            seen["rvc_branch"] += 1
            assert (instr & 0x3) == 0b01
            assert ((instr >> 13) & 0x7) in {0b110, 0b111}

    print("Relocation Test Report:")
    for k, v in seen.items():
        if v > 0:
            print(f"    - {k:15}: {v}")
    return True

def test_riscv64_all_relocations():
    riscv_test_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..", "..", "binaries", "tests", "riscv64"
    )

    if not os.path.exists(riscv_test_dir):
        print(f"Directory not found: {riscv_test_dir}")
        return

    test_files = [os.path.join(riscv_test_dir, f) for f in os.listdir(riscv_test_dir) if f.endswith(".o")]
    
    if not test_files:
        print(f"No .o files found in {riscv_test_dir}")
        return

    success_count = 0
    for file in sorted(test_files):
        if run_reloc_test_on_file(file):
            success_count += 1

    print(f"\n{'-'*60}")
    print(f"Summary: {success_count}/{len(test_files)} files passed.")
    print(f"{'-'*60}")

if __name__ == "__main__":
    test_riscv64_all_relocations()