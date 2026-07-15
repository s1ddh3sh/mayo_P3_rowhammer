import re

BASE = 0x23c          # link-time address right after the call (rel32 is relative to this)
orig_rel32 = 0xfffffd14  # from bytes 14 fd ff ff, little-endian

ret_addrs = []
with open("disasm.txt") as f:
    for line in f:
        m = re.match(r"\s*([0-9a-f]+):\s+c3\s*(?:$|\s+ret)", line)
        if m:
            ret_addrs.append(int(m.group(1), 16))

print(f"Found {len(ret_addrs)} candidate ret addresses")

hits = []
for addr in ret_addrs:
    target_rel32 = (addr - BASE) & 0xffffffff
    diff = target_rel32 ^ orig_rel32
    if diff != 0 and (diff & (diff - 1)) == 0:
        byte_idx = (diff.bit_length() - 1) // 8
        bit_in_byte = 1 << ((diff.bit_length() - 1) % 8)
        hits.append((addr, byte_idx, bit_in_byte))
        print(f"target=0x{addr:x}  flip byte offset {byte_idx} (address 0x{0x237+byte_idx:x}) with bitmask 0x{bit_in_byte:02x}")

if not hits:
    print("No single-bit-flip candidates found among ret sites — see fallback note below")