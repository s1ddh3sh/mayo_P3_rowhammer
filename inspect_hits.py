import re
import sys

RAW_LOG = sys.argv[1] if len(sys.argv) > 1 else "bash_script_results/opcode_bruteforce_raw.txt"
HITS_FILE = sys.argv[2] if len(sys.argv) > 2 else "bash_script_results/opcode_bruteforce_hits.txt"

with open(RAW_LOG, "r", errors="ignore") as f:
    raw = f.read()

# Split raw log into blocks by the "===== ... =====" markers
blocks = re.split(r"\n(?====== \[byte_offset)", raw)

# Build a lookup: note-text -> block content
block_map = {}
for b in blocks:
    m = re.match(r"===== (\[byte_offset.*?\]) crashed=(\w+) =====", b)
    if m:
        note = m.group(1)
        block_map[note] = b

with open(HITS_FILE, "r") as f:
    hit_lines = [l.strip() for l in f if l.strip()]

print(f"{len(hit_lines)} non-crashing hits to inspect\n")

for line in hit_lines:
    m = re.match(r"(\[byte_offset.*?\])", line)
    if not m:
        continue
    note = m.group(1)
    block = block_map.get(note, "")

    # Look for the "Is equal N" printf output
    eq_match = re.search(r"Is equal (-?\d+)", block)
    # Look for gdb's own exit status line
    exit_match = re.search(r"\[Inferior \d+ \(process \d+\) (exited normally|exited with code (\d+))\]", block)
    # Look for any abort/assert signals gdb might report differently
    abort_match = re.search(r"(Aborted|assert|Assertion)", block)

    print(f"{note}")
    if eq_match:
        print(f"   -> printed: Is equal {eq_match.group(1)}")
    else:
        print(f"   -> 'Is equal' line NOT found in output")
    if exit_match:
        print(f"   -> {exit_match.group(0)}")
    else:
        print(f"   -> no explicit exit-status line found (process may have hit gdb's 'quit' before finishing, or output format differs)")
    if abort_match:
        print(f"   -> found '{abort_match.group(1)}' in output (missed by original crash detector!)")
    print()