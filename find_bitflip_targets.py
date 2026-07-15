import os
import subprocess
import tempfile
import sys

def run_gdb(executable, addr_hex, byte_offset, new_value, timeout=3):
    """
    Start `executable` under gdb, at (addr_hex + byte_offset) overwrite the byte
    with new_value (0-255), continue, and capture combined stdout/stderr.
    Returns (output_text, crashed_bool).
    """
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as gdb_script:
        gdb_script.write("set pagination off\n")
        gdb_script.write("handle SIGSEGV nostop noprint pass\n")
        gdb_script.write("handle SIGILL nostop noprint pass\n")
        gdb_script.write("handle SIGBUS nostop noprint pass\n")
        gdb_script.write("handle SIGFPE nostop noprint pass\n")
        gdb_script.write(f"set $addr = {addr_hex} + {byte_offset}\n")
        gdb_script.write("start\n")
        gdb_script.write(f"set *(unsigned char*) $addr = {new_value}\n")
        gdb_script.write("continue\n")
        gdb_script.write("quit\n")
        gdb_script_name = gdb_script.name

    try:
        result = subprocess.run(
            ["timeout", str(timeout), "gdb", "-q", "-x", gdb_script_name, f"./{executable}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False
        )
        output = result.stdout
    except subprocess.TimeoutExpired:
        output = "TIMEOUT"
    finally:
        os.remove(gdb_script_name)

    crashed = ("SIGSEGV" in output or "SIGILL" in output or "SIGBUS" in output
               or "SIGFPE" in output or "Segmentation fault" in output
               or "TIMEOUT" in output or "Program terminated with signal" in output)
    return output, crashed


def get_original_bytes(executable, file_offset, num_bytes):
    """
    Read the original byte values directly from the ELF file on disk, so we
    know what to XOR against for bitflip mode. file_offset must be the FILE
    offset of the target bytes (not the runtime/link virtual address) --
    get this from `readelf -S` (section file offset + (vaddr - section addr)),
    or just eyeball it from `objdump -d` if .text starts at a known file offset.
    """
    with open(f"./{executable}", "rb") as f:
        f.seek(file_offset)
        return f.read(num_bytes)


def main():
    if len(sys.argv) < 6:
        print(f"Usage: python3 {sys.argv[0]} <runtime_base_address> <file_offset> <num_bytes> <liboqs> <success_string> [mode]")
        print(f"  runtime_base_address: address to poke via gdb at runtime, e.g. 0x0000555555556237")
        print(f"  file_offset:          same location's offset within the binary FILE (for reading original bytes)")
        print(f"  mode: 'bitflip' (default, 8 flips/byte) or 'full' (all 256 values/byte)")
        print(f"Example: python3 {sys.argv[0]} 0x0000555555556237 0x2237 5 1 \"Is equal 0\" bitflip")
        sys.exit(1)

    input_addr = sys.argv[1]
    if not input_addr.startswith("0x"):
        print("Error: base address must start with 0x")
        sys.exit(1)

    file_offset = int(sys.argv[2], 16)
    num_bytes = int(sys.argv[3])
    liboqs = int(sys.argv[4])
    success_string = sys.argv[5]
    mode = sys.argv[6] if len(sys.argv) > 6 else "bitflip"

    if liboqs == 1:
        EXECUTABLE = "liboqs_signature_gen/bin/sign_heap"
    else:
        EXECUTABLE = "build/apps/example_mayo_1"  # <-- adjust to your actual mayo binary path

    if not os.path.isfile(f"./{EXECUTABLE}"):
        print(f"Error: ./{EXECUTABLE} does not exist. Please compile your code first.")
        sys.exit(1)

    with open(os.path.expanduser("~/.gdbinit"), "w") as gdbinit:
        gdbinit.write("set debuginfod enabled off\n")

    orig_bytes = get_original_bytes(EXECUTABLE, file_offset, num_bytes)
    print(f"Original bytes at file offset 0x{file_offset:x}: {orig_bytes.hex()}")

    OUTPUT_DIR = "bash_script_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    RAW_LOG = os.path.join(OUTPUT_DIR, "opcode_bruteforce_raw.txt")
    HITS_FILE = os.path.join(OUTPUT_DIR, "opcode_bruteforce_hits.txt")
    open(RAW_LOG, "w").close()
    open(HITS_FILE, "w").close()

    total = 0
    clean_no_crash = 0
    clean_and_success = 0

    for byte_offset in range(num_bytes):
        orig_val = orig_bytes[byte_offset]

        if mode == "bitflip":
            values_to_try = [(orig_val ^ (1 << bit), f"bit{bit}") for bit in range(8)]
        elif mode == "full":
            values_to_try = [(v, f"0x{v:02x}") for v in range(256) if v != orig_val]
        else:
            print(f"Unknown mode: {mode}")
            sys.exit(1)

        for new_val, label in values_to_try:
            total += 1
            note = f"[byte_offset={byte_offset} orig=0x{orig_val:02x} new=0x{new_val:02x} {label}]"

            output, crashed = run_gdb(EXECUTABLE, input_addr, byte_offset, new_val)

            with open(RAW_LOG, "a") as f:
                f.write(f"\n===== {note} crashed={crashed} =====\n")
                f.write(output)
                f.write("\n")

            if not crashed:
                clean_no_crash += 1
                has_success = success_string in output
                status = "SUCCESS_STRING_FOUND" if has_success else "no_success_string"
                with open(HITS_FILE, "a") as f:
                    f.write(f"{note} crashed=False {status}\n")
                if has_success:
                    clean_and_success += 1
                    print(f"[HIT]  {note} -> no crash AND success string found")
                else:
                    print(f"[..]   {note} -> no crash, but success string absent")
            # crashed attempts stay only in RAW_LOG to keep HITS_FILE short and scannable

    print(f"\nDone. {total} attempts | {clean_no_crash} avoided crash | "
          f"{clean_and_success} avoided crash AND matched success string.")
    print(f"Raw output:   {RAW_LOG}")
    print(f"Hits summary: {HITS_FILE}")


if __name__ == "__main__":
    main()