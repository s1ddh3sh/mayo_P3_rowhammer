import os
import subprocess
import tempfile
import sys
import re


EXECUTABLE = "build/apps/example_mayo_1"


def run_gdb(executable, runtime_addr, new_value, success_string, timeout=3):
    """Run executable under GDB, overwrite one byte, continue, and capture output."""

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as gdb_script:
        gdb_script.write("set pagination off\n")
        gdb_script.write("set confirm off\n")
        gdb_script.write("start\n")
        gdb_script.write(
            f"set *(unsigned char*)({runtime_addr}) = {new_value}\n"
        )
        gdb_script.write("continue\n")
        gdb_script.write("quit\n")
        gdb_script_name = gdb_script.name

    try:
        result = subprocess.run(
            [
                "timeout",
                str(timeout),
                "gdb",
                "-q",
                "-x",
                gdb_script_name,
                f"./{executable}"
            ],
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

    crash_strings = [
        "SIGSEGV",
        "SIGILL",
        "SIGBUS",
        "SIGFPE",
        "Segmentation fault",
        "Program terminated with signal",
        "TIMEOUT"
    ]

    crashed = any(s in output for s in crash_strings)
    success_found = success_string in output

    return output, crashed, success_found

def get_disassembly(executable):
    """
    Parse instruction lines from:

        objdump -d -w ./build/apps/example_mayo_1

    Example:

        2237: e8 14 fd ff ff    call 1f50 <P1_times_O.isra.0>

    Returns:

        [
            {
                "address": 0x2237,
                "bytes": [0xe8, 0x14, 0xfd, 0xff, 0xff],
                "asm": "call 1f50 <P1_times_O.isra.0>"
            },
            ...
        ]
    """

    result = subprocess.run(
        ["objdump", "-d", "-w", f"./{executable}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True
    )

    instructions = []

    for line in result.stdout.splitlines():

        # Instruction lines must contain ':'
        if ":" not in line:
            continue

        left, right = line.split(":", 1)

        address_string = left.strip()

        # Validate address field.
        try:
            address = int(address_string, 16)
        except ValueError:
            continue

        #
        # objdump normally separates:
        #
        # bytes <TAB> assembly
        #
        # Example:
        #
        # e8 14 fd ff ff<TAB>call 1f50 <...>
        #

        parts = right.strip().split("\t")

        if not parts:
            continue

        byte_field = parts[0].strip()

        byte_tokens = byte_field.split()

        instruction_bytes = []

        valid_bytes = True

        for token in byte_tokens:

            if len(token) != 2:
                valid_bytes = False
                break

            try:
                value = int(token, 16)
            except ValueError:
                valid_bytes = False
                break

            instruction_bytes.append(value)

        if not valid_bytes or not instruction_bytes:
            continue

        # Everything after the byte field is assembly.
        asm = " ".join(
            part.strip()
            for part in parts[1:]
            if part.strip()
        )

        instructions.append({
            "address": address,
            "bytes": instruction_bytes,
            "asm": asm
        })

    return instructions


def find_instruction_window(instructions, target_addr, before_count, after_count):
    """Return instructions before/after the target instruction."""

    target_index = None

    for i, inst in enumerate(instructions):
        if inst["address"] == target_addr:
            target_index = i
            break

    if target_index is None:
        raise RuntimeError(
            f"Could not find instruction at link address 0x{target_addr:x}"
        )

    start = max(0, target_index - before_count)
    end = min(len(instructions), target_index + after_count + 1)

    return instructions[start:end]


def link_to_runtime_addr(instruction_addr, target_link_addr, target_runtime_addr):
    """Convert link-time address to runtime address using target-address delta."""

    return target_runtime_addr + (instruction_addr - target_link_addr)


def format_bytes(byte_list):
    return " ".join(f"{x:02x}" for x in byte_list)


def main():
    if len(sys.argv) < 7:
        print(
            f"Usage:\n"
            f"  python3 {sys.argv[0]} "
            f"<target_runtime_addr> "
            f"<target_link_addr> "
            f"<before_count> "
            f"<after_count> "
            f"<success_string> "
            f"<mode>\n"
        )

        print(
            "Example:\n"
            f"  python3 {sys.argv[0]} "
            "0x555555556237 "
            "0x2237 "
            "15 "
            "10 "
            "\"Is equal 0\" "
            "bitflip"
        )

        sys.exit(1)

    target_runtime_addr = int(sys.argv[1], 16)
    target_link_addr = int(sys.argv[2], 16)
    before_count = int(sys.argv[3])
    after_count = int(sys.argv[4])
    success_string = sys.argv[5]
    mode = sys.argv[6]

    if not os.path.isfile(f"./{EXECUTABLE}"):
        print(f"Error: ./{EXECUTABLE} does not exist.")
        sys.exit(1)

    instructions = get_disassembly(EXECUTABLE)

    window = find_instruction_window(
        instructions,
        target_link_addr,
        before_count,
        after_count
    )

    print("\nInstructions selected for fault injection:\n")

    for inst in window:
        marker = " <=== TARGET" if inst["address"] == target_link_addr else ""

        print(
            f"0x{inst['address']:x}: "
            f"{format_bytes(inst['bytes']):<30} "
            f"{inst['asm']}"
            f"{marker}"
        )

    OUTPUT_DIR = "bash_script_results"
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    RAW_LOG = os.path.join(
        OUTPUT_DIR,
        "opcode_window_raw.txt"
    )

    HITS_FILE = os.path.join(
        OUTPUT_DIR,
        "opcode_window_hits.txt"
    )

    open(RAW_LOG, "w").close()
    open(HITS_FILE, "w").close()

    total = 0
    clean_no_crash = 0
    clean_and_success = 0

    for inst in window:
        link_addr = inst["address"]

        runtime_addr = link_to_runtime_addr(
            link_addr,
            target_link_addr,
            target_runtime_addr
        )

        # Mutate only the first byte of each decoded instruction.
        orig_opcode = inst["bytes"][0]

        if mode == "bitflip":
            values_to_try = [
                (orig_opcode ^ (1 << bit), f"bit{bit}")
                for bit in range(8)
            ]

        elif mode == "full":
            values_to_try = [
                (value, f"0x{value:02x}")
                for value in range(256)
                if value != orig_opcode
            ]

        else:
            print(f"Unknown mode: {mode}")
            sys.exit(1)

        for new_opcode, label in values_to_try:
            total += 1

            note = (
                f"[inst_link=0x{link_addr:x} "
                f"inst_runtime=0x{runtime_addr:x} "
                f"asm=\"{inst['asm']}\" "
                f"orig_opcode=0x{orig_opcode:02x} "
                f"new_opcode=0x{new_opcode:02x} "
                f"{label}]"
            )

            output, crashed, success_found = run_gdb(
                EXECUTABLE,
                hex(runtime_addr),
                new_opcode,
                success_string
            )

            with open(RAW_LOG, "a") as f:
                f.write(
                    f"\n========================================\n"
                    f"{note}\n"
                    f"ORIGINAL BYTES: {format_bytes(inst['bytes'])}\n"
                    f"CRASHED: {crashed}\n"
                    f"SUCCESS: {success_found}\n"
                    f"========================================\n"
                )
                f.write(output)
                f.write("\n")

            if not crashed:
                clean_no_crash += 1

                status = (
                    "SUCCESS_STRING_FOUND"
                    if success_found
                    else "NO_SUCCESS_STRING"
                )

                with open(HITS_FILE, "a") as f:
                    f.write(
                        f"{note} "
                        f"crashed=False "
                        f"{status}\n"
                    )

                if success_found:
                    clean_and_success += 1

                    print(
                        f"[HIT]  "
                        f"0x{link_addr:x} "
                        f"{inst['asm']} | "
                        f"0x{orig_opcode:02x} -> "
                        f"0x{new_opcode:02x} "
                        f"{label}"
                    )

                else:
                    print(
                        f"[..]   "
                        f"0x{link_addr:x} "
                        f"{inst['asm']} | "
                        f"0x{orig_opcode:02x} -> "
                        f"0x{new_opcode:02x} "
                        f"{label} | "
                        f"NO SUCCESS"
                    )

    print("\n========================================")
    print("FAULT INJECTION COMPLETE")
    print("========================================")
    print(f"Executable:             {EXECUTABLE}")
    print(f"Instructions tested:    {len(window)}")
    print(f"Total fault injections: {total}")
    print(f"Clean executions:       {clean_no_crash}")
    print(f"Successful skips:       {clean_and_success}")
    print(f"Raw log:                {RAW_LOG}")
    print(f"Hits:                   {HITS_FILE}")


if __name__ == "__main__":
    main()
