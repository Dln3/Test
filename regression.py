#!/usr/bin/env python3

import angr
import claripy
import subprocess

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    max_arg_len = 8

    # Create symbolic args
    symbolic_args = []
    for i in range(num_args):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(max_arg_len)]
        arg = claripy.Concat(*chars, claripy.BVV(0,8))  # null terminate
        symbolic_args.append((arg, chars))

    # Setup angr project for version1 only
    proj1 = angr.Project(binary1, auto_load_libs=False)

    # Create initial state with symbolic args
    argv = [binary1] + [arg for arg, _ in symbolic_args]
    state = proj1.factory.full_init_state(args=argv)

    # Avoid strlen reading garbage
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # constrain symbolic bytes to printable ascii
    for _, chars in symbolic_args:
        for c in chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)

    simgr = proj1.factory.simgr(state)

    # Limit steps to avoid explosion
    simgr.run(n=1000)

    print(f"Explored {len(simgr.deadended)} finished states in version1")

    # For each finished path in version1, concretize input and run version2 concretely
    for deadend_state in simgr.deadended:
        solver = deadend_state.solver
        concrete_args = []
        for _, chars in symbolic_args:
            concrete = b''.join(solver.eval(c, cast_to=bytes) for c in chars).rstrip(b'\x00')
            concrete_args.append(concrete.decode('utf-8', errors='ignore'))

        # Get version1 output (already symbolic exec)
        out1 = deadend_state.posix.dumps(1)

        # Run version2 concretely with same input
        proc = subprocess.run([binary2] + concrete_args, capture_output=True)
        out2 = proc.stdout

        if out1 != out2:
            print("[+] Regression found!")
            print(f"version1 output: {out1}")
            print(f"version2 output: {out2}")

            with open("regressing.txt", "w") as f:
                f.write(" ".join(concrete_args) + "\n")

            return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
