#!/usr/bin/env python3

import angr
import claripy
import subprocess

MAX_ARG_LEN = 8
NUM_ARGS = 5
MAX_STEPS = 1000  # Tune for your VM/memory

def make_symbolic_args():
    args = []
    for i in range(NUM_ARGS):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(MAX_ARG_LEN)]
        arg = claripy.Concat(*chars + [claripy.BVV(0, 8)])  # null terminated
        args.append((arg, chars))
    return args

def create_state(proj, symbolic_args):
    args = [proj.filename] + [arg for arg, _ in symbolic_args]
    state = proj.factory.full_init_state(args=args)

    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # constrain to printable ascii
    for _, chars in symbolic_args:
        for c in chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)

    return state

def concretize_args(solver, symbolic_args):
    concrete = []
    for _, chars in symbolic_args:
        val = b''.join(solver.eval(c, cast_to=bytes) for c in chars).rstrip(b'\x00')
        concrete.append(val.decode('utf-8', errors='ignore'))
    return concrete

def run_version2_with_args(args):
    # run bin/version2 with concrete args, capture stdout
    # args is list of strings
    cmd = ['./bin/version2'] + args
    proc = subprocess.run(cmd, capture_output=True)
    return proc.stdout

def main():
    proj1 = angr.Project('bin/version1', auto_load_libs=False)
    symbolic_args = make_symbolic_args()
    state1 = create_state(proj1, symbolic_args)
    simgr = proj1.factory.simgr(state1)
    simgr.run(n=MAX_STEPS)

    print(f"Explored {len(simgr.deadended)} deadended states in version1")

    for s in simgr.deadended:
        # Get concrete inputs from version1 state
        concrete_args = concretize_args(s.solver, symbolic_args)

        # Run version1 concretely to get output (reuse s.posix.dumps(1) if you want)
        out1 = s.posix.dumps(1)

        # Run version2 concretely with same inputs
        out2 = run_version2_with_args(concrete_args)

        if out1 != out2:
            print("[+] Regression found!")
            print(f"version1 output: {out1}")
            print(f"version2 output: {out2}")

            # Save args to regressing.txt
            with open("regressing.txt", "w") as f:
                f.write(" ".join(concrete_args) + "\n")
            return

    print("[-] No regression found.")

if __name__ == '__main__':
    main()
