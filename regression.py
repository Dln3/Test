#!/usr/bin/env python3

import angr
import claripy

MAX_ARG_LEN = 8
NUM_ARGS = 5
MAX_STEPS = 500  # Limit symbolic execution steps to avoid crashes

def make_symbolic_args():
    args = []
    for i in range(NUM_ARGS):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(MAX_ARG_LEN)]
        arg = claripy.Concat(*chars + [claripy.BVV(0, 8)])  # Null-terminated
        args.append((arg, chars))
    return args

def create_state(project, symbolic_args):
    args = [project.filename] + [arg for arg, _ in symbolic_args]
    state = project.factory.full_init_state(args=args)

    # Zero-fill unconstrained memory & registers to prevent strlen issues & warnings
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # Constrain symbolic bytes to printable ASCII range
    for _, chars in symbolic_args:
        for c in chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)

    return state

def run_symbolic(project, symbolic_args):
    state = create_state(project, symbolic_args)
    simgr = project.factory.simgr(state)
    simgr.run(n=MAX_STEPS)  # Limit steps to avoid OOM/crashes
    return simgr.deadended

def main():
    proj1 = angr.Project("bin/version1", auto_load_libs=False)
    proj2 = angr.Project("bin/version2", auto_load_libs=False)

    symbolic_args = make_symbolic_args()

    states_v1 = run_symbolic(proj1, symbolic_args)
    states_v2 = run_symbolic(proj2, symbolic_args)

    for s1 in states_v1:
        for s2 in states_v2:
            out1 = s1.posix.dumps(1)
            out2 = s2.posix.dumps(1)

            if s1.solver.satisfiable(extra_constraints=[out1 != out2]):
                # Found regression
                solver = s1.solver
                with open("regressing.txt", "wb") as f:
                    for _, chars in symbolic_args:
                        concrete = b''.join([solver.eval(c, cast_to=bytes) for c in chars])
                        f.write(concrete.rstrip(b'\x00') + b" ")
                    f.write(b"\n")

                print("[+] Regression found! Input saved in regressing.txt")
                print(f"version1 output: {out1}")
                print(f"version2 output: {out2}")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
