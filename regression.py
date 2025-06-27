#!/usr/bin/env python3

import angr
import claripy

MAX_ARG_LEN = 8
NUM_ARGS = 5

def make_symbolic_args():
    args = []
    for i in range(NUM_ARGS):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(MAX_ARG_LEN)]
        arg = claripy.Concat(*chars + [claripy.BVV(0, 8)])  # Null-terminated string
        args.append((arg, chars))
    return args

def create_state(project, symbolic_args):
    args = [project.filename] + [arg for arg, _ in symbolic_args]
    state = project.factory.full_init_state(args=args)

    # Zero-fill to avoid memory access warnings (e.g., from strlen)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # Constrain all characters to printable ASCII
    for _, chars in symbolic_args:
        for c in chars:
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)

    return state

def run_and_get_terminated(project, symbolic_args):
    state = create_state(project, symbolic_args)
    simgr = project.factory.simgr(state)
    simgr.run()
    return simgr.deadended

def main():
    proj1 = angr.Project("bin/version1", auto_load_libs=False)
    proj2 = angr.Project("bin/version2", auto_load_libs=False)

    symbolic_args = make_symbolic_args()

    states_v1 = run_and_get_terminated(proj1, symbolic_args)
    states_v2 = run_and_get_terminated(proj2, symbolic_args)

    for s1 in states_v1:
        for s2 in states_v2:
            out1 = s1.posix.dumps(1)
            out2 = s2.posix.dumps(1)

            if s1.solver.satisfiable(extra_constraints=[out1 != out2]):
                solver = s1.solver
                with open("regressing.txt", "w") as f:
                    for _, chars in symbolic_args:
                        concrete = b''.join([solver.eval(c, cast_to=bytes) for c in chars])
                        printable = concrete.rstrip(b'\x00').decode('utf-8', errors='ignore')
                        f.write(printable + " ")
                    f.write("\n")
                print("[+] Regression detected. Inputs written to regressing.txt")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
