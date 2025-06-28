#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    arg_len = 8  # exact length per argument

    # Step 1: Create symbolic args without null terminators, constrained to digits only
    symbolic_args = []
    for i in range(num_args):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(arg_len)]
        for c in chars:
            # constrain to digits '0'..'9'
            # We will add constraints on the state below
            pass
        arg = claripy.Concat(*chars)
        symbolic_args.append(arg)

    argv = ['binary'] + symbolic_args  # argv[0] dummy

    proj1 = angr.Project(binary1, auto_load_libs=False)
    state1 = proj1.factory.full_init_state(args=argv)
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain all arg bytes to digits '0'..'9'
    for arg in symbolic_args:
        for byte in arg.chop(8):
            state1.solver.add(byte >= ord('0'))
            state1.solver.add(byte <= ord('9'))

    simgr = proj1.factory.simulation_manager(state1)

    # Limit max explored states at a time to avoid memory explosion
    MAX_STEPS = 5000
    steps = 0

    while simgr.active and steps < MAX_STEPS:
        simgr.step()
        steps += 1

    # Check all deadended states for regression
    for dead_state in simgr.deadended:
        out1 = dead_state.posix.dumps(1)
        if not out1.strip():
            continue

        concrete_args = [dead_state.solver.eval(arg, cast_to=bytes) for arg in symbolic_args]
        concrete_args_str = [a.decode('utf-8') for a in concrete_args]

        proj2 = angr.Project(binary2, auto_load_libs=False)
        state2 = proj2.factory.full_init_state(args=['binary'] + concrete_args_str)
        state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

        simgr2 = proj2.factory.simulation_manager(state2)
        simgr2.run()

        for s2 in simgr2.deadended:
            out2 = s2.posix.dumps(1)
            if out1 != out2:
                print("[+] Regression Found!")
                print(f"version1 output:\n{out1}")
                print(f"version2 output:\n{out2}")
                print(f"Arguments: {concrete_args_str}")

                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args))
                print("[+] Saved regressing.txt with arguments.")
                return

    print("[-] No regression found after exploration limit.")

if __name__ == "__main__":
    main()
