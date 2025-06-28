#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    max_arg_len = 8  # Max length per argument

    # === Step 1: Create symbolic arguments ===
    symbolic_args = []
    for i in range(num_args):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(max_arg_len)]
        arg = claripy.Concat(*chars + [claripy.BVV(0, 8)])  # null-terminated
        symbolic_args.append(arg)

    argv = ['binary'] + symbolic_args  # argv[0] = dummy binary name

    # === Step 2: Setup version1 with symbolic state ===
    proj1 = angr.Project(binary1, auto_load_libs=False)
    state1 = proj1.factory.full_init_state(args=argv)
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain args to printable ASCII
    for arg in symbolic_args:
        for byte in arg.chop(8):
            state1.solver.add(byte >= 0x20)
            state1.solver.add(byte <= 0x7e)

    simgr = proj1.factory.simulation_manager(state1)

    # === Step 3: Explore paths that reach program termination ===
    simgr.run()

    for dead_state in simgr.deadended:
        out1 = dead_state.posix.dumps(1)

        if not out1.strip():
            continue  # Ignore empty output

        # Get concrete inputs
        concrete_args = [dead_state.solver.eval(arg, cast_to=bytes).strip(b'\x00') for arg in symbolic_args]
        concrete_args_str = [a.decode('utf-8', errors='ignore') for a in concrete_args]

        # === Step 4: Replay in version2 with concrete inputs ===
        proj2 = angr.Project(binary2, auto_load_libs=False)
        state2 = proj2.factory.full_init_state(args=['binary'] + concrete_args_str)
        state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

        simgr2 = proj2.factory.simulation_manager(state2)
        simgr2.run()

        for state in simgr2.deadended:
            out2 = state.posix.dumps(1)

            if out1 != out2:
                print("[+] Regression Found!")
                print(f"version1 output:\n{out1}")
                print(f"version2 output:\n{out2}")

                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args))
                print("[+] Saved regressing.txt with arguments.")
                return

    print("[-] No regression found after full symbolic run.")

if __name__ == '__main__':
    main()
