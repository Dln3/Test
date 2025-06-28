#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    arg_len = 8

    # Create symbolic args: 5 args * 8 bytes each
    symbolic_args = []
    for i in range(num_args):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(arg_len)]
        symbolic_args.append(claripy.Concat(*chars))

    argv = ['binary'] + symbolic_args

    proj1 = angr.Project(binary1, auto_load_libs=False)
    state1 = proj1.factory.full_init_state(args=argv)
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain all bytes to ASCII digits '0'..'9'
    for arg in symbolic_args:
        for byte in arg.chop(8):
            state1.solver.add(byte >= ord('0'))
            state1.solver.add(byte <= ord('9'))

    simgr1 = proj1.factory.simulation_manager(state1)
    simgr1.run()

    for s1 in simgr1.deadended:
        out1 = s1.posix.dumps(1)

        concrete_args = [s1.solver.eval(arg, cast_to=bytes) for arg in symbolic_args]
        str_args = [arg.decode('utf-8') for arg in concrete_args]

        # Run version2 concretely with those args
        proj2 = angr.Project(binary2, auto_load_libs=False)
        state2 = proj2.factory.full_init_state(args=['binary'] + str_args)
        state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        simgr2 = proj2.factory.simulation_manager(state2)
        simgr2.run()

        for s2 in simgr2.deadended:
            out2 = s2.posix.dumps(1)

            # Print outputs in hex and raw
            print("version1 output (raw):", repr(out1))
            print("version2 output (raw):", repr(out2))
            print("version1 output (hex):", out1.hex())
            print("version2 output (hex):", out2.hex())

            if out1 != out2:
                print("[+] Regression found!")
                print(f"Arguments: {[a.decode('utf-8') for a in concrete_args]}")

                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args) + b"\n")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
