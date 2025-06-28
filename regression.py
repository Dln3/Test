#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'

    num_args = 5
    arg_len = 8

    # Fix first 4 args
    fixed_args = [
        b"11111111",  # arg1
        b"22222222",  # arg2
        b"33333333",  # arg3
        b"44444444",  # arg4
    ]

    # Make only arg5 symbolic
    sym_chars = [claripy.BVS(f'arg4_{i}', 8) for i in range(arg_len)]
    for c in sym_chars:
        c = claripy.And(c >= ord('0'), c <= ord('9'))
    arg5 = claripy.Concat(*sym_chars)

    argv = ['binary']
    for arg in fixed_args:
        argv.append(claripy.BVV(arg, 8 * arg_len))
    argv.append(arg5)  # symbolic 5th arg

    # Setup project and state
    proj1 = angr.Project(binary1, auto_load_libs=False)
    state1 = proj1.factory.full_init_state(args=argv)
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain symbolic arg to digits
    for c in sym_chars:
        state1.solver.add(c >= ord('0'), c <= ord('9'))

    simgr = proj1.factory.simulation_manager(state1)
    simgr.run()

    for s1 in simgr.deadended:
        out1 = s1.posix.dumps(1)

        concrete_args = [arg for arg in fixed_args]
        last = s1.solver.eval(arg5, cast_to=bytes)
        concrete_args.append(last)

        str_args = [a.decode("utf-8") for a in concrete_args]

        proj2 = angr.Project(binary2, auto_load_libs=False)
        state2 = proj2.factory.full_init_state(args=['binary'] + str_args)
        state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        sm2 = proj2.factory.simulation_manager(state2)
        sm2.run()

        for s2 in sm2.deadended:
            out2 = s2.posix.dumps(1)

            if out1 != out2:
                print("[+] Found regression!")
                print(f"version1: {out1}")
                print(f"version2: {out2}")

                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args) + b"\n")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
