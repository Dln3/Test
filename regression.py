#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    max_arg_len = 8

    # Create symbolic arguments (with null terminator)
    symbolic_args = []
    for i in range(num_args):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(max_arg_len)]
        arg = claripy.Concat(*chars + [claripy.BVV(0, 8)])
        symbolic_args.append((arg, chars))  # Keep chars for decoding

    argv1 = [binary1] + [arg for arg, _ in symbolic_args]
    argv2 = [binary2] + [arg for arg, _ in symbolic_args]

    proj1 = angr.Project(binary1, auto_load_libs=False)
    proj2 = angr.Project(binary2, auto_load_libs=False)

    state1 = proj1.factory.full_init_state(args=argv1)
    state2 = proj2.factory.full_init_state(args=argv2)

    # Zero-fill unknown memory to avoid strlen issues
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain input bytes to printable ASCII
    for _, chars in symbolic_args:
        for c in chars:
            state1.solver.add(c >= 0x20, c <= 0x7e)
            state2.solver.add(c >= 0x20, c <= 0x7e)

    sm1 = proj1.factory.simulation_manager(state1)
    sm2 = proj2.factory.simulation_manager(state2)

    sm1.run()
    sm2.run()

    for s1 in sm1.deadended:
        for s2 in sm2.deadended:
            out1 = s1.posix.dumps(1)
            out2 = s2.posix.dumps(1)

            if s1.solver.satisfiable(extra_constraints=[out1 != out2]):
                # Regression found!
                concrete_args = []
                for _, chars in symbolic_args:
                    concrete = b''.join([s1.solver.eval(c, cast_to=bytes) for c in chars])
                    concrete_args.append(concrete.rstrip(b'\x00'))

                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args))

                print("[+] Regression found!")
                print(f"version1 stdout: {out1}")
                print(f"version2 stdout: {out2}")
                print("[+] Written to regressing.txt")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
