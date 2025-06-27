#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    max_arg_len = 8  # Each argument is at most 8 characters

    # Create symbolic variables for each argument
    symbolic_args = []
    for i in range(num_args):
        arg = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(max_arg_len)]
        arg_concat = claripy.Concat(*arg)
        arg_null_terminated = claripy.Concat(arg_concat, claripy.BVV(0, 8))  # C-style null-terminated string
        symbolic_args.append(arg_null_terminated)

    # List of full argv for both binaries
    argv = ['binary'] + symbolic_args  # dummy program name at argv[0]

    # Create projects
    proj1 = angr.Project(binary1, auto_load_libs=False)
    proj2 = angr.Project(binary2, auto_load_libs=False)

    # Create initial symbolic states for both binaries
    state1 = proj1.factory.full_init_state(args=argv)
    state2 = proj2.factory.full_init_state(args=argv)

    # Ensure uninitialized memory doesn't cause strlen issues
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Optional: constrain characters to printable ASCII
    for arg in symbolic_args:
        for byte in arg.chop(8):
            state1.solver.add(byte >= 0x20, byte <= 0x7e)
            state2.solver.add(byte >= 0x20, byte <= 0x7e)

    # Create simulation managers
    sm1 = proj1.factory.simulation_manager(state1)
    sm2 = proj2.factory.simulation_manager(state2)

    # Run both programs until they terminate
    sm1.run()
    sm2.run()

    # Compare output in final states
    for s1 in sm1.deadended:
        for s2 in sm2.deadended:
            stdout1 = s1.posix.dumps(1)
            stdout2 = s2.posix.dumps(1)

            if stdout1 != stdout2:
                print("[+] Found regression bug!")
                print(f"version1 output: {stdout1}")
                print(f"version2 output: {stdout2}")

                # Solve for concrete argument values
                concrete_args = []
                for arg in symbolic_args:
                    val = s1.solver.eval(arg, cast_to=bytes)
                    concrete_args.append(val.strip(b"\x00"))  # remove null terminator

                # Write to regressing.txt (space-separated)
                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args))

                print("[+] Arguments written to regressing.txt")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
