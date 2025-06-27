#!/usr/bin/env python3

import angr
import claripy

def main():
    BIN1 = 'bin/version1'
    BIN2 = 'bin/version2'
    NUM_ARGS = 5
    MAX_LEN = 8

    # Create symbolic arguments (null-terminated)
    symbolic_args = []
    for i in range(NUM_ARGS):
        bytes_list = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(MAX_LEN)]
        arg = claripy.Concat(*bytes_list + [claripy.BVV(0, 8)])
        symbolic_args.append(arg)

    argv = ['program'] + symbolic_args

    # Create a shared symbolic state
    proj1 = angr.Project(BIN1, auto_load_libs=False)
    proj2 = angr.Project(BIN2, auto_load_libs=False)

    state1 = proj1.factory.full_init_state(args=argv)
    state2 = proj2.factory.full_init_state(args=argv)

    # Help angr with memory reads
    for state in [state1, state2]:
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        for arg in symbolic_args:
            for byte in arg.chop(8):
                state.solver.add(byte >= 0x20, byte <= 0x7e)  # printable

    # Step both programs for a fixed number of instructions
    simgr1 = proj1.factory.simulation_manager(state1)
    simgr2 = proj2.factory.simulation_manager(state2)

    simgr1.run(n=100)
    simgr2.run(n=100)

    # Compare stdout on all reachable states
    for s1 in simgr1.active + simgr1.deadended:
        for s2 in simgr2.active + simgr2.deadended:
            out1 = s1.posix.dumps(1)
            out2 = s2.posix.dumps(1)

            # Ask solver: is it possible they differ?
            if s1.solver.satisfiable(extra_constraints=[out1 != out2]):
                print("[+] Found regression!")

                # Get concrete args that trigger it
                concrete_args = []
                for arg in symbolic_args:
                    val = s1.solver.eval(arg, cast_to=bytes).split(b'\x00')[0]
                    concrete_args.append(val)

                # Save input
                with open('regressing.txt', 'wb') as f:
                    f.write(b' '.join(concrete_args))

                print("[+] Arguments written to regressing.txt")
                return

    print("[-] No regression found.")

if __name__ == '__main__':
    main()
