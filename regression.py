#!/usr/bin/env python3
import angr
import claripy
import os

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    max_arg_len = 8

    # Create symbolic variables for each argument
    symbolic_args = []
    for i in range(num_args):
        chars = [claripy.BVS(f'arg{i}_{j}', 8) for j in range(max_arg_len)]
        arg = claripy.Concat(*chars)
        arg = claripy.Concat(arg, claripy.BVV(0, 8))  # null-terminated
        symbolic_args.append(arg)

    argv = ['binary'] + symbolic_args

    # Setup project for version1 (symbolic execution)
    proj1 = angr.Project(binary1, auto_load_libs=False)
    state1 = proj1.factory.full_init_state(args=argv)
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain all characters to printable ASCII (excluding null terminator)
    for arg in symbolic_args:
        chars = arg.chop(8)[:-1]  # Exclude the null terminator
        for byte in chars:
            state1.solver.add(byte >= 0x20)
            state1.solver.add(byte <= 0x7e)

    sm1 = proj1.factory.simulation_manager(state1)
    
    # ONLY CHANGE: Add state limiting to prevent memory explosion
    sm1.use_technique(angr.exploration_techniques.DFS())
    sm1.use_technique(angr.exploration_techniques.LengthLimiter(max_length=1000))
    
    # Run with a reasonable limit
    try:
        sm1.run(until=lambda sm: len(sm.deadended) >= 10 or len(sm.active) == 0)
    except:
        pass  # Continue even if it times out

    # Create project2 once
    proj2 = angr.Project(binary2, auto_load_libs=False)

    # Check outputs of deadended paths in version1
    for s1 in sm1.deadended:
        output1 = s1.posix.dumps(1)
        
        # Concretize arguments
        concrete_args = [s1.solver.eval(arg, cast_to=bytes).strip(b"\x00") for arg in symbolic_args]
        concrete_args_str = [arg.decode("utf-8", errors="ignore") for arg in concrete_args]
        
        # Re-execute version2 concretely with same args
        state2 = proj2.factory.full_init_state(args=['binary'] + concrete_args_str)
        state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        
        sm2 = proj2.factory.simulation_manager(state2)
        sm2.run()
        
        # Check output from version2
        for s2 in sm2.deadended:
            output2 = s2.posix.dumps(1)
            if output1 != output2:
                print("[+] Found regression!")
                print(f"version1 output:\n{output1}")
                print(f"version2 output:\n{output2}")
                
                # Write to regressing.txt
                with open("regressing.txt", "wb") as f:
                    f.write(b" ".join(concrete_args))
                print("[+] Saved input to regressing.txt")
                return

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
