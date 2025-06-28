#!/usr/bin/env python3

import angr
import claripy

def main():
    binary1 = 'bin/version1'
    binary2 = 'bin/version2'
    num_args = 5
    max_arg_len = 8

    # Create symbolic variables for each argument
    symbolic_args = []
    for i in range(num_args):
        # Create symbolic string without null terminator first
        arg = claripy.BVS(f'arg{i}', max_arg_len * 8)
        symbolic_args.append(arg)

    # Create projects
    proj1 = angr.Project(binary1, auto_load_libs=False)
    proj2 = angr.Project(binary2, auto_load_libs=False)

    # Create initial symbolic states for both binaries
    state1 = proj1.factory.full_init_state(args=['binary'] + symbolic_args)
    state2 = proj2.factory.full_init_state(args=['binary'] + symbolic_args)

    # Add important options
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state1.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    state2.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)

    # Constrain arguments to printable ASCII characters
    for arg in symbolic_args:
        bytes_list = arg.chop(8)
        for byte_val in bytes_list:
            state1.solver.add(byte_val >= 0x20)  # Space
            state1.solver.add(byte_val <= 0x7e)  # Tilde
            state2.solver.add(byte_val >= 0x20)
            state2.solver.add(byte_val <= 0x7e)

    # Create simulation managers
    sm1 = proj1.factory.simulation_manager(state1)
    sm2 = proj2.factory.simulation_manager(state2)

    # Step through both programs simultaneously
    max_steps = 1000
    step_count = 0
    
    while (sm1.active or sm2.active) and step_count < max_steps:
        if sm1.active:
            sm1.step()
        if sm2.active:
            sm2.step()
        step_count += 1
        
        # Check for differences in output periodically
        if step_count % 50 == 0:
            print(f"Step {step_count}: sm1 active: {len(sm1.active)}, sm2 active: {len(sm2.active)}")

    # Alternative approach: Run to completion with timeout
    print("Running version1...")
    try:
        sm1.run(timeout=60)
    except Exception as e:
        print(f"Version1 execution exception: {e}")
    
    print("Running version2...")
    try:
        sm2.run(timeout=60)
    except Exception as e:
        print(f"Version2 execution exception: {e}")

    print(f"Version1 - Deadended: {len(sm1.deadended)}, Active: {len(sm1.active)}, Errored: {len(sm1.errored)}")
    print(f"Version2 - Deadended: {len(sm2.deadended)}, Active: {len(sm2.active)}, Errored: {len(sm2.errored)}")

    # Compare outputs from deadended states
    found_regression = False
    
    # If we have deadended states, compare them
    if sm1.deadended and sm2.deadended:
        for i, s1 in enumerate(sm1.deadended):
            for j, s2 in enumerate(sm2.deadended):
                try:
                    # Get stdout from both states
                    stdout1 = s1.posix.dumps(1)
                    stdout2 = s2.posix.dumps(1)
                    
                    print(f"Comparing state1[{i}] vs state2[{j}]")
                    print(f"  stdout1: {stdout1}")
                    print(f"  stdout2: {stdout2}")
                    
                    if stdout1 != stdout2:
                        print("[+] Found regression bug!")
                        print(f"version1 output: {stdout1}")
                        print(f"version2 output: {stdout2}")
                        
                        # Solve for concrete argument values
                        concrete_args = []
                        for k, arg in enumerate(symbolic_args):
                            try:
                                val = s1.solver.eval(arg, cast_to=bytes)
                                # Convert to string and strip null bytes
                                arg_str = val.decode('ascii', errors='ignore').rstrip('\x00')
                                concrete_args.append(arg_str)
                                print(f"  arg{k}: '{arg_str}'")
                            except Exception as e:
                                print(f"Error evaluating arg{k}: {e}")
                                concrete_args.append("ERROR")
                        
                        # Write to regressing.txt
                        with open("regressing.txt", "w") as f:
                            f.write(" ".join(concrete_args))
                        
                        print("[+] Arguments written to regressing.txt")
                        found_regression = True
                        return
                        
                except Exception as e:
                    print(f"Error comparing states: {e}")
                    continue
    
    # Alternative: If no deadended states, try a different approach
    if not found_regression and not sm1.deadended and not sm2.deadended:
        print("No deadended states found. Trying alternative approach...")
        
        # Use explore to find different paths
        state1_copy = proj1.factory.full_init_state(args=['binary'] + symbolic_args)
        state2_copy = proj2.factory.full_init_state(args=['binary'] + symbolic_args)
        
        # Add the same constraints
        for arg in symbolic_args:
            bytes_list = arg.chop(8)
            for byte_val in bytes_list:
                state1_copy.solver.add(byte_val >= 0x20, byte_val <= 0x7e)
                state2_copy.solver.add(byte_val >= 0x20, byte_val <= 0x7e)
        
        sm1_alt = proj1.factory.simulation_manager(state1_copy)
        sm2_alt = proj2.factory.simulation_manager(state2_copy)
        
        # Explore with find condition (look for any exit)
        sm1_alt.explore(find=lambda s: True, num_find=10)
        sm2_alt.explore(find=lambda s: True, num_find=10)
        
        print(f"Alternative - Found states: v1={len(sm1_alt.found)}, v2={len(sm2_alt.found)}")
        
        # Compare found states
        for s1 in sm1_alt.found[:5]:  # Limit to first 5 to avoid too many comparisons
            for s2 in sm2_alt.found[:5]:
                try:
                    stdout1 = s1.posix.dumps(1)
                    stdout2 = s2.posix.dumps(1)
                    
                    if stdout1 != stdout2:
                        print("[+] Found regression in alternative search!")
                        
                        concrete_args = []
                        for k, arg in enumerate(symbolic_args):
                            val = s1.solver.eval(arg, cast_to=bytes)
                            arg_str = val.decode('ascii', errors='ignore').rstrip('\x00')
                            concrete_args.append(arg_str)
                        
                        with open("regressing.txt", "w") as f:
                            f.write(" ".join(concrete_args))
                        
                        return
                except:
                    continue

    if not found_regression:
        print("[-] No regression found.")

if __name__ == "__main__":
    main()
