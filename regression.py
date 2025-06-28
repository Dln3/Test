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

    # Try differential symbolic execution instead
    print("Setting up differential execution...")
    
    proj1 = angr.Project(binary1, auto_load_libs=False)
    proj2 = angr.Project(binary2, auto_load_libs=False)
    
    state1 = proj1.factory.full_init_state(args=argv)
    state2 = proj2.factory.full_init_state(args=argv)
    
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

    # Constrain all characters to printable ASCII (excluding null terminator)
    for arg in symbolic_args:
        chars = arg.chop(8)[:-1]  # Exclude the null terminator
        for byte in chars:
            state1.solver.add(byte >= 0x20, byte <= 0x7e)
            state2.solver.add(byte >= 0x20, byte <= 0x7e)

    # Run both simultaneously and compare
    sm1 = proj1.factory.simulation_manager(state1)
    sm2 = proj2.factory.simulation_manager(state2)
    
    # Use exploration techniques
    sm1.use_technique(angr.exploration_techniques.DFS())
    sm2.use_technique(angr.exploration_techniques.DFS())
    
    max_steps = 500
    step = 0
    
    print("Starting differential execution...")
    
    while (sm1.active or sm2.active) and step < max_steps:
        if sm1.active:
            sm1.step()
        if sm2.active:
            sm2.step()
        step += 1
        
        # Check for differences after each step
        if step % 50 == 0:
            print(f"Step {step}: v1 states: {len(sm1.active)}, v2 states: {len(sm2.active)}")
        
        # Compare any newly deadended states
        if sm1.deadended and sm2.deadended:
            for s1 in sm1.deadended:
                for s2 in sm2.deadended:
                    # Check if they have the same input constraints
                    try:
                        # Try to find a solution that satisfies both
                        combined_constraints = s1.solver.constraints + s2.solver.constraints
                        if len(combined_constraints) > 0:
                            test_solver = claripy.Solver()
                            for constraint in combined_constraints:
                                test_solver.add(constraint)
                            
                            if test_solver.satisfiable():
                                # They can have the same input, check outputs
                                output1 = s1.posix.dumps(1)
                                output2 = s2.posix.dumps(1)
                                
                                if output1 != output2:
                                    print("[+] Found potential regression!")
                                    
                                    # Get concrete values
                                    concrete_args = []
                                    for arg in symbolic_args:
                                        val = s1.solver.eval(arg, cast_to=bytes).strip(b"\x00")
                                        concrete_args.append(val)
                                    
                                    concrete_args_str = [arg.decode("utf-8", errors="ignore") for arg in concrete_args]
                                    
                                    print(f"Args: {concrete_args_str}")
                                    print(f"v1 output: {output1}")
                                    print(f"v2 output: {output2}")
                                    
                                    # Write to regressing.txt
                                    with open("regressing.txt", "wb") as f:
                                        f.write(b" ".join(concrete_args))
                                    
                                    return
                    except:
                        continue
    
    # If differential didn't work, try the original approach but with more exploration
    print("Trying broader exploration of version1...")
    
    # Reset and try different exploration
    state1 = proj1.factory.full_init_state(args=argv)
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    
    for arg in symbolic_args:
        chars = arg.chop(8)[:-1]
        for byte in chars:
            state1.solver.add(byte >= 0x20, byte <= 0x7e)
    
    sm1 = proj1.factory.simulation_manager(state1)
    
    # Try different exploration strategies
    print("Using BFS exploration...")
    sm1.use_technique(angr.exploration_techniques.Explorer(find=lambda s: True, num_find=20))
    
    try:
        sm1.run(until=lambda sm: len(sm.found) >= 10 or len(sm.active) == 0)
        states_to_check = sm1.found + sm1.deadended
    except:
        states_to_check = sm1.deadended
    
    print(f"Found {len(states_to_check)} states to check")
    
    # Check each state
    for i, s1 in enumerate(states_to_check[:15]):  # Limit to first 15
        try:
            output1 = s1.posix.dumps(1)
            
            # Get concrete args
            concrete_args = []
            for arg in symbolic_args:
                val = s1.solver.eval(arg, cast_to=bytes).strip(b"\x00")
                concrete_args.append(val)
            
            concrete_args_str = [arg.decode("utf-8", errors="ignore") for arg in concrete_args]
            
            print(f"Testing state {i+1}: {concrete_args_str}")
            
            # Test with version2
            state2 = proj2.factory.full_init_state(args=['binary'] + concrete_args_str)
            state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            
            sm2 = proj2.factory.simulation_manager(state2)
            sm2.run()
            
            for s2 in sm2.deadended:
                output2 = s2.posix.dumps(1)
                
                print(f"  v1: {repr(output1)}")
                print(f"  v2: {repr(output2)}")
                
                if output1 != output2:
                    print("[+] Found regression!")
                    
                    with open("regressing.txt", "wb") as f:
                        f.write(b" ".join(concrete_args))
                    
                    return
        except Exception as e:
            print(f"Error with state {i}: {e}")
            continue

    print("[-] No regression found.")

if __name__ == "__main__":
    main()
