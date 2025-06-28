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
    
    # Add memory safety options
    state1.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state1.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    
    # Constrain all characters to printable ASCII
    for arg in symbolic_args:
        for byte in arg.chop(8)[:-1]:  # Skip null terminator
            state1.solver.add(byte >= 0x20)
            state1.solver.add(byte <= 0x7e)

    sm1 = proj1.factory.simulation_manager(state1)
    
    # CRITICAL: Limit exploration to prevent memory explosion
    max_states = 50  # Limit total states to prevent memory issues
    max_steps = 1000  # Limit execution steps
    
    print("Starting symbolic execution of version1...")
    try:
        # Use explore with limits instead of run()
        sm1.explore(
            num_find=max_states,  # Stop after finding this many paths
            step_func=lambda sm: sm if len(sm.active) + len(sm.deadended) < max_states else sm.prune()
        )
        
        # Alternative: step with limits
        step_count = 0
        while sm1.active and step_count < max_steps and len(sm1.active) + len(sm1.deadended) < max_states:
            sm1.step()
            step_count += 1
            
            # Prune states periodically to manage memory
            if step_count % 100 == 0:
                print(f"Step {step_count}: Active={len(sm1.active)}, Deadended={len(sm1.deadended)}")
                if len(sm1.active) > 20:  # Too many active states
                    # Keep only first 10 active states
                    sm1.active = sm1.active[:10]
                    print("Pruned active states to manage memory")
        
    except Exception as e:
        print(f"Error during symbolic execution: {e}")
        return

    print(f"Symbolic execution complete. Deadended states: {len(sm1.deadended)}")
    
    if not sm1.deadended:
        print("[-] No deadended states found in version1")
        return

    # Create project for version2 once (reuse it)
    proj2 = angr.Project(binary2, auto_load_libs=False)
    
    # Check outputs of deadended paths in version1
    found_regression = False
    checked_count = 0
    max_checks = 20  # Limit how many states we check to prevent infinite loops
    
    for i, s1 in enumerate(sm1.deadended[:max_checks]):  # Limit states checked
        try:
            print(f"Checking deadended state {i+1}/{min(len(sm1.deadended), max_checks)}")
            
            # Get output from version1
            output1 = s1.posix.dumps(1)
            
            # Concretize arguments
            concrete_args = []
            for j, arg in enumerate(symbolic_args):
                try:
                    concrete_val = s1.solver.eval(arg, cast_to=bytes).strip(b"\x00")
                    concrete_str = concrete_val.decode("utf-8", errors="ignore")
                    concrete_args.append(concrete_str)
                except Exception as e:
                    print(f"Error concretizing arg {j}: {e}")
                    concrete_args.append("")  # Use empty string as fallback
            
            print(f"Testing args: {concrete_args}")
            
            # Re-execute version2 concretely with same args
            try:
                state2 = proj2.factory.full_init_state(args=['binary'] + concrete_args)
                state2.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
                
                sm2 = proj2.factory.simulation_manager(state2)
                
                # Run version2 with timeout and step limit
                step_count2 = 0
                max_steps2 = 500
                
                while sm2.active and step_count2 < max_steps2:
                    sm2.step()
                    step_count2 += 1
                
                # Check if version2 completed normally
                if not sm2.deadended:
                    print(f"  Version2 didn't complete normally (active: {len(sm2.active)}, errored: {len(sm2.errored)})")
                    continue
                
                # Compare outputs
                for s2 in sm2.deadended:
                    output2 = s2.posix.dumps(1)
                    
                    print(f"  v1 output: {repr(output1)}")
                    print(f"  v2 output: {repr(output2)}")
                    
                    if output1 != output2:
                        print("[+] Found regression!")
                        print(f"Arguments: {concrete_args}")
                        print(f"version1 output: {output1}")
                        print(f"version2 output: {output2}")
                        
                        # Write to regressing.txt
                        with open("regressing.txt", "w") as f:
                            f.write(" ".join(concrete_args))
                        
                        print("[+] Saved input to regressing.txt")
                        found_regression = True
                        break
                
                if found_regression:
                    break
                    
            except Exception as e:
                print(f"Error executing version2 with args {concrete_args}: {e}")
                continue
            
            checked_count += 1
            
        except Exception as e:
            print(f"Error processing deadended state {i}: {e}")
            continue
    
    if not found_regression:
        print(f"[-] No regression found after checking {checked_count} states")

if __name__ == "__main__":
    main()
