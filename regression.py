import angr
import claripy

MAX_ARG_LEN = 8
NUM_ARGS = 5

def symbolic_args():
    args = []
    for i in range(NUM_ARGS):
        arg = claripy.BVS(f'arg{i}', MAX_ARG_LEN * 8)  # 8 bits per char
        args.append(arg)
    return args

def create_state(proj, sym_args):
    # Construct argv with filename as first arg, then symbolic args
    argv = [proj.filename]
    for arg in sym_args:
        # Add null terminator for each string and limit length to MAX_ARG_LEN
        argv.append(arg)
    state = proj.factory.full_init_state(args=argv)

    # Constrain symbolic arguments to be printable and null-terminated within 8 bytes
    for arg in sym_args:
        for i in range(MAX_ARG_LEN):
            c = arg.get_byte(i)
            state.solver.add(c >= 0x20)
            state.solver.add(c <= 0x7e)
    return state

def get_terminated_states(proj, sym_args):
    state = create_state(proj, sym_args)
    simgr = proj.factory.simgr(state)
    simgr.run()
    return simgr.deadended

def main():
    proj1 = angr.Project('bin/version1', auto_load_libs=False)
    proj2 = angr.Project('bin/version2', auto_load_libs=False)

    sym_args = symbolic_args()

    states_v1 = get_terminated_states(proj1, sym_args)
    states_v2 = get_terminated_states(proj2, sym_args)

    for s1 in states_v1:
        for s2 in states_v2:
            # Check for diverging behavior - here: different exit codes
            if s1.solver.satisfiable(extra_constraints=[s1.regs.eax != s2.regs.eax]):
                m = s1.solver.min
                with open("regressing.txt", "w") as f:
                    for arg in sym_args:
                        val = m(s1.solver.eval(arg, cast_to=bytes).rstrip(b'\x00'))
                        f.write(val.decode('utf-8', errors='ignore') + " ")
                    f.write("\n")
                print("Regression found! Inputs written to regressing.txt")
                return
    print("No regression found.")

if __name__ == '__main__':
    main()
