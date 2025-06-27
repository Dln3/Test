#!/usr/bin/env python3
import angr
import claripy

BIN1 = "bin/version1"
BIN2 = "bin/version2"
NUM_ARGS = 5
MAX_LEN = 8

def make_symbolic_args():
    args = []
    for i in range(NUM_ARGS):
        chars = [claripy.BVS(f"arg{i}_{j}", 8) for j in range(MAX_LEN)]
        arg = claripy.Concat(*chars, claripy.BVV(0, 8))
        args.append(arg)
    return args

def instrument_printf(state, tag):
    out_data = []
    @state.inspect.b('syscall', when=angr.BP_AFTER)
    def catch_write(state2):
        if state2.inspect.syscall_name == "write" and state2.inspect.syscall_arg(0) == 1:
            data = state2.mem[state2.inspect.syscall_arg(1)].string.concrete
            out_data.append(data)
    state.globals[tag] = out_data

def main():
    sym_args = make_symbolic_args()
    argv = ["prog"] + sym_args

    proj1 = angr.Project(BIN1, auto_load_libs=False)
    proj2 = angr.Project(BIN2, auto_load_libs=False)

    s1 = proj1.factory.full_init_state(args=argv)
    s2 = proj2.factory.full_init_state(args=argv)

    for st in (s1, s2):
        st.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        for arg in sym_args:
            for byte in arg.chop(8):
                st.solver.add(byte >= 0x20, byte <= 0x7e)

    instrument_printf(s1, "out1")
    instrument_printf(s2, "out2")

    simgr1 = proj1.factory.simulation_manager(s1)
    simgr2 = proj2.factory.simulation_manager(s2)

    # Run side-by-side until one diverges or ends
    for _ in range(200):
        if not simgr1.active or not simgr2.active:
            break
        simgr1.step()
        simgr2.step()

        for st1 in simgr1.active:
            for st2 in simgr2.active:
                o1 = b"".join(st1.globals["out1"])
                o2 = b"".join(st2.globals["out2"])
                if st1.solver.satisfiable(extra_constraints=[o1 != o2]):
                    print("[+] Found divergence in printed output!")
                    args = []
                    for arg in sym_args:
                        v = st1.solver.eval(arg, cast_to=bytes).split(b'\x00')[0]
                        args.append(v)
                    with open("regressing.txt", "wb") as f:
                        f.write(b" ".join(args))
                    print("[+] Arguments saved in regressing.txt")
                    print("version1 printed:", o1)
                    print("version2 printed:", o2)
                    return

    print("[-] No divergence found.")

if __name__ == "__main__":
    main()
