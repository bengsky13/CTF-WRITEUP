import angr
import claripy

target_addr = 0x00101a34
fail_addr = 0x00101acd
base_addr = 0x00100000

p = angr.Project("./chall", main_opts = {"base_addr": base_addr})
pass_char = [claripy.BVS(f'aa{i}', 8) for i in range(32)]
passphrase = claripy.Concat(*pass_char + [claripy.BVV(b"\n")])
state = p.factory.full_init_state(
    args= ["./chall"],
    add_options = angr.options.unicorn,
    stdin=passphrase
)

sim_manager = p.factory.simulation_manager(state)
sim_manager.explore(find = target_addr, avoid=fail_addr)

if len(sim_manager.found) > 0:
    for found in sim_manager.found:
        print(found.posix.dumps(0))