"""
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

"""

import angr
import claripy
import sys
import os
import logging
import argparse
import networkx as nx
import time  # <-- Added for timing

# Suppress debug logs from angr and claripy for cleaner output
logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)

def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="angr symbolic execution with register monitoring.")
    parser.add_argument("binary", help="Path to the binary")
    parser.add_argument("ret_addr", type=lambda x: int(x, 16), help="Return address to hook (hex)")
    parser.add_argument("mode", choices=["argv", "stdin"], help="Input mode: 'argv' or 'stdin'")
    parser.add_argument("max_len", type=int, nargs="?", help="Max input length (for brute-force mode)")
    parser.add_argument("-e", type=int, help="Exact input length (disables brute-force)")
    parser.add_argument("-r", "--registers", help="Comma-separated list of registers to monitor")
    parser.add_argument("-addr", "--address", type=lambda x: int(x, 16), help="Address to display register values")
    parser.add_argument("--cfg", action="store_true", help="Generate colored CFG if a match is found")

    args = parser.parse_args()

    # Extract arguments into local variables
    binary_path = args.binary
    ret_addr = args.ret_addr
    mode = args.mode
    exact_mode = args.e is not None
    input_lengths = [args.e] if exact_mode else range(1, args.max_len + 1)
    max_len = args.e if exact_mode else args.max_len
    reg_list = args.registers.split(",") if args.registers else []
    watch_addr = args.address

    # Check if the binary exists
    if not os.path.isfile(binary_path):
        print(f"[!] File not found: {binary_path}")
        return

    # Print execution settings
    print(f"\n[+] Binary            : {os.path.basename(binary_path)}")
    print(f"[+] Hooking return at : 0x{ret_addr:x}")
    print(f"[+] Input Mode        : {mode}")
    print(f"[+] Exact Length Mode : {exact_mode}")
    print(f"[+] Max/Exact Length  : {max_len}")
    if reg_list:
        print(f"[+] Monitoring Regs   : {reg_list}")
    if watch_addr:
        print(f"[+] Register Watch At : 0x{watch_addr:x}")

    # Load the binary into an angr project
    project = angr.Project(binary_path, auto_load_libs=False)
    arch = project.arch.name
    ret_reg = 'rax' if '64' in arch else 'eax'  # Choose return register based on architecture
    print(f"[+] Architecture      : {arch}\n")

    matched_path_addrs = []
    matched_watch_hits = []
    found = False

    # Record the start time
    start_time = time.time()

    # Try different input lengths until we find a solution
    for input_len in input_lengths:
        print(f"[>] Trying length {input_len}: ", end='', flush=True)

        # ----------- Create a symbolic state with symbolic input -----------
        if mode == 'argv':
            # Create a symbolic variable for argv input
            sym_arg = claripy.BVS("arg", input_len * 8)
            args_list = [binary_path, sym_arg]
            state = project.factory.full_init_state(args=args_list)
            state.globals['solution'] = sym_arg
        else:
            # Create symbolic stdin input (byte by byte)
            input_bytes = [claripy.BVS(f'c{i}', 8) for i in range(input_len)]
            input_str = claripy.Concat(*input_bytes + [claripy.BVV(0, 8)])  # null-terminate
            stdin = angr.SimFileStream(name='stdin', content=input_str, has_end=False)
            state = project.factory.full_init_state(stdin=stdin)
            state.globals['solution'] = state.posix.stdin.load(0, input_len)

        # Add constraints to restrict input to printable ASCII characters
        for b in range(input_len):
            byte = state.globals['solution'].get_byte(b)
            state.solver.add(byte >= 0x20, byte <= 0x7e)  # ASCII space to tilde

        # Fill unknown memory with zeroes
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)

        # Prepare to track path and register accesses
        state.globals['path_addrs'] = []
        state.globals['watch_hits'] = []

        # ---------- Define a hook at return address ----------
        # If return register == 1, this is a success condition
        def hook_ret(s):
            reg = getattr(s.regs, ret_reg)
            if s.solver.satisfiable(extra_constraints=[reg == 1]):
                s.add_constraints(reg == 1)  # force this condition true
                s.globals['found'] = True    # mark this state as successful

        # ---------- Optional: hook to monitor registers at a specific address ----------
        if watch_addr:
            def watch_hook(s):
                reg_values = {}
                for r in reg_list:
                    try:
                        # Read value from register
                        reg_expr = getattr(s.regs, r)
                        reg_bits = reg_expr.size()
                        val = s.solver.eval(reg_expr, cast_to=int)
                        reg_hex = f"0x{val:0{reg_bits // 4}x}"
                        deref = "<n/a>"

                        # Try to read memory pointed to by that register
                        try:
                            preview_len = 16
                            mem_val = s.memory.load(val, preview_len, endness=project.arch.memory_endness)
                            mem_concrete = s.solver.eval(mem_val, cast_to=bytes)
                            ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in mem_concrete)
                            deref = f"{mem_concrete.hex()} ('{ascii_preview}')"
                        except:
                            deref = "<unreadable>"

                        reg_values[r] = f"{reg_hex} → {deref}"
                    except:
                        reg_values[r] = "<unresolved>"

                s.globals['watch_hits'].append((s.addr, reg_values))

            # Install the register watch hook
            project.hook(watch_addr, watch_hook)

        # Hook the return address to detect valid states
        project.unhook(ret_addr)
        project.hook(ret_addr, hook_ret)

        # Create simulation manager and start symbolic execution
        simgr = project.factory.simgr(state)

        # Track path addresses (for later CFG generation)
        def step_callback(sm):
            for s in sm.active:
                s.globals['path_addrs'].append(s.addr)

        simgr.run(step_func=step_callback)

        # Look through all finished (deadended) states
        for s in simgr.deadended:
            if s.globals.get('found'):
                try:
                    # Extract input that caused the condition (ret_reg == 1)
                    key = s.solver.eval(s.globals['solution'], cast_to=bytes).rstrip(b"\x00")
                    key_str = key.decode('utf-8', errors='ignore')
                    print("✓ Match found\n")
                    print(f"    [✓] Key       : {key_str}")
                    print(f"    [✓] Condition : {ret_reg} == 1")

                    # If we had register watchpoints, show them
                    if s.globals.get("watch_hits"):
                        print("\n[~] Watchpoint log:")
                        for addr, reg_vals in s.globals["watch_hits"]:
                            print(f"    Hit at 0x{addr:x}:")
                            for reg, val in reg_vals.items():
                                print(f"        {reg} = {val}")

                    matched_path_addrs = s.globals['path_addrs']
                    matched_watch_hits = s.globals.get('watch_hits', [])
                    found = True
                    break
                except Exception:
                    continue

        # If we found a valid key, stop checking further lengths
        if found:
            break
        else:
            print("✘ No match")

    # Record end time
    end_time = time.time()
    elapsed = end_time - start_time

    # If no input satisfied the condition, report it
    if not found:
        print("\n[!] No valid key found.")
    else:
        print(f"\n[✓] Time elapsed: {elapsed:.2f} seconds "
              f"({elapsed / 60:.2f} min, {elapsed / 3600:.2f} hr)")

    # ------- Optional: Generate Control Flow Graph (CFG) --------
    if found and args.cfg:
        print("\n[*] Generating colored CFG with mnemonics...")
        g = nx.DiGraph()

        for i in range(len(matched_path_addrs)):
            addr = matched_path_addrs[i]
            block = project.factory.block(addr)
            disasm = block.capstone
            mnemonic_lines = [f"{ins.mnemonic} {ins.op_str}" for ins in disasm.insns]
            label = f"0x{addr:x}\\n" + "\\n".join(mnemonic_lines)
            label = f'"{label}"'

            node_attrs = {
                "label": label,
                "shape": "box",
                "style": "filled",
                "fillcolor": "white"
            }

            # Color first and last nodes
            if i == 0:
                node_attrs["fillcolor"] = "palegreen"
            elif i == len(matched_path_addrs) - 1:
                node_attrs["fillcolor"] = "indianred1"

            g.add_node(f"0x{addr:x}", **node_attrs)

            if i < len(matched_path_addrs) - 1:
                g.add_edge(f"0x{addr:x}", f"0x{matched_path_addrs[i + 1]:x}")

        dot_path = os.path.basename(binary_path) + "_matched_colored.dot"
        png_path = os.path.basename(binary_path) + "_matched_colored.png"

        try:
            from networkx.drawing.nx_pydot import write_dot
            write_dot(g, dot_path)
            os.system(f"dot -Tpng {dot_path} -o {png_path}")
            print(f"[✓] Colored CFG saved to: {png_path}")
        except Exception as e:
            print(f"[!] Failed to generate CFG: {e}")

    print("\n")

# Run the main function when this script is executed
if __name__ == "__main__":
    main()