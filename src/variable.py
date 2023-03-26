import angr
import claripy
import archinfo

class SymVar:

    def __init__(self, data_bucket, state: angr.SimState):
        self.vars = {} # dict {addr: {size, var}}
        self.state = state
        self.data_bucket = data_bucket
        self.parse_var()
        self.store_vars_to_mem()

    def add_size_to_vars(self, addr, size):
        self.vars[addr] = {}
        self.vars[addr]["size"] = size

    def add_var_to_vars(self, addr, var):
        self.vars[addr]["var"] = var

    def parse_var(self):
        # case of pointer or data is on stack
        for data in self.data_bucket["sp"]:

            n_pointer = data["n_pointer"]
            sp_offsets = data["sp_offsets"]
            #val_offsets = data["val_offsets"]
            size = data["size"]

            addr = self.state.regs.rbp-sp_offsets[0] 
            addr = self.state.solver.eval(addr)

            # 
            for _ in range(n_pointer):
                addr = self.state.memory.load(addr, 8, endness=archinfo.Endness.LE)
                addr = self.state.solver.eval(addr)
                #val_offset = self.state.mem[sp_offsets[i]].uint64_t
                #addr += val_offset
                #addr += val_offsets[i]
            print("sym var addr = %x" % addr)
            self.add_size_to_vars(addr, size)


    def store_vars_to_mem(self):
        for addr, dict in self.vars.items():
            size = dict["size"]
            var = claripy.BVS(str(addr), size) # take name as addr
            self.state.memory.store(addr, var) # setup symbolic variable
            self.add_var_to_vars(addr, var)
            

    def sync_to_monitored(self, state: angr.SimState, proj):
        for addr, dict in self.vars.items():
            var = dict["var"]
            val = state.solver.eval(var, cast_to=bytes) # solve AST to bytes
            addr = state.solver.eval(addr) # convert from BVV to Python int
            proj.concrete_target.write_memory(addr, val)
            print("ans val=%s, addr =%x"%(val.decode(), addr))
            exit(0)