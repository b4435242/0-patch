import argparse

import proc_addr

''' API '''
def parse_params():
    args = parse_arg()
    binary = args.binary
    port = args.port
    dynamic_base = proc_addr.get_text_dynamic_base(pid=args.pid, binary=binary)
    commands = Commands(args.command, args.pid, binary, dynamic_base)
    return binary, commands.ctrl_bucket, commands.data_bucket, port, dynamic_base

'''Util'''

CTRL_COMMANDS = ["breakpoint", "target"]
DATA_COMMANDS = ["sp"]
class Commands:
    def __init__(self, command_path, bin_pid, binary, dynamic_base):
        self.ctrl_bucket = {
            CTRL_COMMANDS[0] : [], # addr
            CTRL_COMMANDS[1] : [], # addr
        }
        self.data_bucket = {
            DATA_COMMANDS[0] : [] # dict : { n_pointer, sp_offsets, val_offsets, size }
        }
        self.dynamic_base = dynamic_base
        self.command_path = command_path
        self.parse_file()

    def add_ctrl(self, cmd, addr):
        addr = int(addr, 16)
        addr += self.dynamic_base # pie
        self.ctrl_bucket[cmd].append(addr)
    
    def add_data(self, cmd, n_pointer, offsets, size):
        n_pointer = int(n_pointer)
        sp_offsets = [int(sp_offset, 16) for sp_offset in offsets]
        size = int(size, 16)
        data = {"n_pointer": n_pointer, "sp_offsets": sp_offsets, "size": size}
        self.data_bucket[cmd].append(data)

    def parse_file(self): # support parsing only one set of breakpoint-target
        
        f = open(self.command_path)
        for line in f.readlines():
            splits = line.split()
            cmd = splits[0]
            if cmd in CTRL_COMMANDS:
                addr = splits[1]
                self.add_ctrl(cmd, addr)
            else:
                if cmd==DATA_COMMANDS[0]:
                    n_pointer = int(splits[1])
                    size = splits[2]
                    #len_offsets = n_pointer + 1# no pointer -> data on stack -> offset 1
                    #offsets = [splits[i] for i in range(3, 2*len_offsets+3, 2)]
                    offsets = [splits[3]]
                    self.add_data(cmd, n_pointer, offsets, size)
        f.close()
        

def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", dest="binary")
    parser.add_argument("--cmd", dest="command")
    parser.add_argument("--port", dest="port")
    parser.add_argument("--pid", dest="pid")

    args = parser.parse_args()
    return args


