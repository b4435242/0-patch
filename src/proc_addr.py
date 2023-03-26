import subprocess

maps_fields = ["address", "perms", "offset", "dev", "inode", "pathname"]


def get_text_dynamic_base(pid, binary):
    print(pid)
    ret = subprocess.run(["sudo", "cat", "/proc/%s/maps"%pid], stdout=subprocess.PIPE)
    mappings = ret.stdout.decode("utf-8")
    mappings = mappings.split("\n")
    for m in mappings:
        if len(m)==0:
            continue
        # parse string to dict
        values = m.split(" ")
        values = [v for v in values if len(v)>0]
        if len(values)!=len(maps_fields):
            continue
        map = {}
        for i, f in enumerate(maps_fields): 
            map[f] = values[i]


        # filter
        pathname = map["pathname"]
        permissions = map["perms"]
        offset = map["offset"]
        print("%s %s "%(binary, pathname))

        if binary in pathname and "x" in permissions:
            base = map["address"].split("-")[0]
            base = int(base, 16)
            offset = int(offset, 16)
            #print(map)
            print("base = %x" %(base))
            return base - offset


