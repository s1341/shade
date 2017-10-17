import struct
import copy
import math

peda = PEDA()


def execute_output(command):

    # create temporary file for the output
    filename = os.getenv('HOME') + os.sep + 'gdb_output_' + str(os.getpid())

    # set gdb logging
    gdb.execute("set logging file " + filename)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging on")

    # execute command
    try:
        gdb.execute(command)
    except:
        pass

    # restore normal gdb behaviour
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")

    # read output and close temporary file
    outfile = open(filename, 'r')
    output = outfile.read()
    outfile.close()

    # delete file
    os.remove(filename)

    # split lines
    output = output.splitlines()

    return output

def parse_disassembled_output(output, regex=''):

    instructions = dict()

    # parse output
    for line in output:

        # delete program counter mark
        line = line.replace('=>', '  ')

        # get only instruction lines
        if line.startswith(' '):
            field = re.compile('\s+').split(line)

            # parse
            if field[1].endswith(':'):
                addr = int(field[1].replace(':',''), 16)
                code = ' '.join(field[2:])
            else:
                addr = int(field[1], 16)
                code = ' '.join(field[3:])

            # apply regex
            if regex != '':
                if not re.search(regex, code):
                    continue

            # add to instructions
            instructions[addr] = code

    return instructions

def ascii_table(tuples_list, header=True):
    # find the bigger tuple in the list
    max_len = max(len(t) for t in tuples_list)

    # find out the max len of each column element
    max_element_len = [0] * max_len
    for i in range(0, max_len):
        # str(t[i]) gets the wrong length of DMLStrings
        # values = (str(t[i]) for t in tuples_list)
        values = (str(t[i]) for t in tuples_list)
        max_element_len[i] = max(len(v) for v in values)

    list_body = tuples_list

    out = ""

    # table header
    if header is True:
        list_body = tuples_list[1:]
        line_len = 0
        header_tuple = tuples_list[0]
        for i in range(0, len(header_tuple)):
            if i == 0:
                spacing = 0
            else:
                spacing = 4
            align = (max_element_len[i] - len(str(header_tuple[i])))
            out += " " * spacing + str(header_tuple[i]) + " " * align
    out += "\n"

    # print header seperator line
    line_len = sum(l + 4 for l in max_element_len)
    out += "-" * line_len
    out += "\n"

    # print the rest of the table
    for t in list_body:
        for i in range(0, len(t)):
            if i == 0:
                spacing = 0
            else:
                spacing = 4
            # align = (max_element_len[i] - len(str(t[i])))
            align = max_element_len[i] - len(str(t[i]))
            out +=  " " * spacing
            out += str(t[i])
            out += " " * align
        out += "\n"

    return out
def readmem(address, length):
    return gdb.selected_inferior().read_memory(address, length)

def read32(address):
    return struct.unpack("I", readmem(address, 4))[0]

def rshift(val, n):
    return (val % 0x100000000) >> n

NSMALLBINS = 32
NTREEBINS = 32

PINUSE_BIT = 0x1
CINUSE_BIT = 0x2
FLAG4_BIT = 0x4
FLAG_BITS = PINUSE_BIT | CINUSE_BIT | FLAG4_BIT
INUSE_BITS = PINUSE_BIT | CINUSE_BIT

SMALLBIN_SHIFT = 3
TREEBIN_SHIFT = 8
MIN_LARGE_SIZE = 1 << TREEBIN_SHIFT
MAX_SMALL_SIZE = MIN_LARGE_SIZE - 1

MALLOC_ALIGNMENT = 2 * 4
CHUNK_OVERHEAD = 4
CHUNK_ALIGN_MASK = MALLOC_ALIGNMENT - 1
MIN_CHUNK_SIZE = (4 * 4 + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK
MIN_REQUEST = MIN_CHUNK_SIZE - CHUNK_OVERHEAD - 1
MAX_REQUEST = ((-MIN_CHUNK_SIZE) << 2) & 0xffffffff

class Segment:
    def __init__(self, addr):
        self.addr = addr
        self.parse()

    def parse(self):
        self.base, self.size, self.next, self.sflags = struct.unpack("IIII", readmem(self.addr,
                                                                                4 * 4))

    def __repr__(self):
        return "0x%08x - 0x%08x [%08x]" % (self.base, self.base + self.size, self.sflags)

class ChunkRegistry:
    def __init__(self):
        self.chunks = {}

    def get(self, addr, size=0, as_tree_chunk=False, do_parse=True):
        if not addr in self.chunks:
            if as_tree_chunk:
                self.chunks[addr] = TreeBinChunk(self, addr, size)
            else:
                self.chunks[addr] = Chunk(self, addr, size)

        if as_tree_chunk and not isinstance(self.chunks[addr], TreeBinChunk):
            prev_chunk = self.chunks[addr]
            self.chunks[addr] = TreeBinChunk(self, addr, prev_chunk.size |
                                             prev_chunk.flags)
            self.chunks[addr].parent = self.chunks[addr].left_child = self.chunks[addr].right_child = None
            self.chunks[addr].from_dv = prev_chunk.from_dv
            self.chunks[addr].from_top = prev_chunk.from_top
            self.chunks[addr].from_larger_chunk = prev_chunk.from_larger_chunk

        if do_parse:
            self.chunks[addr].parse()
        else:
            self.chunks[addr].fd = self.chunks[addr].bk = addr


        return self.chunks[addr]

    def create_temp(self, addr, size, from_dv=False, from_top=False,
                    from_larger_chunk=False, new_dv=False):
        assert(addr not in self.chunks)
        chunk = Chunk(self, addr, size)
        chunk.from_dv = from_dv
        chunk.from_top = from_top
        chunk.from_larger_chunk = from_larger_chunk
        chunk.new_dv = new_dv
        return chunk

class Chunk(object):
    def __init__(self, registry, addr, size=0):
        self.registry = registry
        self.addr = addr
        self.data_addr = addr + 8
        self.size = size & ~FLAG_BITS
        self.flags = size & FLAG_BITS
        self.from_dv = False
        self.from_top = False
        self.from_larger_chunk = False
        self.new_dv = False

    def parse(self):
        self.prev_size, size, self.fd, self.bk = struct.unpack("IIII", readmem(self.addr,
                                                                               4 * 4))

        self.flags = size & FLAG_BITS
        self.size = size & ~FLAG_BITS

    def next_chunk(self):
        return chunk_registry.get(self.addr + self.size)

    def is_free(self):
        return (self.flags & CINUSE_BIT) == 0

    def get_status(self):
        status = ""
        if self.is_free():
            status = "free"
        else:
            status = "in use"
        if self.from_dv:
            status += " (from dv)"
        elif self.from_top:
            status += " (from top)"
        elif self.from_larger_chunk:
            status += " (from larger)"
        return status

    def is_mmaped(self):
        return (self.flags & INUSE_BITS) == 0

    def as_tree_chunk(self):
        new = self.registry.get(self.addr, self.size,  as_tree_chunk=True, do_parse=False)
        new.parent = new.left_child = new.right_child = None
        new.siblings = []
        return new

class SmallBin:
    def __init__(self, index, bin_header_addr, smallmap):
        self.index = index
        self.bin_header_addr = bin_header_addr
        self.smallmap = smallmap
        self.chunks = []
        self.size = self.index << SMALLBIN_SHIFT

    def parse(self):
        # based on dlmalloc, unlink_first_small_chunk
        b = self.bin_header_addr
        p = chunk_registry.get(b).fd
        while ((self.smallmap >> self.index) & 1) != 0:
            current_chunk = chunk_registry.get(p)
            f = current_chunk.fd
            assert (p != b)
            assert (p != f)
            self.chunks.append(current_chunk)
            if b == f:
                break
            p = f

    def __deepcopy__(self, memodict):
        new = SmallBin(self.index, self.bin_header_addr, self.smallmap)
        new.chunks = self.chunks[:]
        return new

class TreeBinChunk(Chunk):
    def __init__(self, registry, addr, size=0):
        super(TreeBinChunk, self).__init__(registry, addr, size)

    def parse(self):
        super(TreeBinChunk, self).parse()

        self.left_child_addr, self.right_child_addr, self.parent_addr, self.bin_index = \
            struct.unpack("IIII", readmem(self.addr + 4 * 4, 4 * 4))

    def build_tree(self, registry, bin_addr=0, recursive=True):
        self.siblings = [self]
        current_address = self.bk
        while current_address != self.addr:
            chunk = registry.get(current_address)
            self.siblings.append(chunk)
            current_address = chunk.bk

        self.left_child = self.right_child = self.parent = None
        if self.left_child_addr != 0:
            self.left_child = registry.get(self.left_child_addr,
                                           as_tree_chunk=True)
            self.left_child.parse()
            if recursive:
                self.left_child.build_tree(registry)
        if self.right_child_addr != 0:
            self.right_child = registry.get(self.right_child_addr,
                                            as_tree_chunk=True)
            self.right_child.parse()
            if recursive:
                self.right_child.build_tree(registry)
        if self.parent_addr != 0 and self.parent_addr != bin_addr:
            self.parent = registry.get(self.parent_addr,
                                       as_tree_chunk=True)
            self.parent.parse()
            if recursive:
                self.parent.build_tree(registry, recursive=False)

    def leftmost_child(self):
        if self.left_child:
            return self.left_child
        return self.right_child

    def get_children(self):
        children = []
        # first chunks smaller than us
        if self.left_child:
            children.extend(self.left_child.get_children())

        # our chunk
        children.append(self)

        # chunks of the same size
        current_address = self.fd
        while current_address != self.addr:
            current_chunk = chunk_registry.get(current_address)
            children.append(current_chunk)
            current_address = current_chunk.fd

        # lastly, chunks bigger than us
        if self.right_child:
            children.extend(self.right_child.get_children())

        return children


class TreeBin:
    def __init__(self, index, addr, root_addr):
        self.index = index
        self.addr = addr
        self.root_addr = root_addr

        self.min_size = (1 << ((self.index >> 1) + TREEBIN_SHIFT)) | \
            ((self.index & 1) << ((self.index >> 1) + TREEBIN_SHIFT - 1))

        self.max_size = (1 << (((self.index + 1) >> 1) + TREEBIN_SHIFT)) | \
            (((self.index + 1) & 1) << (((self.index + 1) >> 1) + TREEBIN_SHIFT - 1))

    def parse(self):
        if self.root_addr == 0x0:
            self.root = None
            self.chunks = []
            return

        self.root = chunk_registry.get(self.root_addr, as_tree_chunk=True)
        self.root.parse()
        self.root.build_tree(chunk_registry, bin_addr=self.addr)
        #assert(self.root.parent.addr == self.addr)

        self.chunks = self.root.get_children()

    def __deepcopy__(self, memodict):
        new = TreeBin(self.index, self.addr, self.root_addr)
        new.chunk_registry = ChunkRegistry()


        if new.root_addr != 0x0:
            new.root = new.chunk_registry.get(new.root_addr, as_tree_chunk=True)
            new.root.parse()
            new.root.build_tree(new.chunk_registry, bin_addr=self.addr)
        else:
            new.root = None
        return new

class MallocParams:
    def __init__(self):
        disassm = parse_disassembled_output(execute_output("disassemble dlmalloc,+16"))
        offset = -1
        self.addr = -1
        for addr in sorted(disassm.keys()):
            if offset != -1 and self.addr != -1:
                break
            if disassm[addr].startswith("ldr.w"):
                m = re.search("#([0-9]+)", disassm[addr])
                offset = m.group(1)
                offset = read32(addr + 4 + int(offset))
            if disassm[addr] == "add r3, pc":
                self.addr = addr + 4 + offset

        self.parse()

    def parse(self):
        self.magic, self.page_size, self.granularity, self.mmap_threshold, \
        self.trim_threshold, self.default_mflags = \
            struct.unpack("IIIIII", readmem(self.addr, 6 * 4))

class MallocState:
    def __init__(self):
        self.malloc_params = MallocParams()

        # find the libc's data segment
        libc_segments = peda.get_vmmap()
        start_addr = end_addr = -1
        found_libc = False
        for segment in libc_segments:
            if segment[3].endswith("libc.so"):
                found_libc = True
            if found_libc and segment[2] == "rw-p" and segment[3] == "mapped":
                start_addr, end_addr = segment[:2]
                break

        # find the magic in the libc data segment
        magic_str = ''.join(map(lambda c:'\\x%02x' % c, map(ord, struct.pack("I",
                                                                             self.malloc_params.magic))))
        locations = peda.searchmem(start_addr, end_addr, magic_str)
        for addr, match in locations:
            if addr != self.malloc_params.addr:
                break
        self.addr = addr - (9 * 4)

        self.parse()

    def parse(self):
        self.smallmap, self.treemap, self.dvsize, self.topsize, self.least_addr, self.dv, \
            self.top, self.trim_check, self.release_checks, self.magic = \
        struct.unpack("IIIIIIIIII", readmem(self.addr, 10 * 4))

        offset = 10 * 4
        self.smallbins = {}
        for i in range(NSMALLBINS):
            smallbin = SmallBin(i, self.addr + offset, self.smallmap)
            smallbin.parse()
            self.smallbins[i] = smallbin
            offset += 8

        offset += 8
        self.treebins = {}
        for i in range(NTREEBINS):
            self.treebins[i] = TreeBin(i, self.addr + offset + i * 4, read32(self.addr + offset + i * 4))
            self.treebins[i].parse()

        offset += NTREEBINS * 4
        self.footprint, self.max_footprint, self.footprint_limit, self.mflags = \
        struct.unpack("IIII", readmem(self.addr + offset, 4 * 4))

        offset += 4 * 4

        # mutex
        offset += 4

        self.segments = []
        addr = self.addr + offset
        while addr != 0:
            current_segment = Segment(addr)
            self.segments.append(current_segment)
            addr = current_segment.next

    def segment_from_chunk(self, chunk):
        for segment in self.segments:
            if chunk.addr >= segment.base and chunk.addr < segment.base + segment.size:
                return segment

        return None

    def dump_address(self, addr):
        chunk = chunk_registry.get(addr - 8)

        print("[dl] Info about 0x%08x" % addr)
        print("[dl] chunk: 0x%08x" % chunk.addr)
        print("[dl] size: 0x%08x" % chunk.size)
        print("[dl] usable size: 0x%08x" % (chunk.size - 8))
        if chunk.is_free():
            print("[dl] status: free")
        else:
            print("[dl] status: in use")

        segment = self.segment_from_chunk(chunk)
        print("[dl] segment base: 0x%08x" % segment.base)


    def dump_segment(self, addr):
        for segment in self.segments:
            if segment.base == addr:
                break

        if segment.base != addr:
            print("[dl] passed address is not a segment base address")
            return

        table = [("data address", "size", "status")]

        current_address = segment.base
        while current_address < segment.base + segment.size:
            current_chunk = chunk_registry.get(current_address)
            if ((current_chunk.fd == segment.base and current_chunk.bk == segment.size) or
                current_address + current_chunk.size >= segment.base + segment.size):
                break
            if current_chunk.is_free():
                status = "free"
            else:
                status = "in use"
            table.append((hex(current_chunk.data_addr), hex(current_chunk.size), status))
            current_address += current_chunk.size

        print(ascii_table(table))

    def dump_segment_around(self, addr, count):
        our_chunk = chunk_registry.get(addr - 8)
        segment = self.segment_from_chunk(our_chunk)

        chunks = []

        current_address = segment.base
        while current_address < segment.base + segment.size:
            current_chunk = chunk_registry.get(current_address)
            chunks.append(current_chunk)
            if ((current_chunk.fd == segment.base and current_chunk.bk == segment.size) or
                current_address + current_chunk.size >= segment.base + segment.size):
                break
            current_address += current_chunk.size

        our_chunk_index = chunks.index(our_chunk)

        chunks = chunks[our_chunk_index - count:our_chunk_index + count + 1]

        table = [("data address", "size", "status")]
        for current_chunk in chunks:
            if current_chunk.is_free():
                status = "free"
            else:
                status = "in use"
            table.append((hex(current_chunk.data_addr), hex(current_chunk.size), status))

        print(ascii_table(table))

    def dump_segments_from(self, addr):
        segments_to_dump = []
        for segment in self.segments:
            segments_to_dump.append(segment)
            if segment.base == addr:
                break

        if segment.base != addr:
            print("[dl] passed address is not a segment base address")
            return

        table = [("data address", "size", "status")]

        for segment in reversed(segments_to_dump):
            current_address = segment.base
            while current_address < segment.base + segment.size:
                current_chunk = chunk_registry.get(current_address)
                if (current_chunk.fd == segment.base or
                    current_address + current_chunk.size >= segment.base + segment.size):
                    break
                if current_chunk.is_free():
                    status = "free"
                else:
                    status = "in use"
                table.append((hex(current_chunk.data_addr), hex(current_chunk.size), status))
                current_address += current_chunk.size

        print(ascii_table(table))

    def dump_bins(self):

        print("[dl] small bins:")
        table = [("index", "size", "num chunks")]

        for index, smallbin in self.smallbins.items():
            if smallbin != None:
                table.append((index, hex(smallbin.size), len(smallbin.chunks)))

        print(ascii_table(table))

        print("[dl] tree bins:")
        table = [("index", "min size","max size", "num chunks")]
        for index, treebin in self.treebins.items():
            if treebin != None:
                table.append((index, hex(treebin.min_size), hex(treebin.max_size),
                              len(treebin.chunks)))

        print(ascii_table(table))

    def dump_bin(self, size):
        if size < MAX_SMALL_SIZE:
            index = size >> SMALLBIN_SHIFT

            if self.smallbins[index] == None:
                print("[dl] small bin with index %d is empty" % index)
                return

            print("[dl] dumping small bin with index %d:" % index)
            table = [("data address", "size", "status")]
            for chunk in self.smallbins[index].chunks:
                if chunk.is_free():
                    status = "free"
                else:
                    status = "in use"
                table.append((hex(chunk.data_addr), hex(chunk.size), status))

            print(ascii_table(table))
        else:
            table = [("data address", "size", "status")]
            for index, treebin in self.treebins.items():
                if treebin is None:
                    continue
                if size >= treebin.min_size and size < treebin.max_size:
                    for chunk in treebin.chunks:
                        if chunk.is_free():
                            status = "free"
                        else:
                            status = "in use"
                        table.append((hex(chunk.data_addr), hex(chunk.size), status))
                    break
            print(ascii_table(table))

    def dump_free(self, size):

        allocator = Allocator(self)
        table = [("data address", "size", "status", "notes")]
        while True:
            chunk = allocator.allocate(size)
            if chunk == None:
                break
            notes = ""
            if chunk.addr == self.dv:
                notes += "dv"
            if chunk.addr == self.top:
                notes += "top"
            if chunk.new_dv:
                notes += "new dv"
            table.append((hex(chunk.data_addr), hex(chunk.size), chunk.get_status(), notes))

        print(ascii_table(table))
        return


class Allocator:
    def __init__(self, malloc_state):
        self.smallmap = malloc_state.smallmap
        self.smallbins = copy.deepcopy(malloc_state.smallbins)
        self.topsize = malloc_state.topsize
        self.top_addr = malloc_state.top
        self.treemap = malloc_state.treemap
        self.treebins = copy.deepcopy(malloc_state.treebins)
        dv_addr = malloc_state.dv
        self.dvsize = malloc_state.dvsize
        if self.dvsize != 0:
            self.dvchunk = chunk_registry.get(dv_addr)
        else:
            self.dvchunk = None

    def pad_request(self, req):
        return (req + CHUNK_OVERHEAD + CHUNK_ALIGN_MASK) & ~CHUNK_ALIGN_MASK

    def smallmap_is_marked(self, index):
        return self.smallmap & (1 << index)

    def mark_smallmap(self, index):
        self.smallmap |= (1 << index)

    def clear_smallmap(self, index):
        self.smallmap &= ~(1 << index)

    def treemap_is_marked(self, index):
        return self.treemap & (1 << index)

    def mark_treemap(self, index):
        self.treemap |= (1 << index)

    def clear_treemap(self, index):
        self.treemap &= ~(1 << index)

    def left_bits(self, x):
        b = (x << 1)
        return (b | -b)

    def least_bit(self, x):
        return (x & -x)

    def compute_bit2idx(self, x):
        # this is essentially finding the first set bit
        return int(round(math.log(x, 2)))

    def compute_tree_index(self, size):
        X = rshift(size, TREEBIN_SHIFT)
        if X == 0:
            return 0
        elif X > 0xffff:
            return NTREEBINS - 1
        else:
            n = X
            for i in range(31, 0, -1):
                if n & (1 << i):
                    break

            return (i << 1) + (size >> (i + (TREEBIN_SHIFT - 1)) & 1)

    def leftshift_for_tree_index(self, index):
        if index == NTREEBINS - 1:
            return 0
        return (32 - 1) - ((index >> 1) + TREEBIN_SHIFT - 1)

    def replace_dv(self, chunk):
        if self.dvchunk:
            self.insert_small_chunk(self.dvchunk)
        self.dvchunk = chunk
        self.dvsize = self.dvchunk.size

    def insert_small_chunk(self, chunk):
        index = chunk.size >> SMALLBIN_SHIFT
        smallbin = self.smallbins[index]
        if not self.smallmap_is_marked(index):
            self.mark_smallmap(index)
        smallbin.chunks.insert(0, chunk)

    def insert_chunk(self, chunk):
        if chunk.size <= MAX_SMALL_SIZE:
            self.insert_small_chunk(chunk)
        else:
            self.insert_large_chunk(chunk)


    def insert_large_chunk(self, chunk):
        chunk = chunk.as_tree_chunk()
        index = self.compute_tree_index(chunk.size)
        treebin = self.treebins[index]
        chunk.bin_index = index
        chunk.left_child = chunk.right_child = None
        if not self.treemap_is_marked(index):
            self.mark_treemap(index)
            treebin.root = chunk
            chunk.parent_addr = treebin.addr
            chunk.siblings = [chunk]
        else:
            t = treebin.root
            K = chunk.size << self.leftshift_for_tree_index(index)
            while True:
                if t.size != chunk.size:
                    C = None
                    if (K >> (32 - 1)) & 1 == 0:
                        C = t.left_child
                    else:
                        C = t.right_child
                    if C:
                        t = C
                    else:
                        if (K >> (32 - 1)) & 1 == 0:
                            t.left_child = chunk
                        else:
                            t.right_child = chunk
                        chunk.parent = t
                        chunk.siblings = [chunk]
                        break
                else:
                    t.siblings.append(chunk)
                    chunk.parent = None
                    break

    def unlink_large_chunk(self, node):
        new_node = None
        if len(node.siblings) >= 2:
            node.siblings.pop(0)
            new_node = node.siblings[0].as_tree_chunk()
            new_node.bin_index = node.bin_index
            new_node.siblings = node.siblings[:]
        else:
            if node.right_child:
                new_node = node.right_child
            elif node.left_child:
                new_node = node.left_child
            if new_node:
                prev_new_node_is_right = False
                parent = None
                while True:
                    temp_node = None
                    if new_node.right_child:
                        parent = new_node
                        temp_node = new_node.right_child
                        prev_new_node_is_right = True
                    elif new_node.left_child:
                        parent = new_node
                        temp_node = new_node.left_child
                        prev_new_node_is_right = False
                    if temp_node:
                        new_node = temp_node
                    else:
                        break
                if parent:
                    if prev_new_node_is_right:
                        parent.right_child = None
                    else:
                        parent.left_child = None

        treebin = self.treebins[node.bin_index]
        if treebin.root == node:
            if not new_node:
                self.clear_treemap(node.bin_index)
            treebin.root = new_node
        else:
            if node.parent.left_child == node:
                node.parent.left_child = new_node
            else:
                node.parent.right_child = new_node

        if new_node:
            new_node.parent = node.parent
            if node.left_child:
                if node.left_child != new_node:
                    new_node.left_child = node.left_child
                    new_node.left_child.parent = new_node
                else:
                    new_node.left_child = None
            if node.right_child:
                if node.right_child != new_node:
                    new_node.right_child = node.right_child
                    new_node.right_child.parent = new_node
                else:
                    new_node.right_child = None


    def tmalloc_small(self, size):
        # Get the smallest non-empty treebin
        leastbit = self.least_bit(self.treemap)
        i = self.compute_bit2idx(leastbit)
        treebin = self.treebins[i]

        rsize = treebin.root.size - size
        v = t = treebin.root

        while True:
            t = t.leftmost_child()
            if not t:
                break
            trem = t.size - size
            if (trem < rsize):
                rsize = trem
                v = t

        if v:
            self.unlink_large_chunk(v)
            if rsize >= MIN_CHUNK_SIZE:
                remainder_chunk = chunk_registry.create_temp(v.addr + size, rsize
                                                            | PINUSE_BIT,
                                                            from_larger_chunk = True,
                                                            new_dv = True)
                self.replace_dv(remainder_chunk)

            return v

        # Error occurred
        return None

    def tmalloc_large(self, size):
        v = None
        rsize = -size & 0xffffffff
        index = self.compute_tree_index(size)
        treebin = self.treebins[index]

        t = treebin.root
        v = None
        if treebin.root != None:
            # traverse tree for this bin looking for node with size == size
            sizebits = size << self.leftshift_for_tree_index(index)
            rst = None

            while True:
                trem = (t.size - size) & 0xffffffff
                if trem < rsize:
                    v = t
                    rsize = trem
                    if (rsize == 0):
                        break

                right = t.right_child
                if (sizebits >> (32 - 1)) & 1 == 0:
                    t = t.left_child
                else:
                    t = t.right_child
                if right and right != t:
                    rst = right
                if not t:
                    t = rst
                    break
                sizebits <<= 1

        if not t and not v:
            # set t to root of next non-empty treebin
            leftbits = self.left_bits(1 << index) & self.treemap
            if leftbits != 0:
                leastbit = self.least_bit(leftbits)
                i = self.compute_bit2idx(leastbit)
                t = self.treebins[i].root

        while t:
            # find smallest of tree or subtree
            trem = t.size - size
            if trem < rsize:
                rsize = trem
                v = t
            t = t.leftmost_child()

        # if dv is a better fit, return 0 so malloc will use it
        if not v or rsize >= ((self.dvsize - size) & 0xffffffff):
            return None

        self.unlink_large_chunk(v)

        if rsize >= MIN_CHUNK_SIZE:
            remainder_chunk = chunk_registry.create_temp(v.addr + size, rsize
                                                        | PINUSE_BIT,
                                                        from_larger_chunk = True)
            self.insert_chunk(remainder_chunk)

        return v

    def allocate(self, size):
        if size < MIN_REQUEST:
            size = MIN_CHUNK_SIZE
        else:
            size = self.pad_request(size)

        if size < MAX_SMALL_SIZE:
            index = size >> SMALLBIN_SHIFT
            smallbits = self.smallmap >> index

            # Remainderless fit to a smallbin
            if (smallbits & 3) != 0:
                index += ~smallbits & 1
                chunk = smallbin.chunks.pop(0)
                if len(smallbin.chunks) == 0:
                    self.clear_smallmap(index)
                return chunk
            elif size > self.dvsize:
                # Use chunk in next nonempty smallbin
                if smallbits != 0:
                    # get the next smallest bin which is non-empty:
                    leftbits = (smallbits << index) & self.left_bits(1 << index)
                    leastbit = self.least_bit(leftbits)
                    i = self.compute_bit2idx(leastbit)
                    smallbin = self.smallbins[i]
                    chunk = smallbin.chunks.pop(0)
                    if len(smallbin.chunks) == 0:
                        self.clear_smallmap(i)
                    rsize = (i << SMALLBIN_SHIFT) - size
                    remainder_chunk = chunk_registry.create_temp(chunk.addr + size, rsize
                                                                 | PINUSE_BIT,
                                                                 from_larger_chunk = True,
                                                                 new_dv = True)
                    self.replace_dv(remainder_chunk)
                    return chunk
                elif self.treemap != 0:
                    chunk = self.tmalloc_small(size)
                    if chunk:
                        return chunk
        elif size >= MAX_REQUEST:
            raise ValueError("Size too large")
        else:
            if self.treemap != 0:
                chunk = self.tmalloc_large(size)
                if chunk:
                    return chunk

        if size <= self.dvsize:
            rsize = self.dvchunk.size - size
            if rsize >= MIN_CHUNK_SIZE:
                # split dv
                chunk = self.dvchunk
                remainder_chunk = chunk_registry.create_temp(chunk.addr + size,
                                                             rsize | PINUSE_BIT,
                                                             from_dv = True)
                self.dvchunk = remainder_chunk
                self.dvsize = self.dvchunk.size
            else:
                # exhaust dv:
                chunk = self.dvchunk
                self.dvchunk = None
                self.dvsize = 0
            return chunk
        elif size < self.topsize:
            self.topsize -= size
            chunk = chunk_registry.create_temp(self.top_addr, size |
                                               PINUSE_BIT, from_top = True)
            self.top_addr += size
            return chunk

        # this is where dlmalloc tries to allocate from the system
        return None




malloc_state = None
chunk_registry = None
class DlParse (gdb.Command):
    def __init__ (self):
        super (DlParse, self).__init__ ("dlparse", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state, chunk_registry
        chunk_registry = ChunkRegistry()
        if malloc_state == None:
            malloc_state = MallocState()
        else:
            malloc_state.parse()

class DlTop (gdb.Command):
    def __init__ (self):
        super (DlTop, self).__init__ ("dltop", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        table = [("type", "address", "size")]
        table.append(("top", hex(malloc_state.top), hex(malloc_state.topsize)))
        table.append(("designated victim", hex(malloc_state.dv), hex(malloc_state.dvsize)))
        print(ascii_table(table))

class DlSegments (gdb.Command):
    def __init__ (self):
        super (DlSegments, self).__init__ ("dlsegments", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        table = [("start", "end", "flags")]
        for segment in malloc_state.segments:
            table.append((hex(segment.base), hex(segment.base + segment.size),
                          segment.sflags))
        print(ascii_table(table))

class DlBins (gdb.Command):
    def __init__ (self):
        super (DlBins, self).__init__ ("dlbins", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_bins()

class DlBin (gdb.Command):
    def __init__ (self):
        super (DlBin, self).__init__ ("dlbin", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                size = int(arg[0], 16)
            else:
                size = int(arg[0])
        except:
            print('[dl] usage: dlbin <size>')
            print('[dl] for example: dlbin 0x20')
            return

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_bin(size)

class DlInfo (gdb.Command):
    def __init__ (self):
        super (DlInfo, self).__init__ ("dlinfo", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                addr = int(arg[0], 16)
            else:
                addr = int('0x%s' % (arg[0]), 16)
        except:
            print('[dl] usage: dlinfo <data address>')
            print('[dl] for example: dlinfo 0x079e5440')
            return

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_address(addr)

class DlAround (gdb.Command):
    def __init__ (self):
        super (DlAround, self).__init__ ("dlaround", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                addr = int(arg[0], 16)
            else:
                addr = int('0x%s' % (arg[0]), 16)
            if len(arg) > 1:
                count = int(arg[1])
            else:
                count = 5
        except:
            print('[dl] usage: dlaround <base-address> [<count>]')
            print('[dl] for example: dlaround 0x89d93000 5')
            return

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_segment_around(addr, count)

class DlSegment (gdb.Command):
    def __init__ (self):
        super (DlSegment, self).__init__ ("dlsegment", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                addr = int(arg[0], 16)
            else:
                addr = int('0x%s' % (arg[0]), 16)
        except:
            print('[dl] usage: dlsegment <base-address>')
            print('[dl] for example: dlsegment 0x89d93000')
            return

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_segment(addr)

class DlFrom (gdb.Command):
    def __init__ (self):
        super (DlFrom, self).__init__ ("dlfrom", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                addr = int(arg[0], 16)
            else:
                addr = int(arg[0])
        except:
            print('[dl] usage: dlfrom <base-address>')
            print('[dl] for example: dlfrom 0x89d93000')
            return

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_segments_from(addr)

class DlFree (gdb.Command):
    def __init__ (self):
        super (DlFree, self).__init__ ("dlfree", gdb.COMMAND_USER)

    def invoke (self, arg, from_tty):
        global malloc_state
        arg = arg.split()

        try:
            if arg[0].startswith('0x'):
                size = int(arg[0], 16)
            else:
                size = int(arg[0])
        except:
            print('[dl] usage: dlfree <size>')
            print('[dl] for example: dlfree 0x20')
            return

        if malloc_state == None:
            print('[dl] please run dlparse first')
            return

        malloc_state.dump_free(size)

DlParse()
DlTop()
DlBins()
DlBin()
DlInfo()
DlSegment()
DlAround()
DlSegments()
DlFrom()
DlFree()

