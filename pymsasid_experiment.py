import pymsasid3.pymsasid as pyms
#import syn_c

def disassemble(source):
    pymsas = pyms.Pymsasid(source=source, hook=pyms.BufferHook,
        vendor=pyms.VENDOR_AMD)
    pymsas.dis_mode = 64

    result = ''
    pos = 0
    while pos < len(source):
        inst = pymsas.decode()
        result += str(inst) + '\n'
        pos += inst.size

    return result

def main():
    src = "\x55\x48\x89\xe5\x53\x48\x83\xec\x08\x80\x3d\xe8\x0b\x20\x00\x00\x75\x4b\xbb\x40\x0e\x60\x00\x48\x8b\x05\xe2\x0b\x20\x00\x48\x81\xeb\x38\x0e\x60\x00\x48\xc1\xfb\x03\x48\x83\xeb\x01\x48\x39\xd8\x73\x24\x66\x0f\x1f\x44\x00\x00\x48\x83\xc0\x01\x48\x89\x05\xbd\x0b\x20\x00\xff\x14\xc5\x38\x0e\x60\x00\x48\x8b\x05\xaf\x0b\x20\x00\x48\x39\xd8\x72\xe2\xc6\x05\x9b\x0b\x20\x00\x01\x48\x83\xc4\x08\x5b\x5d\xc3"
    dis = disassemble(src)
    print(dis)

main()
