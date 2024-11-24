import numpy, sys

def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))

def calc(esi):
    edx = 0x00
    ror_count = 0
    for eax in esi:
            edx = edx + ord(eax)
            if ror_count < len(esi)-1:
                edx = ror_str(edx, 0xd)
            ror_count += 1
    return hex(edx)

print(calc(sys.argv[1]))
