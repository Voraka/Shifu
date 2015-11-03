# dga_shifu.py
#
# This script will produce the DGA URL used by Shifu
# The key and seed may be different from Shifu variants
# Usage: dga_shifu.py <number_of_url_to_be_generated>
#
# FortiGuard Lion Team

import sys
import os
import struct

KEY  = 'B2luZm8AAAC75IWXxwy6uvPkhZc='
BASE = '|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\]^_`abcdefghijklmnopq'
SEED = 0x3a31337a

def generate_stream(key, base):
    len_key = len(key)
    counter_key = 0
    array_list = []

    while True:
        counter1 = 0
        counter2 = 0
        array_4 = []
        while True:
            if counter_key >= len_key:
                break
            x = 0
            while not x:
                base_key = ord(key[counter_key])
                counter_key += 1
                if base_key - 43 > 79:
                    x = 0
                else:
                    x = ord(base[base_key - 43])
                if x:
                    x = (x - 61) & ((x == 36) - 1)
                if counter_key >= len_key:
                    if not x:
                        counter2 += 1
                    break
            counter1 += 1
            array_4.append(x - 1)
            counter2 += 1
            #print x
            if counter2 == 4:
                break

        if counter1:
            x_1 = (array_4[0] * 4 | (array_4[1] >> 4)) & 255
            x_2 = (array_4[1] * 16 | (array_4[2] >> 2)) & 255
            x_3 = (array_4[3] | (array_4[2] << 6)) & 255

            array_list.append(x_1)
            array_list.append(x_2)
            array_list.append(x_3)

        if counter_key == len_key:
            break

    return array_list


def main():

    if len(sys.argv) == 1:
        print 'Usage: %s <number of url to generate>' %os.path.basename(__file__)
        sys.exit()

    num  = int(sys.argv[1])
    seed = SEED

    print '[+] Shifu\'s DGA URL using seed (0x%x):' % (seed)
    for u in range(num):

        # Generate the DGA's components
        stream = generate_stream(KEY, BASE)

        # Retrieve the DGA's components
        val_add = struct.unpack('<L', ''.join([chr(x) for x in stream[8:12]]))[0]
        val_xor = struct.unpack('<L', ''.join([chr(x) for x in stream[12:16]]))[0]
        url_len = stream[0]
        tld = ''.join([chr(x) for x in stream[1:5]])
        domain = ''


        # Forming the DGA's URL
        for i in range(url_len):
            ch = (seed % 25 + 97) & 255
            domain = domain + chr(ch)
            seed = ((seed + val_add) ^ val_xor) & 0xffffffff

        domain += '.' + tld
        print domain

if __name__ == '__main__':
    main()
