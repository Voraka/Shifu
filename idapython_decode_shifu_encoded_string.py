import idaapi
import idc
import re

Key = 0x87
Length = 0x24
ea = 0x10025E30
tmp_ea = ea

str = ''
i = 0
while i < Length:
    ch = idaapi.get_byte(tmp_ea)
    ch = ch ^ Key
    str += chr(ch)
    tmp_ea += 1 
    i += 1
    
print "Decoded string: " + str
new_name = re.sub(r'[^A-Za-z0-9]+', '_', str)
idc.MakeName(ea, new_name)
idc.MakeRptCmt(ea, str)