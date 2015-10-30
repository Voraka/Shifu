import idaapi
import idautils

# Global variables
IMG_BASE = idaapi.get_imagebase()
list_seg = []
for seg in idautils.Segments():
    list_seg.append(seg)
IMG_END = idc.SegEnd(list_seg[len(list_seg)-1])

def decrypt(ea, key):
    
    # Virtual address to IMAGE_IMPORT_DESCRIPTOR->FirstThunk
    va_iat = 0
    # Virtual address to IMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk
    va_int = 0
    tmp_ea = ea
    
    # Back-tracing to locate the IMAGE_IMPORT_DESCRIPTOR from import address table passed from the callback
    for xref in idautils.XrefsTo(ea, 0):
        if XrefTypeName(xref.type) == 'Data_Offset':
            va_iat = xref.frm - 0x10

    if va_iat != 0:
        print "Import Name Table->%08x" % (idaapi.get_long(va_iat) + IMG_BASE)
        va_int = idaapi.get_long(va_iat) + IMG_BASE
    else:
        return
        
    if va_int != 0:
        va_itd = idaapi.get_long(va_int)
        # Enumerate array of IMAGE_THUNK_DATA
        while va_itd != 0:
            va_itd = va_itd + IMG_BASE
            if va_itd > IMG_BASE and va_itd <= IMG_END:
                print "Image thunk data->%08x" % va_itd
                va_ibn = va_itd + 2
                ch = idaapi.get_byte(va_ibn)
                str = ''
                while ch != 0 and ch != 255:
                    str += chr(ch ^ key)
                    va_ibn += 1
                    ch = idaapi.get_byte(va_ibn)
                
                # Save the decoded import name
                print "IMAGE_IMPORT_BY_NAME->Name (%08x): %s" % (va_itd+2, str)
                idc.MakeName(tmp_ea, str)
                tmp_ea += 4
                
            # Next IMAGE_THUNK_DATA
            va_int += 4
            va_itd = idaapi.get_long(va_int)
    else:
        return



def imp_cb(ea, name, ord):
    if not name:
        print "%08x: ord#%d" % (ea, ord)
    else:
        print "%08x: %s (ord#%d)" % (ea, name, ord)
    
    # The decrypt function will be responsible to enumerate IMPORT_DESCRIPTOR_TABLE to decode all the function name
    decrypt(ea, 0xFF)
    # We only want to callback once for every imported DLL
    return False

# Main
nimps = idaapi.get_import_module_qty()

for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print "Failed to get import module name for #%d" % i
        continue

    print "Walking-> %s" % name
    idaapi.enum_import_names(i, imp_cb)

print "All done..."