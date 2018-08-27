#!/usr/bin/env python
# OpenIPC key extractor by Mark Ermolov (@_markel___)
#                          Maxim Goryachy (@h0t_max)
#
# Details:  https://github.com/ptresearch/IntelME-JTAG
#           https://github.com/ptresearch/IntelTXE-POC
idaapi.get_strlist_options()
idaapi.build_strlist()
str_count = idaapi.get_strlist_qty()
str_info = idaapi.string_info_t()
key_start_ea = idaapi.BADADDR
for i in range(str_count):
  assert idaapi.get_strlist_item(str_info, i)
  seg_name = idaapi.get_segm_name(idaapi.getseg(str_info.ea))
  if not seg_name or seg_name != ".rdata" and seg_name != ".rodata":
    continue
  str_val = str(idaapi.get_many_bytes(str_info.ea, str_info.length))
  if str_val.startswith("Logging.xml"):
      key_start_ea = str_info.ea + str_info.length
      break
idaapi.clear_strlist()

if key_start_ea == idaapi.BADADDR:
    raise Exception("Can't find OpenIPC config data key")

key_ea = idaapi.BADADDR
for ea in range(key_start_ea, key_start_ea+0x10):
    if idaapi.get_first_dref_to(ea) != idaapi.BADADDR:
        key_ea = ea
        break

if key_ea == idaapi.BADADDR:
    raise Exception("Can't find OpenIPC config data key")

key = idaapi.get_many_bytes(key_ea, 0x10)
print '"' + key.encode("hex") + '"'
