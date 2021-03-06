'''
Windows API utilities by Joel Odom.

Copyright (c) 2016-2018 by Joel Odom, Marietta, GA

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
International License. To view a copy of this license,
visit http://creativecommons.org/licenses/by-sa/4.0/.
'''

import binascii

import utils
import unittest
from winapi import *
import pymsasid3.pymsasid as pyms

#
# image file header utilities
#

def image_file_characteristics_to_str(characteristics):
  '''
  Converts the Characteristics WORD from an IMAGE_FILE_HEADER to a string.
  '''

  chars = []

  if characteristics & IMAGE_FILE_RELOCS_STRIPPED:
    chars.append('IMAGE_FILE_RELOCS_STRIPPED')
  if characteristics & IMAGE_FILE_EXECUTABLE_IMAGE:
    chars.append('IMAGE_FILE_EXECUTABLE_IMAGE')
  if characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED:
    chars.append('IMAGE_FILE_LINE_NUMS_STRIPPED')
  if characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED:
    chars.append('IMAGE_FILE_LOCAL_SYMS_STRIPPED')
  if characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM:
    chars.append('IMAGE_FILE_AGGRESIVE_WS_TRIM')
  if characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE:
    chars.append('IMAGE_FILE_LARGE_ADDRESS_AWARE')
  if characteristics & IMAGE_FILE_BYTES_REVERSED_LO:
    chars.append('IMAGE_FILE_BYTES_REVERSED_LO')
  if characteristics & IMAGE_FILE_32BIT_MACHINE:
    chars.append('IMAGE_FILE_32BIT_MACHINE')
  if characteristics & IMAGE_FILE_DEBUG_STRIPPED:
    chars.append('IMAGE_FILE_DEBUG_STRIPPED')
  if characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP:
    chars.append('IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP')
  if characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP:
    chars.append('IMAGE_FILE_NET_RUN_FROM_SWAP')
  if characteristics & IMAGE_FILE_SYSTEM:
    chars.append('IMAGE_FILE_SYSTEM')
  if characteristics & IMAGE_FILE_DLL:
    chars.append('IMAGE_FILE_DLL')
  if characteristics & IMAGE_FILE_UP_SYSTEM_ONLY:
    chars.append('IMAGE_FILE_UP_SYSTEM_ONLY')
  if characteristics & IMAGE_FILE_BYTES_REVERSED_HI:
    chars.append('IMAGE_FILE_BYTES_REVERSED_HI')

  return '\n'.join(chars)

def image_file_machine_to_str(image_file_machine_machine):
  '''
  Converts the Machine WORD from an IMAGE_FILE_HEADER to a string.
  '''

  if image_file_machine_machine == IMAGE_FILE_MACHINE_I386:
    return 'IMAGE_FILE_MACHINE_I386'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_R3000:
    return 'IMAGE_FILE_MACHINE_R3000'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_R4000:
    return 'IMAGE_FILE_MACHINE_R4000'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_R10000:
    return 'IMAGE_FILE_MACHINE_R10000'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_WCEMIPSV2:
    return 'IMAGE_FILE_MACHINE_WCEMIPSV2'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_ALPHA:
    return 'IMAGE_FILE_MACHINE_ALPHA'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_SH3:
    return 'IMAGE_FILE_MACHINE_SH3'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_SH3DSP:
    return 'IMAGE_FILE_MACHINE_SH3DSP'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_SH3E:
    return 'IMAGE_FILE_MACHINE_SH3E'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_SH4:
    return 'IMAGE_FILE_MACHINE_SH4'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_SH5:
    return 'IMAGE_FILE_MACHINE_SH5'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_ARM:
    return 'IMAGE_FILE_MACHINE_ARM'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_THUMB:
    return 'IMAGE_FILE_MACHINE_THUMB'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_AM33:
    return 'IMAGE_FILE_MACHINE_AM33'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_POWERPC:
    return 'IMAGE_FILE_MACHINE_POWERPC'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_POWERPCFP:
    return 'IMAGE_FILE_MACHINE_POWERPCFP'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_IA64:
    return 'IMAGE_FILE_MACHINE_IA64'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_MIPS16:
    return 'IMAGE_FILE_MACHINE_MIPS16'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_ALPHA64:
    return 'IMAGE_FILE_MACHINE_ALPHA64'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_MIPSFPU:
    return 'IMAGE_FILE_MACHINE_MIPSFPU'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_MIPSFPU16:
    return 'IMAGE_FILE_MACHINE_MIPSFPU16'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_TRICORE:
    return 'IMAGE_FILE_MACHINE_TRICORE'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_CEF:
    return 'IMAGE_FILE_MACHINE_CEF'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_EBC:
    return 'IMAGE_FILE_MACHINE_EBC'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_AMD64:
    return 'IMAGE_FILE_MACHINE_AMD64'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_M32R:
    return 'IMAGE_FILE_MACHINE_M32R'
  if image_file_machine_machine == IMAGE_FILE_MACHINE_CEE:
    return 'IMAGE_FILE_MACHINE_CEE'

  return 'Unknown'


def time_stamp_to_str(ts):
  # "value is seconds since December 31st, 1969, at 4:00 P.M."
  # I'M NOT SURE I BELIEVE THAT BECAUSE IT'S A FEW HOURS DIFFERENT THAN THE UNIX EPOCH
  # Add unit test for this when it's ready
  return 'TODO'

def image_file_header_to_str(image_file_header):
  return (
    'Machine: %s (0x%04x)\n'
    'Number of sections: %s\n'
    'Timestamp: %s (%s)\n'
    'Symbol table offset: %s\n'
    'Number of symbols: %s\n'
    'Size of optional header: %s\n'
    'Characteristics (0x%04x):\n'
    '%s'

    % (image_file_machine_to_str(image_file_header.Machine), image_file_header.Machine,
    image_file_header.NumberOfSections,
    time_stamp_to_str(image_file_header.TimeDateStamp), image_file_header.TimeDateStamp,
    image_file_header.PointerToSymbolTable,
    image_file_header.NumberOfSymbols,
    image_file_header.SizeOfOptionalHeader,
    image_file_header.Characteristics,
    utils.indent_string(image_file_characteristics_to_str(image_file_header.Characteristics))
    ))


class TestImageFileHeaderUtilities(unittest.TestCase):

  def setUp(self):
    '''
    Loads a known PE to use for this test case.
    '''

    with open(r'C:\Users\jo94\Dropbox\shared_with_work\aljack\etc\stack1.exe', 'rb') as f:
      # read the DOS header
      dos_header = read_dos_header(f)

      # seek to and read the PE header
      f.seek(dos_header.e_lfanew)
      pe_header = read_pe_header(f)

      self.image_file_header = pe_header.image_file_header

  def test_image_file_characteristics_to_str(self):
    chars = image_file_characteristics_to_str(self.image_file_header.Characteristics)

    self.assertGreater(len(chars), 0)
    self.assertNotEqual(chars[-1], '\n')

    split_chars = chars.split()
    self.assertEqual(len(split_chars), 6)
    self.assertIn('IMAGE_FILE_RELOCS_STRIPPED', split_chars)
    self.assertIn('IMAGE_FILE_EXECUTABLE_IMAGE', split_chars)
    self.assertIn('IMAGE_FILE_LINE_NUMS_STRIPPED', split_chars)
    self.assertIn('IMAGE_FILE_LOCAL_SYMS_STRIPPED', split_chars)
    self.assertIn('IMAGE_FILE_32BIT_MACHINE', split_chars)
    self.assertIn('IMAGE_FILE_DEBUG_STRIPPED', split_chars)

  def test_image_file_machine_to_str(self):
    machine = image_file_machine_to_str(self.image_file_header.Machine)
    self.assertEqual('IMAGE_FILE_MACHINE_I386', machine)

  def test_image_file_header_to_str(self):
    s = image_file_header_to_str(self.image_file_header)

#
# code to deal with debug events
#

def debug_event_code_to_str(debug_event_code):
  if debug_event_code == EXCEPTION_DEBUG_EVENT:
    return 'EXCEPTION_DEBUG_EVENT'
  if debug_event_code == CREATE_THREAD_DEBUG_EVENT:
    return 'CREATE_THREAD_DEBUG_EVENT'
  if debug_event_code == CREATE_PROCESS_DEBUG_EVENT:
    return 'CREATE_PROCESS_DEBUG_EVENT'
  if debug_event_code == EXIT_THREAD_DEBUG_EVENT:
    return 'EXIT_THREAD_DEBUG_EVENT'
  if debug_event_code == EXIT_PROCESS_DEBUG_EVENT:
    return 'EXIT_PROCESS_DEBUG_EVENT'
  if debug_event_code == LOAD_DLL_DEBUG_EVENT:
    return 'LOAD_DLL_DEBUG_EVENT'
  if debug_event_code == UNLOAD_DLL_DEBUG_EVENT:
    return 'UNLOAD_DLL_DEBUG_EVENT'
  if debug_event_code == OUTPUT_DEBUG_STRING_EVENT:
    return 'OUTPUT_DEBUG_STRING_EVENT'
  if debug_event_code == RIP_EVENT:
    return 'RIP_EVENT'
  return 'Unknown (%s)' % c

def create_process_debug_info_to_str(create_process_debug_info):
  return (
    'hFile: 0x%x\n'
    'hProcess: 0x%x\n'
    'hThread: 0x%x\n'
    'lpBaseOfImage: 0x%x\n'
    'dwDebugInfoFileOffset: %s\n'
    'nDebugInfoSize: %s\n'
    'lpThreadLocalBase: %s\n'
    'lpStartAddress: %s\n'
    'lpImageName: %s\n'
    'fUnicode: %s'
    % (create_process_debug_info.hFile,
    create_process_debug_info.hProcess,
    create_process_debug_info.hThread,
    create_process_debug_info.lpBaseOfImage,
    create_process_debug_info.dwDebugInfoFileOffset,
    create_process_debug_info.nDebugInfoSize,
    create_process_debug_info.lpThreadLocalBase,
    create_process_debug_info.lpStartAddress,
    create_process_debug_info.lpImageName,
    create_process_debug_info.fUnicode)
  )

def load_dll_debug_info_to_str(process_handle, load_dll_debug_info):
  if not load_dll_debug_info.fUnicode:
    raise Exception('need to handle non-Unicode')

  return (
    'hFile: 0x%08x\n'
    'lpBaseOfDll: 0x%08x\n'
    'dwDebugInfoFileOffset: 0x%08x\n'
    'nDebugInfoSize: %s\n'
    'lpImageName: %s\n'
    'fUnicode: %s'
    % (load_dll_debug_info.hFile,
    load_dll_debug_info.lpBaseOfDll,
    load_dll_debug_info.dwDebugInfoFileOffset,
    load_dll_debug_info.nDebugInfoSize,
    lp_image_name_to_str(process_handle, load_dll_debug_info),
    load_dll_debug_info.fUnicode)
  )

def unload_dll_debug_info_to_str(process_handle, load_dll_debug_info):
  return 'lpBaseOfDll: 0x%08x\n' % load_dll_debug_info.lpBaseOfDll

def debug_event_to_str(debug_event):
  return '%s' % debug_event_code_to_str(debug_event.dwDebugEventCode)

def exception_debug_info_to_str(process_handle, exception_debug_info):
  return (
    'ExceptionRecord:\n'
    '%s'
    %
    exception_record_to_str(process_handle, exception_debug_info.ExceptionRecord)
  )

def lp_image_name_to_str(process_handle, load_dll_debug_info):
  #  MSDN information about lpImageName
  #
  #  A pointer to the file name associated with hFile. This member may be NULL,
  #  or it may contain the address of a string pointer in the address space of
  #  the process being debugged. That address may, in turn, either be NULL or
  #  point to the actual filename. If fUnicode is a nonzero value, the name
  #  string is Unicode; otherwise, it is ANSI.
  #
  #  This member is strictly optional. Debuggers must be prepared to handle the
  #  case where lpImageName is NULL or *lpImageName (in the address space of
  #  the process being debugged) is NULL. Specifically, the system will never
  #  provide an image name for a create process event, and it will not likely
  #  pass an image name for the first DLL event. The system will also never
  #  provide this information in the case of debugging events that originate
  #  from a call to the DebugActiveProcess function.

  if not load_dll_debug_info.fUnicode:
    raise Exception('need to handle non-Unicode')

  image_name = '<< no image name available >>'

  if load_dll_debug_info.lpImageName:
    p = read_dword_from_remote_process(process_handle, load_dll_debug_info.lpImageName)
    if p:
      image_name = read_wstring_from_remote_process(process_handle, p)

  return image_name

class TestDebugEventUtilities(unittest.TestCase): # TODO

  def setUp(self):
    pass

  def test_debug_event_code_to_str(self):
    pass

  def test_create_process_debug_info_to_str(self):
    pass

  def test_load_dll_debug_info_to_str(self):
    pass

  def test_unload_dll_debug_info_to_str(self):
    pass

  def test_debug_event_to_str(self):
    pass

  def test_exception_debug_info_to_str(self):
    pass

  def test_lp_image_name_to_str(self):
    pass

#
# remote process memory access utilities
#

def memory_basic_info_to_str(memory_basic_info):
  return (
    'BaseAddress: 0x%08x\n'
    'AllocationBase: 0x%08x\n'
    'AllocationProtect: %s\n'
    'RegionSize: %s\n'
    'State: %s\n'
    'Protect: %s\n'
    'Type: %s'
    % (memory_basic_info.BaseAddress if memory_basic_info.BaseAddress != None else 0,
    memory_basic_info.AllocationBase if memory_basic_info.AllocationBase != None else 0,
    memory_basic_info.AllocationProtect,
    memory_basic_info.RegionSize,
    memory_basic_info.State,
    memory_basic_info.Protect,
    memory_basic_info.Type)
  )

def show_memory_information(process_handle, pointer):
  print('Memory Information for 0x%08x:' % pointer)
  memory_basic_info = MEMORY_BASIC_INFORMATION()
  status = VirtualQueryEx(
    process_handle, pointer, ctypes.pointer(memory_basic_info), ctypes.sizeof(memory_basic_info))
  if status == ctypes.sizeof(memory_basic_info):
    print(utils.indent_string(memory_basic_info_to_str(memory_basic_info)))
    print()
  else:
    print('VirtualQueryEx failed')


def read_byte_from_remote_process(process_handle, pointer):
  '''
  Reads a byte from a remote process.

  Returns the byte as an integer.
  '''

  #print('Trying to read one byte from 0x%08x.' % pointer)
  buf = ctypes.create_string_buffer(1) # 1-byte buffer, initialized to null
  if not ReadProcessMemory(process_handle, pointer, buf, 1, nullptr):
    print('*** ReadProcessMemory failed ***')
    show_memory_information(process_handle, pointer)
    return None
  #print('At 0x%08x we have byte 0x%02x.' % (pointer, buf[0][0]))
  return buf[0][0]

def read_word_from_remote_process(process_handle, pointer):
  '''
  Reads a word from a remote process.

  Returns the word as an integer by swapping the bytes and converting to integer.
  '''

  buf = ctypes.create_string_buffer(2) # 2-byte buffer, initialized to nulls
  if not ReadProcessMemory(process_handle, pointer, buf, 2, nullptr):
    print('*** ReadProcessMemory failed ***')
    show_memory_information(process_handle, pointer)
  rv = (buf.raw[1] << 8) + buf.raw[0]
  #print('At 0x%08x we have word 0x%04x.' % (pointer, rv))
  return rv

def read_dword_from_remote_process(process_handle, pointer):
  '''
  Reads a double word from a remote process.

  Returns the double word as an integer.
  '''

  buf = ctypes.create_string_buffer(4) # 4-byte buffer, initialized to nulls
  if not ReadProcessMemory(process_handle, pointer, buf, 4, nullptr):
    print('*** ReadProcessMemory failed ***')
    show_memory_information(process_handle, pointer)
  rv = (buf.raw[3] << 24) + (buf.raw[2] << 16) + (buf.raw[1] << 8) + buf.raw[0]
  #print('At 0x%08x we have dword 0x%08x.' % (pointer, rv))
  return rv

def read_wstring_from_remote_process(process_handle, pointer):
  rv = ''
  while True:
    i = read_word_from_remote_process(process_handle, pointer)
    if i == 0:
      return rv
    rv += chr(i)
    pointer += 2

def read_string_from_remote_process(process_handle, pointer):
  #print('About to read string at 0x%08x' % pointer)
  rv = ''
  while True:
    i = read_byte_from_remote_process(process_handle, pointer)
    if i == 0:
      return rv
    rv += chr(i)
    pointer += 1

def read_structure_from_remote_process(process_handle, pointer, structure):
  '''
  Reads a structure from a remote process.
  '''

  #print('Trying to read %s bytes from 0x%08x.' % (ctypes.sizeof(structure), pointer))
  buf = ctypes.create_string_buffer(ctypes.sizeof(structure)) # initialized to nulls
  if not ReadProcessMemory(process_handle, pointer, buf, ctypes.sizeof(structure), nullptr):
    print('*** ReadProcessMemory failed ***')
    show_memory_information(process_handle, pointer)
  ctypes.memmove(ctypes.addressof(structure), buf, ctypes.sizeof(structure))

class TestMemoryAccessUtilities(unittest.TestCase): # TODO

  def setUp(self):
    pass

#
# context utilities
#

def context_to_str(context):
  return (
    'ContextFlags: 0x%08x\n'
    'EBP: 0x%08x\n'
    'ESP: 0x%08x\n'
    'EIP: 0x%08x'
    % (context.ContextFlags,
    context.Esp,
    context.Ebp,
    context.Eip)
  )

wow64_context_to_str = context_to_str

class TestContextUtilities(unittest.TestCase): # TODO

  def setUp(self):
    pass

#
# these utilities need to be categorized and put under test (TODO)
#

class PEHeader():
  # a metaclass to hold various components of a PE header
  pass

def data_directory_to_str(data_directory):
  '''
  Convert a data directory to a string.

  data_directory is an array IMAGE_NUMBEROF_DIRECTORY_ENTRIES-length array of IMAGE_DATA_DIRECTORY
  structures.
  '''

  rv = ''

  for i in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
    if i == IMAGE_DIRECTORY_ENTRY_EXPORT:
      rv += 'IMAGE_DIRECTORY_ENTRY_EXPORT'
    elif i == IMAGE_DIRECTORY_ENTRY_IMPORT:
      rv += 'IMAGE_DIRECTORY_ENTRY_IMPORT'
    elif i == IMAGE_DIRECTORY_ENTRY_RESOURCE:
      rv += 'IMAGE_DIRECTORY_ENTRY_RESOURCE'
    elif i == IMAGE_DIRECTORY_ENTRY_EXCEPTION:
      rv += 'IMAGE_DIRECTORY_ENTRY_EXCEPTION'
    elif i == IMAGE_DIRECTORY_ENTRY_SECURITY:
      rv += 'IMAGE_DIRECTORY_ENTRY_SECURITY'
    elif i == IMAGE_DIRECTORY_ENTRY_BASERELOC:
      rv += 'IMAGE_DIRECTORY_ENTRY_BASERELOC'
    elif i == IMAGE_DIRECTORY_ENTRY_DEBUG:
      rv += 'IMAGE_DIRECTORY_ENTRY_DEBUG'
    elif i == IMAGE_DIRECTORY_ENTRY_ARCHITECTURE:
      rv += 'IMAGE_DIRECTORY_ENTRY_ARCHITECTURE'
    elif i == IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
      rv += 'IMAGE_DIRECTORY_ENTRY_GLOBALPTR'
    elif i == IMAGE_DIRECTORY_ENTRY_TLS:
      rv += 'IMAGE_DIRECTORY_ENTRY_TLS'
    elif i == IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
      rv += 'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG'
    elif i == IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
      rv += 'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'
    elif i == IMAGE_DIRECTORY_ENTRY_IAT:
      rv += 'IMAGE_DIRECTORY_ENTRY_IAT'
    elif i == IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
      rv += 'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT'
    elif i == IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
      rv += 'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR'
    else:
      rv += 'Unassigned or unknown directory entry (%s)' % i

    rv += (':\n  VirtualAddress: 0x%08x  Size: %s\n' % (
      data_directory[i].VirtualAddress, data_directory[i].Size))

  return rv

def image_optional_header_to_str(image_optional_header):
  return (
    'Data Directory:\n'
    '%s'

    % (utils.indent_string(data_directory_to_str(image_optional_header.DataDirectory))
    ))

def pe_header_to_str(pe_header):
  return (
    'Image File Header:\n'
    '%s\n'
    '\n'
    'Image Optional Headers:\n'
    '%s\n'

    % (utils.indent_string(image_file_header_to_str(pe_header.image_file_header)),
    utils.indent_string(image_optional_header_to_str(pe_header.image_optional_header))
  ))

def get_image_import_name(process_handle, image_base_address, rva):
  # takes a pointer to an IMAGE_IMPORT_BY_NAME
  # because of the weird declaration in winnt.h, we have to read this manually
  return read_string_from_remote_process(process_handle, image_base_address + rva + 2)

def image_import_by_name_to_str(process_handle, image_base_address, rva):
  return 'Name: %s' % get_image_import_name(process_handle, image_base_address, rva)

def image_import_by_name_array_to_str(process_handle, image_base_address, rva, by_name):
  pointer = image_base_address + rva
  rv = ''

  while True:
    struct_rva = read_dword_from_remote_process(process_handle, pointer)
    if struct_rva == 0:
      break
    if by_name:
      rv += '%s\n' % image_import_by_name_to_str(process_handle, image_base_address, struct_rva)
    else: # by address
      rv += '0x%08x\n' % struct_rva
    pointer += 4

  return rv

def is_iat_populated(process_handle, image_base_address, image_import_descriptor):
  '''
  Determines whether or not the IAT pointed to by image_import_descriptor is populated or not.
  '''

  original_first_entry = read_dword_from_remote_process(
    process_handle, image_base_address + image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk)
  current_first_entry = read_dword_from_remote_process(
    process_handle, image_base_address + image_import_descriptor.FirstThunk)
  return original_first_entry != current_first_entry

def import_table_to_str(process_handle, image_base_address, rva):
  pointer = image_base_address + rva
  rv = ''

  while True: # break when we reach the last entry
    image_import_descriptor = IMAGE_IMPORT_DESCRIPTOR()
    read_structure_from_remote_process(process_handle, pointer, image_import_descriptor)

    if image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk == 0:
      # no more structures
      break

    name = '<< no name >>'
    if image_import_descriptor.Name != 0:
      name = read_string_from_remote_process(
        process_handle, image_base_address + image_import_descriptor.Name)

    # The import table (at the original first thunk RVA) tells what functions are
    # imported from the DLL in question.  The import address table (at the first thunk RVA)
    # originally contains the function names but the loader overwrites these names with the
    # function addresses.

    if is_iat_populated(process_handle, image_base_address, image_import_descriptor):
      # show addresses in the IAT, not names
      rv +=(
        'Name: %s\n'
        'TimeDateStamp: %s\n'
        'ForwarderChain: %s\n'
        'This table appears to be populated.\n'
        '\n'
        'Original First Thunk RVA: 0x%08x\n'
        '%s\n' # hint name array
        'First Thunk RVA: 0x%08x\n'
        '%s' # import address table
        % (
        name,
        image_import_descriptor.TimeDateStamp,
        image_import_descriptor.ForwarderChain,
        image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk,
        utils.indent_string(image_import_by_name_array_to_str(process_handle, image_base_address,
          image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk, True)),
        image_import_descriptor.FirstThunk,
        utils.indent_string(image_import_by_name_array_to_str(process_handle, image_base_address,
          image_import_descriptor.FirstThunk, False))
      ))
    else:
      rv +=(
        'Name: %s\n'
        'TimeDateStamp: %s\n'
        'ForwarderChain: %s\n'
        'This table does not appear to be populated.\n'
        '\n'
        'Original First Thunk RVA: 0x%08x\n'
        '%s\n' # hint name array
        'First Thunk RVA: 0x%08x\n'
        '%s' # import address table
        % (
        name,
        image_import_descriptor.TimeDateStamp,
        image_import_descriptor.ForwarderChain,
        image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk,
        utils.indent_string(image_import_by_name_array_to_str(process_handle, image_base_address,
          image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk, True)),
        image_import_descriptor.FirstThunk,
        utils.indent_string(image_import_by_name_array_to_str(process_handle, image_base_address,
          image_import_descriptor.FirstThunk, True))
      ))

    pointer += ctypes.sizeof(image_import_descriptor)

  return rv

def lookup_pointer_to_function_address_from_imports(
  process_handle, image_base_address, rva_to_import_table, function_name):

  # this utility could probably use much more refinement

  import_table_pointer = image_base_address + rva_to_import_table
  rv = ''

  # search the import table DLL-by-DLL

  while True: # break when we reach the last entry

    image_import_descriptor = IMAGE_IMPORT_DESCRIPTOR()
    read_structure_from_remote_process(
      process_handle, import_table_pointer, image_import_descriptor)

    if image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk == 0:
      break # no more structures

    if is_iat_populated(process_handle, image_base_address, image_import_descriptor):

      # we only get here if this DLL's IAT is populated

      descriptor_pointer = (
        image_base_address + image_import_descriptor.DUMMYUNIONNAME.OriginalFirstThunk)

      i = 0

      # search the DLL's imports function-by-function

      while True:
        struct_rva = read_dword_from_remote_process(process_handle, descriptor_pointer)
        if struct_rva == 0:
          break # last entry in array

        name = get_image_import_name(process_handle, image_base_address, struct_rva)
        if name == function_name:
          # found a match!
          # calculate pointer to corresponding entry in IAT
          return (image_base_address
            + image_import_descriptor.FirstThunk + ctypes.sizeof(IMAGE_IMPORT_BY_NAME)*i)

        i += 1
        descriptor_pointer += 4

    import_table_pointer += ctypes.sizeof(image_import_descriptor)

  return None # not found

def lookup_function_from_imports(
  process_handle, image_base_address, rva_to_import_table, function_name):

  address_in_iat = lookup_pointer_to_function_address_from_imports(
    process_handle, image_base_address, rva_to_import_table, function_name)
  if address_in_iat == None:
    return None # not found
  function_address = read_dword_from_remote_process(process_handle, address_in_iat)
  return function_address

def replace_function_address(
  process_handle, image_base_address, rva_to_import_table, function_name, new_address):

  address_in_iat = lookup_pointer_to_function_address_from_imports(
    process_handle, image_base_address, rva_to_import_table, function_name)
  if address_in_iat == None:
    raise Exception('failed to find function')

  if not WriteProcessMemory(process_handle, address_in_iat,
    ctypes.pointer(ctypes.cast(new_address, ctypes.wintypes.LPVOID)),
    4, nullptr):
      raise Exception('WriteProcessMemory failed')

def exception_record_to_str(process_handle, exception_record):
  exception_code_str = '<< unknown >>'

  if exception_record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
    exception_code_str = 'EXCEPTION_ACCESS_VIOLATION'
  elif exception_record.ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT:
    exception_code_str = 'EXCEPTION_DATATYPE_MISALIGNMENT'
  elif exception_record.ExceptionCode == EXCEPTION_BREAKPOINT:
    exception_code_str = 'EXCEPTION_BREAKPOINT'
  elif exception_record.ExceptionCode == EXCEPTION_SINGLE_STEP:
    exception_code_str = 'EXCEPTION_SINGLE_STEP'
  elif exception_record.ExceptionCode == EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    exception_code_str = 'EXCEPTION_ARRAY_BOUNDS_EXCEEDED'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_DENORMAL_OPERAND:
    exception_code_str = 'EXCEPTION_FLT_DENORMAL_OPERAND'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_DIVIDE_BY_ZERO:
    exception_code_str = 'EXCEPTION_FLT_DIVIDE_BY_ZERO'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_INEXACT_RESULT:
    exception_code_str = 'EXCEPTION_FLT_INEXACT_RESULT'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_INVALID_OPERATION:
    exception_code_str = 'EXCEPTION_FLT_INVALID_OPERATION'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_OVERFLOW:
    exception_code_str = 'EXCEPTION_FLT_OVERFLOW'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_STACK_CHECK:
    exception_code_str = 'EXCEPTION_FLT_STACK_CHECK'
  elif exception_record.ExceptionCode == EXCEPTION_FLT_UNDERFLOW:
    exception_code_str = 'EXCEPTION_FLT_UNDERFLOW'
  elif exception_record.ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO:
    exception_code_str = 'EXCEPTION_INT_DIVIDE_BY_ZERO'
  elif exception_record.ExceptionCode == EXCEPTION_INT_OVERFLOW:
    exception_code_str = 'EXCEPTION_INT_OVERFLOW'
  elif exception_record.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION:
    exception_code_str = 'EXCEPTION_PRIV_INSTRUCTION'
  elif exception_record.ExceptionCode == EXCEPTION_IN_PAGE_ERROR:
    exception_code_str = 'EXCEPTION_IN_PAGE_ERROR'
  elif exception_record.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION:
    exception_code_str = 'EXCEPTION_ILLEGAL_INSTRUCTION'
  elif exception_record.ExceptionCode == EXCEPTION_NONCONTINUABLE_EXCEPTION:
    exception_code_str = 'EXCEPTION_NONCONTINUABLE_EXCEPTION'
  elif exception_record.ExceptionCode == EXCEPTION_STACK_OVERFLOW:
    exception_code_str = 'EXCEPTION_STACK_OVERFLOW'
  elif exception_record.ExceptionCode == EXCEPTION_INVALID_DISPOSITION:
    exception_code_str = 'EXCEPTION_INVALID_DISPOSITION'
  elif exception_record.ExceptionCode == EXCEPTION_GUARD_PAGE:
    exception_code_str = 'EXCEPTION_GUARD_PAGE'
  elif exception_record.ExceptionCode == EXCEPTION_INVALID_HANDLE:
    exception_code_str = 'EXCEPTION_INVALID_HANDLE'

  return 'ExceptionCode: %s' % exception_code_str

def output_memory_bytes_until_failure(process_handle, pointer):
  # slow and dumb approach
  show_memory_information(process_handle, pointer)
  line = ''
  while True:
    byte = read_byte_from_remote_process(process_handle, pointer)
    if byte == None:
      break
    if byte > 31 and byte < 126:
      line += chr(byte)
    else:
      line += '.'
    if len(line) % 80 == 0:
      print(line)
      line = ''
    pointer += 1
  print()

#
# utility functions to read structured data
#

def read_exact_number_of_bytes(f, n):
  '''
  Reads exactly n bytes from f.
  '''

  bytes = f.read(n)
  if len(bytes) != n:
    raise Exception('failed to read bytes')

  return bytes

def read_into_structure(f, structure):
  bytes = read_exact_number_of_bytes(f, ctypes.sizeof(structure))
  ctypes.memmove(ctypes.addressof(structure), bytes, ctypes.sizeof(structure))

class MemoryMetaFile():
  '''
  A metafile class that access Windows memory as it if were a Python file object.
  '''

  def __init__(self, process_handle, base_address):
    self.process_handle = process_handle
    self.base_address = base_address
    self.position = 0 # position from base address in bytes

  def read(self, num_bytes):
    buf = ctypes.create_string_buffer(num_bytes) # initialized to nulls
    rv = ReadProcessMemory(
      self.process_handle, self.base_address + self.position, buf, num_bytes, nullptr)
    if not rv or len(buf) != num_bytes:
        print('*** ReadProcessMemory failed ***')
        #show_memory_information(self.process_handle, pointer)
    self.position += num_bytes
    return bytes(buf)

  def tell(self):
    return self.position

  def seek(self, position):
    self.position = position

#
# code to handle PE reading and parsing
#

def read_dos_header(f):
  '''
  Reads the DOS header.

  The file position should be queued to the header to read.
  '''

  dos_header = IMAGE_DOS_HEADER()
  read_into_structure(f, dos_header)

  return dos_header


def read_pe_header(f):
  '''
  Reads the PE header.

  The file position should be queued to the header to read.
  '''

  pe_header = PEHeader()

  # check the signature

  pe_header.signature = read_exact_number_of_bytes(f, 4)
  if pe_header.signature != bytes('PE\0\0', 'ascii'):
    raise Exception('bad PE signature (%s)' % binascii.hexlify(pe_header.signature))

  # read the image file header

  pe_header.image_file_header = IMAGE_FILE_HEADER()
  read_into_structure(f, pe_header.image_file_header)

  # read the optional header

  if pe_header.image_file_header.SizeOfOptionalHeader == ctypes.sizeof(IMAGE_OPTIONAL_HEADER32):
    pe_header.image_optional_header = IMAGE_OPTIONAL_HEADER32()
  elif pe_header.image_file_header.SizeOfOptionalHeader == ctypes.sizeof(IMAGE_OPTIONAL_HEADER64):
    pe_header.image_optional_header = IMAGE_OPTIONAL_HEADER64()
  else:
    raise Exception('unexpected SizeOfOptionalHeader')

  position_before_optional_header = f.tell()
  read_into_structure(f, pe_header.image_optional_header)

  # sanity check position against size_of_optional_header

  position_after_optional_header = f.tell()

  optional_header_bytes_read = position_after_optional_header - position_before_optional_header
  if optional_header_bytes_read != pe_header.image_file_header.SizeOfOptionalHeader:
    raise Exception('optional header size check failed (read %s bytes and expected %s bytes)'
      % (optional_header_bytes_read, pe_header.image_file_header.SizeOfOptionalHeader))

  return pe_header


def read_section_header(f):
  '''
  Reads a section header.

  The file position should be queued to the table to read.
  '''

  section_header = IMAGE_SECTION_HEADER()
  read_into_structure(f, section_header)

  return section_header


def analyze_pe_file(f): # code for experimentation
  # read the DOS header
  dos_header = read_dos_header(f)

  # seek to and read the PE header
  f.seek(dos_header.e_lfanew)
  pe_header = read_pe_header(f)

  rv = pe_header_to_str(pe_header)

  # read the section table
  rv += 'Sections: \n'
  for i in range(pe_header.image_file_header.NumberOfSections):
    section_header = read_section_header(f)
    name = ''
    for b in section_header.Name:
      name += chr(b)
    physical_address = section_header.Misc.PhysicalAddress
    virtual_address = section_header.VirtualAddress
    rv += f'  {name}' \
      f'    Physical Addr: 0x{physical_address:08x}\n' \
      f'    Virtual Addr: 0x{virtual_address:08x}\n' \
      f'    SizeOfRawData: {section_header.SizeOfRawData}\n'

  return rv

#
# other utilities (to categorize)
#

def disassemble(f):
  '''
  It's still TBD how this will look.
  '''

  source = read_exact_number_of_bytes(f, 48) # TODO: don't read past segment
  source = source.decode('latin-1')

  rv = ''
  pos = 0
  while pos < len(source):
    inst = pyms.Pymsasid(hook=pyms.BufferHook, source = source).disassemble(pos)
    rv += f'{str(inst)}\n'
    pos += inst.size

  return rv

def create_process(binary):
  '''
  Starts a process with caller attached as debugger.

  Returns a PROCESS_INFORMATION structure.
  '''

  creation_flags = DEBUG_PROCESS | CREATE_NEW_CONSOLE

  startup_info = STARTUPINFOW()
  startup_info.cb = ctypes.sizeof(startup_info)

  process_info = PROCESS_INFORMATION()

  if not CreateProcess(binary, nullptr, nullptr, nullptr,
    FALSE, creation_flags, nullptr, nullptr,
    ctypes.pointer(startup_info), ctypes.pointer(process_info)):
      raise Exception('CreateProcess failed')

  return process_info


def get_last_error_string():
  error = GetLastError()
  buf = ctypes.wintypes.LPWSTR()

  status = FormatMessage(
    FORMAT_MESSAGE_ALLOCATE_BUFFER  | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    nullptr, error, 0, ctypes.cast(ctypes.byref(buf), ctypes.wintypes.LPWSTR), 0, nullptr);
  if not status:
    raise Exception('FormatMessage failed (%s)' % GetLastError())

  message = buf.value

  if LocalFree(buf) != nullptr:
    raise Exception('LocalFree failed (%s)' % GetLastError())

  return '%s (%s)' % (message, error)

if __name__ == '__main__':
    unittest.main()
