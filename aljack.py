#
# A PE analyzer by Joel Odom
#

import sys
import winapi
import ctypes
import utils

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 5:
  raise Exception(
    'Please run this script under Python 3.5 (or remove the version check if you feel brave).')


#
# Utility functions to read structured data
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


#
# Code to handle PE reading and parsing
#

def read_dos_header(f):
  '''
  Reads the DOS header.

  The file position should be queued to the header to read.
  '''

  dos_header = winapi.IMAGE_DOS_HEADER()
  read_into_structure(f, dos_header)

  return dos_header


def read_pe_header(f):
  '''
  Reads the PE header.

  The file position should be queued to the header to read.
  '''

  pe_header = winapi.PEHeader()

  # check the signature

  pe_header.signature = read_exact_number_of_bytes(f, 4)
  if pe_header.signature != bytes('PE\0\0', 'ascii'):
    raise Exception('bad PE signature')

  # read the image file header

  pe_header.image_file_header = winapi.IMAGE_FILE_HEADER()
  read_into_structure(f, pe_header.image_file_header)

  # read the optional header

  pe_header.image_optional_header = winapi.IMAGE_OPTIONAL_HEADER32()
  position_before_optional_header = f.tell()
  read_into_structure(f, pe_header.image_optional_header)

  # sanity check position against size_of_optional_header

  position_after_optional_header = f.tell()

  optional_header_bytes_read = position_after_optional_header - position_before_optional_header
  if optional_header_bytes_read != pe_header.image_file_header.SizeOfOptionalHeader:
    raise Exception('optional header size check failed (read %s bytes)'
      % optional_header_bytes_read)

  return pe_header


def read_section_header(f):
  '''
  Reads a section header.

  The file position should be queued to the table to read.
  '''

  section_header = winapi.IMAGE_SECTION_HEADER()
  read_into_structure(f, section_header)


  return section_header




PE_FILE = r'E:\Dropbox\aljack\etc\stack1.exe'

pe_header = None # used later in debugging to find the address of modules

with open(PE_FILE, 'rb') as f:

  print('Information for PE file %s:' % PE_FILE)
  print()

  # read the DOS header
  dos_header = read_dos_header(f)

  # seek to and read the PE header
  f.seek(dos_header.e_lfanew)
  pe_header = read_pe_header(f)

  print(utils.indent_string(winapi.pe_header_to_str(pe_header)))

  # read the section table
  print('  Sections: ')
  for i in range(pe_header.image_file_header.NumberOfSections):
    section_header = read_section_header(f)
    name = ''
    for b in section_header.Name:
      name += chr(b)
    print('    %s' % name)

print()

#
# Code to debug a runnnig process
#

image_base_address = None # populated below as image loads

try:

  thread_handle = None # monitor this thread for experimentation

  # create the debugee

  creation_flags = winapi.DEBUG_PROCESS

  startup_info = winapi.STARTUPINFOW()
  startup_info.cb = ctypes.sizeof(startup_info)

  process_info = winapi.PROCESS_INFORMATION()

  if not winapi.CreateProcess(PE_FILE, winapi.nullptr, winapi.nullptr, winapi.nullptr,
    winapi.FALSE, creation_flags, winapi.nullptr, winapi.nullptr,
    ctypes.pointer(startup_info), ctypes.pointer(process_info)):
      raise Exception('CreateProcess failed')

  print('== Debug Events ==')
  print()

  while True: # debugger loop

    # wait for a debug event

    debug_event = winapi.DEBUG_EVENT()

    if not winapi.WaitForDebugEvent(ctypes.pointer(debug_event), winapi.INFINITE):
      #if winapi.GetLastError() == winapi.ERROR_SEM_TIMEOUT:
      #  continue
      raise Exception('WaitForDebugEvent failed')

    # handle the debug event

    print('Debug Event: %s' % winapi.debug_event_to_str(debug_event))
    print()

    if debug_event.dwDebugEventCode == winapi.CREATE_PROCESS_DEBUG_EVENT:

      # CREATE_PROCESS_DEBUG_EVENT

      create_process_debug_info = debug_event.u.CreateProcessInfo
      print(utils.indent_string(winapi.create_process_debug_info_to_str(create_process_debug_info)))
      print()

      image_base_address = debug_event.u.CreateProcessInfo.lpBaseOfImage
      thread_handle = debug_event.u.CreateProcessInfo.hThread

    elif debug_event.dwDebugEventCode == winapi.LOAD_DLL_DEBUG_EVENT:

      # LOAD_DLL_DEBUG_EVENT
      load_dll_debug_info = debug_event.u.LoadDll
      print(utils.indent_string(winapi.load_dll_debug_info_to_str(
        process_info.hProcess, load_dll_debug_info)))
      print()

    # INTERLUDE: output information on the thread we are experimentally monitoring

    if thread_handle != None:
      context = winapi.WOW64_CONTEXT()
      context.ContextFlags = winapi.WOW64_CONTEXT_ALL
      if not winapi.Wow64GetThreadContext(thread_handle, ctypes.pointer(context)):
          raise Exception('GetThreadContext failed')
      print(utils.indent_string(winapi.wow64_context_to_str(context)))
      print()

    if image_base_address != None:

      # show the import table
      import_table_rva = pe_header.image_optional_header.DataDirectory[
        winapi.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
      print('  Current Process Import Table (at RVA 0x%08x):' % import_table_rva)
      print()
      print(utils.indent_string(winapi.import_table_to_str(
        process_info.hProcess, image_base_address, import_table_rva), '    '))
      print()

      # see if we can find a function
      address = winapi.lookup_function_from_import_table(
        process_info.hProcess, image_base_address, import_table_rva, 'exit')
      if address != None:
        print('  Address of exit: 0x%08x' % address)
        print()

    # END INTERLUDE

    if debug_event.dwDebugEventCode == winapi.EXIT_PROCESS_DEBUG_EVENT:
      # EXIT_PROCESS_DEBUG_EVENT
      break # exit the debugger loop

    # allow the debugee to continue

    if not winapi.ContinueDebugEvent(
      debug_event.dwProcessId,  debug_event.dwThreadId,  winapi.DBG_CONTINUE):
        raise Exception('ContinueDebugEvent failed')

except Exception as ex:
  print('**********  ERROR  **********')
  print('Last Windows Error: %s' % winapi.get_last_error_string())
  print()
  raise ex
  #  #winapi.MessageBox(winapi.nullptr, error, str(ex), winapi.MB_ICONEXCLAMATION)

print('Done.')
