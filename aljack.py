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

def read_one_byte_int(f):
  return int(read_exact_number_of_bytes(f, 1)[0])

def read_two_byte_int_little_endian(f):
  '''
  Reads two bytes and returns an integer.
  '''
  bytes = read_exact_number_of_bytes(f, 2)
  return bytes[0] + 256*bytes[1]

def read_four_byte_int_little_endian(f):
  '''
  Reads four bytes and returns an integer.
  '''
  bytes = read_exact_number_of_bytes(f, 4)
  return bytes[0] + 256*bytes[1] + 65536*bytes[2] + 16777216*bytes[3]

def copy_bytes(dst, src, n):
  if len(dst) != len(src) != n:
    raise Exception('byte copy sanity check failed')
  for i in range(n):
    dst[i] = src[i]

#
# Code to handle PE reading and parsing
#

def read_dos_header(f):
  '''
  Reads the DOS header.

  The file position should be queued to the header to read.
  '''

  DOS_HEADER_BYTES = bytearray.fromhex( # typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    '4d5a' # WORD   e_magic;                     // Magic number
    '9000' # WORD   e_cblp;                      // Bytes on last page of file
    '0300' # WORD   e_cp;                        // Pages in file
    '0000' # WORD   e_crlc;                      // Relocations
    '0400' # WORD   e_cparhdr;                   // Size of header in paragraphs
    '0000' # WORD   e_minalloc;                  // Minimum extra paragraphs needed
    'ffff' # WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    '0000' # WORD   e_ss;                        // Initial (relative) SS value
    'b800' # WORD   e_sp;                        // Initial SP value
    '0000' # WORD   e_csum;                      // Checksum
    '0000' # WORD   e_ip;                        // Initial IP value
    '0000' # WORD   e_cs;                        // Initial (relative) CS value
    '4000' # WORD   e_lfarlc;                    // File address of relocation table
    '0000' # WORD   e_ovno;                      // Overlay number
    '0000000000000000' # WORD   e_res[4];        // Reserved words
    '0000' # WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    '0000' # WORD   e_oeminfo;                   // OEM information; e_oemid specific
    '0000000000000000000000000000000000000000' # WORD   e_res2[10];             // Reserved words
    # read below     # LONG   e_lfanew;                    // File address of new exe header
    )

  dos_header_bytes = read_exact_number_of_bytes(f, len(DOS_HEADER_BYTES))

  if dos_header_bytes != DOS_HEADER_BYTES:
    raise Exception(
      'need to actually parse the DOS header instead of counting on it always to be same')

  dos_header = winapi.IMAGE_DOS_HEADER()
  dos_header.e_lfanew = read_four_byte_int_little_endian(f)

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

  pe_header.image_file_header.Machine = read_two_byte_int_little_endian(f)
  pe_header.image_file_header.NumberOfSections = read_two_byte_int_little_endian(f)
  pe_header.image_file_header.TimeDateStamp = read_four_byte_int_little_endian(f)
  pe_header.image_file_header.PointerToSymbolTable = read_four_byte_int_little_endian(f)
  pe_header.image_file_header.NumberOfSymbols = read_four_byte_int_little_endian(f)
  pe_header.image_file_header.SizeOfOptionalHeader = read_two_byte_int_little_endian(f)
  pe_header.image_file_header.Characteristics = read_two_byte_int_little_endian(f)

  # read the optional header

  pe_header.image_optional_header = winapi.IMAGE_OPTIONAL_HEADER32()
  position_before_optional_header = f.tell()

  pe_header.image_optional_header.Magic = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.MajorLinkerVersion = read_one_byte_int(f)
  pe_header.image_optional_header.MinorLinkerVersion = read_one_byte_int(f)
  pe_header.image_optional_header.SizeOfCode = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfInitializedData = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfUninitializedData = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.AddressOfEntryPoint = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.BaseOfCode = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.BaseOfData = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.ImageBase = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SectionAlignment = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.FileAlignment = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.MajorOperatingSystemVersion = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.MinorOperatingSystemVersion = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.MajorImageVersion = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.MinorImageVersion = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.MajorSubsystemVersion = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.MinorSubsystemVersion = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.Win32VersionValue = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfImage = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfHeaders = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.CheckSum = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.Subsystem = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.DllCharacteristics = read_two_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfStackReserve = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfStackCommit = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfHeapReserve = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.SizeOfHeapCommit = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.LoaderFlags = read_four_byte_int_little_endian(f)
  pe_header.image_optional_header.NumberOfRvaAndSizes = read_four_byte_int_little_endian(f)

  for i in range(winapi.IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
    image_data_directory = winapi.IMAGE_DATA_DIRECTORY()
    image_data_directory.VirtualAddress = read_four_byte_int_little_endian(f)
    image_data_directory.Size = read_four_byte_int_little_endian(f)
    pe_header.image_optional_header.DataDirectory[i] = image_data_directory

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

  copy_bytes(section_header.Name, read_exact_number_of_bytes(f, winapi.IMAGE_SIZEOF_SHORT_NAME),
    winapi.IMAGE_SIZEOF_SHORT_NAME)

  section_header.Misc.PhysicalAddress = read_four_byte_int_little_endian(f)
  section_header.VirtualAddress = read_four_byte_int_little_endian(f)
  section_header.SizeOfRawData = read_four_byte_int_little_endian(f)
  section_header.PointerToRawData = read_four_byte_int_little_endian(f)
  section_header.PointerToRelocations = read_four_byte_int_little_endian(f)
  section_header.PointerToLinenumbers = read_four_byte_int_little_endian(f)
  section_header.NumberOfRelocations = read_two_byte_int_little_endian(f)
  section_header.NumberOfLinenumbers = read_two_byte_int_little_endian(f)
  section_header.Characteristics = read_four_byte_int_little_endian(f)

  return section_header




PE_FILE = r'E:\Dropbox\aljack\etc\stack1.exe'

with open(PE_FILE, 'rb') as f:

  print('Information for PE file %s:' % PE_FILE)
  print()

  # read the DOS header
  dos_header = read_dos_header(f)

  # seek to and read the PE header
  f.seek(dos_header.e_lfanew)
  pe_header = read_pe_header(f)

  print(utils.indent_string(winapi.pe_header_to_str(pe_header)))
  print()

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

      thread_handle = debug_event.u.CreateProcessInfo.hThread

    # INTERLUDE: output information on the thread we are experimentally monitoring

    if thread_handle != None:
      context = winapi.WOW64_CONTEXT()
      context.ContextFlags = winapi.WOW64_CONTEXT_ALL
      if not winapi.Wow64GetThreadContext(thread_handle, ctypes.pointer(context)):
          raise Exception('GetThreadContext failed')
      print(utils.indent_string(winapi.wow64_context_to_str(context)))
      print()

    # END INTERLUDE

    if debug_event.dwDebugEventCode == winapi.LOAD_DLL_DEBUG_EVENT:

      # LOAD_DLL_DEBUG_EVENT
      load_dll_debug_info = debug_event.u.LoadDll
      print(utils.indent_string(winapi.load_dll_debug_info_to_str(
        process_info.hProcess, load_dll_debug_info)))
      print()

    elif debug_event.dwDebugEventCode == winapi.EXIT_PROCESS_DEBUG_EVENT:
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
