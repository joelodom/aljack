#
# a PE analyzer by Joel Odom
#

import sys

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 5:
  raise Exception(
    'Please run this script under Python 3.5 (or remove the version check if you feel brave).')


def read_exact_number_of_bytes(f, n):
  '''
  Reads exactly n bytes from f.
  '''

  bytes = f.read(n)
  if len(bytes) != n:
    raise Exception('failed to read bytes')

  return bytes


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



class DOSHeader:
  pass

def read_dos_header(f):
  '''
  Reads the DOS header.

  The file position should be queued to the header to read.
  '''

  #typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
  #    WORD   e_magic;                     // Magic number
  #    WORD   e_cblp;                      // Bytes on last page of file
  #    WORD   e_cp;                        // Pages in file
  #    WORD   e_crlc;                      // Relocations
  #    WORD   e_cparhdr;                   // Size of header in paragraphs
  #    WORD   e_minalloc;                  // Minimum extra paragraphs needed
  #    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
  #    WORD   e_ss;                        // Initial (relative) SS value
  #    WORD   e_sp;                        // Initial SP value
  #    WORD   e_csum;                      // Checksum
  #    WORD   e_ip;                        // Initial IP value
  #    WORD   e_cs;                        // Initial (relative) CS value
  #    WORD   e_lfarlc;                    // File address of relocation table
  #    WORD   e_ovno;                      // Overlay number
  #    WORD   e_res[4];                    // Reserved words
  #    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
  #    WORD   e_oeminfo;                   // OEM information; e_oemid specific
  #    WORD   e_res2[10];                  // Reserved words
  #    LONG   e_lfanew;                    // File address of new exe header
  #  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

  dos_header = DOSHeader()

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

  dos_header.e_lfanew = read_four_byte_int_little_endian(f)

  return dos_header




def machine_to_str(machine):

  #define IMAGE_FILE_MACHINE_UNKNOWN           0
  #define IMAGE_FILE_MACHINE_I386              0x014c  // Intel 386.
  #define IMAGE_FILE_MACHINE_R3000             0x0162  // MIPS little-endian, 0x160 big-endian
  #define IMAGE_FILE_MACHINE_R4000             0x0166  // MIPS little-endian
  #define IMAGE_FILE_MACHINE_R10000            0x0168  // MIPS little-endian
  #define IMAGE_FILE_MACHINE_WCEMIPSV2         0x0169  // MIPS little-endian WCE v2
  #define IMAGE_FILE_MACHINE_ALPHA             0x0184  // Alpha_AXP
  #define IMAGE_FILE_MACHINE_SH3               0x01a2  // SH3 little-endian
  #define IMAGE_FILE_MACHINE_SH3DSP            0x01a3
  #define IMAGE_FILE_MACHINE_SH3E              0x01a4  // SH3E little-endian
  #define IMAGE_FILE_MACHINE_SH4               0x01a6  // SH4 little-endian
  #define IMAGE_FILE_MACHINE_SH5               0x01a8  // SH5
  #define IMAGE_FILE_MACHINE_ARM               0x01c0  // ARM Little-Endian
  #define IMAGE_FILE_MACHINE_THUMB             0x01c2
  #define IMAGE_FILE_MACHINE_AM33              0x01d3
  #define IMAGE_FILE_MACHINE_POWERPC           0x01F0  // IBM PowerPC Little-Endian
  #define IMAGE_FILE_MACHINE_POWERPCFP         0x01f1
  #define IMAGE_FILE_MACHINE_IA64              0x0200  // Intel 64
  #define IMAGE_FILE_MACHINE_MIPS16            0x0266  // MIPS
  #define IMAGE_FILE_MACHINE_ALPHA64           0x0284  // ALPHA64
  #define IMAGE_FILE_MACHINE_MIPSFPU           0x0366  // MIPS
  #define IMAGE_FILE_MACHINE_MIPSFPU16         0x0466  // MIPS
  #define IMAGE_FILE_MACHINE_AXP64             IMAGE_FILE_MACHINE_ALPHA64
  #define IMAGE_FILE_MACHINE_TRICORE           0x0520  // Infineon
  #define IMAGE_FILE_MACHINE_CEF               0x0CEF
  #define IMAGE_FILE_MACHINE_EBC               0x0EBC  // EFI Byte Code
  #define IMAGE_FILE_MACHINE_AMD64             0x8664  // AMD64 (K8)
  #define IMAGE_FILE_MACHINE_M32R              0x9041  // M32R little-endian
  #define IMAGE_FILE_MACHINE_CEE               0xC0EE

  if machine == 0x14d:
    return 'Intel i860'
  elif machine == 0x14c:
    return 'Intel I386'
  elif machine == 0x162:
    return 'MIPS R3000'
  elif machine == 0x166:
    return 'MIPS R4000'
  elif machine == 0x183:
    return 'DEC Alpha AXP'

  return 'Unknown'

def time_stamp_to_str(ts):
  # "value is seconds since December 31st, 1969, at 4:00 P.M."
  # I'M NOT SURE I BELIEVE THAT BECAUSE IT'S A FEW HOURS DIFFERENT THAN THE UNIX EPOCH
  return 'TODO'

def characteristics_to_str(characteristics):

  #define IMAGE_FILE_RELOCS_STRIPPED           0x0001  // Relocation info stripped from file.
  #define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002  // File is executable  (i.e. no unresolved externel references).
  #define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004  // Line nunbers stripped from file.
  #define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008  // Local symbols stripped from file.
  #define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010  // Agressively trim working set
  #define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020  // App can handle >2gb addresses
  #define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  // Bytes of machine word are reversed.
  #define IMAGE_FILE_32BIT_MACHINE             0x0100  // 32 bit word machine.
  #define IMAGE_FILE_DEBUG_STRIPPED            0x0200  // Debugging info stripped from file in .DBG file
  #define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400  // If Image is on removable media, copy and run from the swap file.
  #define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800  // If Image is on Net, copy and run from the swap file.
  #define IMAGE_FILE_SYSTEM                    0x1000  // System File.
  #define IMAGE_FILE_DLL                       0x2000  // File is a DLL.
  #define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000  // File should only be run on a UP machine
  #define IMAGE_FILE_BYTES_REVERSED_HI         0x8000  // Bytes of machine word are reversed.

  return 'TODO'


class PEHeader:
  def __str__(self):
    return str(self.image_file_header)

class ImageFileHeader:
  def __str__(self):

    return (
      'Machine: %s (%s)\n'
      'Number of sections: %s\n'
      'Timestamp: %s (%s)\n'
      'Symbol table offset: %s\n'
      'Number of symbols: %s\n'
      'Size of optional header: %s\n'
      'Characteristics: %s (0x%04x)'

      % (machine_to_str(self.machine), self.machine,
      self.number_of_sections,
      time_stamp_to_str(self.time_date_stamp), self.time_date_stamp,
      self.pointer_to_symbol_table,
      self.number_of_symbols,
      self.size_of_optional_header,
      characteristics_to_str(self.characteristics), self.characteristics
      ))

def read_pe_header(f):
  '''
  Reads the PE header.

  The file position should be queued to the header to read.
  '''

  pe_header = PEHeader()

  #typedef struct _IMAGE_NT_HEADERS {
  #    DWORD Signature;
  #    IMAGE_FILE_HEADER FileHeader;
  #    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
  #} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

  # check the signature

  pe_header.signature = read_exact_number_of_bytes(f, 4)
  if pe_header.signature != bytes('PE\0\0', 'ascii'):
    raise Exception('bad PE signature')

  # read the image file header

  pe_header.image_file_header = ImageFileHeader()

  #  typedef struct _IMAGE_FILE_HEADER {
  #    WORD    Machine;
  #    WORD    NumberOfSections;
  #    DWORD   TimeDateStamp;
  #    DWORD   PointerToSymbolTable;
  #    DWORD   NumberOfSymbols;
  #    WORD    SizeOfOptionalHeader;
  #    WORD    Characteristics;
  #} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

  pe_header.image_file_header.machine = read_two_byte_int_little_endian(f)
  pe_header.image_file_header.number_of_sections = read_two_byte_int_little_endian(f)
  pe_header.image_file_header.time_date_stamp = read_four_byte_int_little_endian(f)
  pe_header.image_file_header.pointer_to_symbol_table = read_four_byte_int_little_endian(f)
  pe_header.image_file_header.number_of_symbols = read_four_byte_int_little_endian(f)
  pe_header.image_file_header.size_of_optional_header = read_two_byte_int_little_endian(f)
  pe_header.image_file_header.characteristics = read_two_byte_int_little_endian(f)

  return pe_header


PE_FILE = r'E:\Dropbox\aljack\etc\stack1.exe'

with open(PE_FILE, 'rb') as f:

  # read the DOS header
  dos_header = read_dos_header(f)

  # seek to and read the PE header
  f.seek(dos_header.e_lfanew)
  pe_header = read_pe_header(f)

  print(pe_header)
