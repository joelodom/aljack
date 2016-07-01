import sys

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 5:
  raise Exception(
    'Please run this script under Python 3.5 (or remove the version check if you feel brave).')



def read_dos_header(f):
  '''
  Reads the DOS header, including the short program that comes after it.

  The file position should be queued to the header to read.
  '''


  DOS_HEADER = bytearray.fromhex( # typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
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
    '0000000000000000' # WORD   e_res[4];                    // Reserved words
    '0000' # WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    '0000' # WORD   e_oeminfo;                   // OEM information; e_oemid specific
    '0000000000000000000000000000000000000000' # WORD   e_res2[10];             // Reserved words
    '80000000' # LONG   e_lfanew;                    // File address of new exe header
    )

  # Remember that this is little endian, so e_lfanew above is 0x80, which is indeed where
  # the PE header starts in stack1.exe

  dos_header = f.read(len(DOS_HEADER))
  if len(dos_header) != len(DOS_HEADER):
    raise Exception('failed to read enough bytes')

  if dos_header != DOS_HEADER:
    raise Exception(
      'need to actually parse the DOS header instead of counting on it always to be same')



def read_pe_header(f):
  pass



PE_FILE = r'E:\Dropbox\aljack\etc\stack1.exe'

with open(PE_FILE, 'rb') as f:
  read_dos_header(f)
  read_pe_header(f)
