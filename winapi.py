#
# Windows API wrapper by Joel Odom.  Does not contain everything, so add as needed.
#
# Comment that resembles C code are probably snippets from Windows header files
#

import sys
import ctypes
import ctypes.wintypes

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 5:
  raise Exception(
    'Please run this script under Python 3.5 (or remove the version check if you feel brave).')

#
# Windows API wrappers
#

nullptr = None

#define MB_OK                       0x00000000L
#define MB_OKCANCEL                 0x00000001L
#define MB_ABORTRETRYIGNORE         0x00000002L
#define MB_YESNOCANCEL              0x00000003L
#define MB_YESNO                    0x00000004L
#define MB_RETRYCANCEL              0x00000005L
#define MB_CANCELTRYCONTINUE        0x00000006L
#define MB_ICONHAND                 0x00000010L
#define MB_ICONQUESTION             0x00000020L
#define MB_ICONEXCLAMATION          0x00000030L
#define MB_ICONASTERISK             0x00000040L

MB_OK = 0x00000000
MB_OKCANCEL = 0x00000001
MB_ABORTRETRYIGNORE = 0x00000002
MB_YESNOCANCEL = 0x00000003
MB_YESNO = 0x00000004
MB_RETRYCANCEL = 0x00000005
MB_CANCELTRYCONTINUE = 0x00000006
MB_ICONHAND = 0x00000010
MB_ICONQUESTION = 0x00000020
MB_ICONEXCLAMATION = 0x00000030
MB_ICONASTERISK = 0x00000040

#typedef void *PVOID;
PVOID = ctypes.c_void_p

#WINBASEAPI
#BOOL
#WINAPI
#DebugActiveProcess(
#    __in DWORD dwProcessId
#    );

DebugActiveProcess = ctypes.windll.kernel32.DebugActiveProcess
DebugActiveProcess.restype = ctypes.wintypes.BOOL
DebugActiveProcess.argtypes = [ ctypes.wintypes.DWORD ]

#WINBASEAPI
#BOOL
#WINAPI
#DebugActiveProcessStop(
#    __in DWORD dwProcessId
#    );

DebugActiveProcessStop = ctypes.windll.kernel32.DebugActiveProcessStop
DebugActiveProcessStop.restype = ctypes.wintypes.BOOL
DebugActiveProcessStop.argtypes = [ ctypes.wintypes.DWORD ]


#WINUSERAPI
#int
#WINAPI
#MessageBoxW(
#    __in_opt HWND hWnd,
#    __in_opt LPCWSTR lpText,
#    __in_opt LPCWSTR lpCaption,
#    __in UINT uType);

MessageBox = ctypes.windll.user32.MessageBoxW
MessageBox.restype = ctypes.c_int
MessageBox.argtypes = [ ctypes.wintypes.HWND, ctypes.wintypes.LPCWSTR,
  ctypes.wintypes.LPCWSTR, ctypes.wintypes.UINT ]

#define EXCEPTION_MAXIMUM_PARAMETERS 15 // maximum number of exception parameters
EXCEPTION_MAXIMUM_PARAMETERS = 15

# not sure if this is correct
ULONG_PTR = ctypes.wintypes.PULONG

#typedef struct _EXCEPTION_RECORD {
#    DWORD    ExceptionCode;
#    DWORD ExceptionFlags;
#    struct _EXCEPTION_RECORD *ExceptionRecord;
#    PVOID ExceptionAddress;
#    DWORD NumberParameters;
#    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
#    } EXCEPTION_RECORD;

class EXCEPTION_RECORD(ctypes.Structure):
  _fields_ = [
    ('ExceptionCode', ctypes.wintypes.DWORD),
    ('ExceptionFlags', ctypes.wintypes.DWORD),
    #TODO ('ExceptionRecord', ctypes.POINTER(EXCEPTION_RECORD)),
    ('ExceptionRecord', ctypes.c_void_p),
    ('ExceptionAddress', ctypes.c_void_p),
    ('NumberParameters', ctypes.wintypes.DWORD),
    ('ExceptionInformation', ULONG_PTR * EXCEPTION_MAXIMUM_PARAMETERS )
  ]

#typedef DWORD (WINAPI *PTHREAD_START_ROUTINE)(
#    LPVOID lpThreadParameter
#    );

PTHREAD_START_ROUTINE = ctypes.WINFUNCTYPE(
  ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.wintypes.LPVOID)

#typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

LPTHREAD_START_ROUTINE = ctypes.POINTER(PTHREAD_START_ROUTINE)

#typedef struct _CREATE_THREAD_DEBUG_INFO {
#    HANDLE hThread;
#    LPVOID lpThreadLocalBase;
#    LPTHREAD_START_ROUTINE lpStartAddress;
#} CREATE_THREAD_DEBUG_INFO, *LPCREATE_THREAD_DEBUG_INFO;

class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('hThread', ctypes.wintypes.HANDLE),
    ('lpThreadLocalBase', ctypes.wintypes.LPVOID),
    ('lpStartAddress', LPTHREAD_START_ROUTINE)
  ]

#typedef struct _CREATE_PROCESS_DEBUG_INFO {
#    HANDLE hFile;
#    HANDLE hProcess;
#    HANDLE hThread;
#    LPVOID lpBaseOfImage;
#    DWORD dwDebugInfoFileOffset;
#    DWORD nDebugInfoSize;
#    LPVOID lpThreadLocalBase;
#    LPTHREAD_START_ROUTINE lpStartAddress;
#    LPVOID lpImageName;
#    WORD fUnicode;
#} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;

class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('hFile', ctypes.wintypes.HANDLE),
    ('hProcess', ctypes.wintypes.HANDLE),
    ('hThread', ctypes.wintypes.HANDLE),
    ('lpBaseOfImage', ctypes.wintypes.LPVOID),
    ('dwDebugInfoFileOffset', ctypes.wintypes.DWORD),
    ('nDebugInfoSize', ctypes.wintypes.DWORD),
    ('lpThreadLocalBase', ctypes.wintypes.LPVOID),
    ('lpStartAddress', LPTHREAD_START_ROUTINE),
    ('lpImageName', ctypes.wintypes.LPVOID),
    ('fUnicode', ctypes.wintypes.WORD)
  ]

#typedef struct _EXIT_THREAD_DEBUG_INFO {
#    DWORD dwExitCode;
#} EXIT_THREAD_DEBUG_INFO, *LPEXIT_THREAD_DEBUG_INFO;

class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('dwExitCode', ctypes.wintypes.DWORD)
  ]

#typedef struct _EXIT_PROCESS_DEBUG_INFO {
#    DWORD dwExitCode;
#} EXIT_PROCESS_DEBUG_INFO, *LPEXIT_PROCESS_DEBUG_INFO;

class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('dwExitCode', ctypes.wintypes.DWORD)
  ]

#typedef struct _LOAD_DLL_DEBUG_INFO {
#    HANDLE hFile;
#    LPVOID lpBaseOfDll;
#    DWORD dwDebugInfoFileOffset;
#    DWORD nDebugInfoSize;
#    LPVOID lpImageName;
#    WORD fUnicode;
#} LOAD_DLL_DEBUG_INFO, *LPLOAD_DLL_DEBUG_INFO;

class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('hFile', ctypes.wintypes.HANDLE),
    ('lpBaseOfDll', ctypes.wintypes.LPVOID),
    ('dwDebugInfoFileOffset', ctypes.wintypes.DWORD),
    ('nDebugInfoSize', ctypes.wintypes.DWORD),
    ('lpImageName', ctypes.wintypes.LPVOID),
    ('fUnicode', ctypes.wintypes.WORD)
  ]

#typedef struct _UNLOAD_DLL_DEBUG_INFO {
#    LPVOID lpBaseOfDll;
#} UNLOAD_DLL_DEBUG_INFO, *LPUNLOAD_DLL_DEBUG_INFO;

class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('lpBaseOfDll', ctypes.wintypes.LPVOID)
  ]

#typedef struct _OUTPUT_DEBUG_STRING_INFO {
#    LPSTR lpDebugStringData;
#    WORD fUnicode;
#    WORD nDebugStringLength;
#} OUTPUT_DEBUG_STRING_INFO, *LPOUTPUT_DEBUG_STRING_INFO;

class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
  _fields_ = [
    ('lpDebugStringData', ctypes.wintypes.LPSTR),
    ('fUnicode', ctypes.wintypes.WORD),
    ('nDebugStringLength', ctypes.wintypes.WORD)
  ]

#typedef struct _RIP_INFO {
#    DWORD dwError;
#    DWORD dwType;
#} RIP_INFO, *LPRIP_INFO;

class RIP_INFO(ctypes.Structure):
  _fields_ = [
    ('dwError', ctypes.wintypes.DWORD),
    ('dwType', ctypes.wintypes.DWORD)
  ]

#typedef struct _EXCEPTION_DEBUG_INFO {
#    EXCEPTION_RECORD ExceptionRecord;
#    DWORD dwFirstChance;
#} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
  _fields_ = [
    ('ExceptionRecord', EXCEPTION_RECORD),
    ('dwFirstChance', ctypes.wintypes.DWORD)
  ]

#typedef struct _DEBUG_EVENT {
#    DWORD dwDebugEventCode;
#    DWORD dwProcessId;
#    DWORD dwThreadId;
#    union {
#        EXCEPTION_DEBUG_INFO Exception;
#        CREATE_THREAD_DEBUG_INFO CreateThread;
#        CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
#        EXIT_THREAD_DEBUG_INFO ExitThread;
#        EXIT_PROCESS_DEBUG_INFO ExitProcess;
#        LOAD_DLL_DEBUG_INFO LoadDll;
#        UNLOAD_DLL_DEBUG_INFO UnloadDll;
#        OUTPUT_DEBUG_STRING_INFO DebugString;
#        RIP_INFO RipInfo;
#    } u;
#} DEBUG_EVENT, *LPDEBUG_EVENT;

class DEBUG_EVENT(ctypes.Structure):
  class u(ctypes.Union):
    _fields_ = [
      ('Exception', EXCEPTION_DEBUG_INFO),
      ('CreateThread', CREATE_THREAD_DEBUG_INFO),
      ('CreateProcessInfo', CREATE_PROCESS_DEBUG_INFO),
      ('ExitThread', EXIT_THREAD_DEBUG_INFO),
      ('ExitProcess', EXIT_PROCESS_DEBUG_INFO),
      ('LoadDll', LOAD_DLL_DEBUG_INFO),
      ('UnloadDll', UNLOAD_DLL_DEBUG_INFO),
      ('DebugString', OUTPUT_DEBUG_STRING_INFO),
      ('RipInfo', RIP_INFO)
    ]

  _fields_ = [
    ('dwDebugEventCode', ctypes.wintypes.DWORD),
    ('dwProcessId', ctypes.wintypes.DWORD),
    ('dwThreadId', ctypes.wintypes.DWORD),
    ('u', u)
  ]

LPDEBUG_EVENT = ctypes.POINTER(DEBUG_EVENT)

#define EXCEPTION_DEBUG_EVENT       1
#define CREATE_THREAD_DEBUG_EVENT   2
#define CREATE_PROCESS_DEBUG_EVENT  3
#define EXIT_THREAD_DEBUG_EVENT     4
#define EXIT_PROCESS_DEBUG_EVENT    5
#define LOAD_DLL_DEBUG_EVENT        6
#define UNLOAD_DLL_DEBUG_EVENT      7
#define OUTPUT_DEBUG_STRING_EVENT   8
#define RIP_EVENT                   9

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

#WINBASEAPI
#BOOL
#WINAPI
#WaitForDebugEvent(
#    __in LPDEBUG_EVENT lpDebugEvent,
#    __in DWORD dwMilliseconds
#    );

WaitForDebugEvent = ctypes.windll.kernel32.WaitForDebugEvent
WaitForDebugEvent.restype = ctypes.wintypes.BOOL
WaitForDebugEvent.argtypes = [ LPDEBUG_EVENT, ctypes.wintypes.DWORD ]

#define INFINITE            0xFFFFFFFF  // Infinite timeout

INFINITE = 0Xffffffff

#WINBASEAPI
#BOOL
#WINAPI
#DebugSetProcessKillOnExit(
#    __in BOOL KillOnExit
#    );

DebugSetProcessKillOnExit = ctypes.windll.kernel32.DebugSetProcessKillOnExit
DebugSetProcessKillOnExit.restype = ctypes.wintypes.BOOL
DebugSetProcessKillOnExit.argtypes = [ ctypes.wintypes.BOOL ]

#define DBG_EXCEPTION_HANDLED            ((DWORD   )0x00010001L)
#define DBG_CONTINUE                     ((DWORD   )0x00010002L)

DBG_EXCEPTION_HANDLED = 0x00010001
DBG_CONTINUE = 0x00010002

#WINBASEAPI
#BOOL
#WINAPI
#ContinueDebugEvent(
#    __in DWORD dwProcessId,
#    __in DWORD dwThreadId,
#    __in DWORD dwContinueStatus
#    );

ContinueDebugEvent = ctypes.windll.kernel32.ContinueDebugEvent
ContinueDebugEvent.restype = ctypes.wintypes.BOOL
ContinueDebugEvent.argtypes = [ ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
  ctypes.wintypes.DWORD ]

#WINBASEAPI
#__checkReturn
#DWORD
#WINAPI
#GetLastError(
#    VOID
#    );

GetLastError = ctypes.windll.kernel32.GetLastError
GetLastError.restype = ctypes.wintypes.DWORD
GetLastError.argtypes = [ ]

#WINBASEAPI
#DWORD
#WINAPI
#FormatMessageW(
#    __in     DWORD dwFlags,
#    __in_opt LPCVOID lpSource,
#    __in     DWORD dwMessageId,
#    __in     DWORD dwLanguageId,
#    __out    LPWSTR lpBuffer,
#    __in     DWORD nSize,
#    __in_opt va_list *Arguments
#    );

FormatMessage = ctypes.windll.kernel32.FormatMessageW
FormatMessage.restype = ctypes.wintypes.DWORD
FormatMessage.argtypes = [ ctypes.wintypes.DWORD, ctypes.wintypes.LPCVOID, ctypes.wintypes.DWORD,
  ctypes.wintypes.DWORD, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD,
  ctypes.wintypes.LPVOID ] # doesn't support the optional argument list

#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100
#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_FROM_STRING     0x00000400
#define FORMAT_MESSAGE_FROM_HMODULE    0x00000800
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define FORMAT_MESSAGE_ARGUMENT_ARRAY  0x00002000
#define FORMAT_MESSAGE_MAX_WIDTH_MASK  0x000000FF

FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
FORMAT_MESSAGE_FROM_STRING = 0x00000400
FORMAT_MESSAGE_FROM_HMODULE = 0x00000800
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
FORMAT_MESSAGE_MAX_WIDTH_MASK = 0x000000FF


#
# Utility functions
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

def debug_event_to_str(debug_event):
  return '%s' % debug_event_code_to_str(debug_event.dwDebugEventCode)

def get_last_error_string():
  error = GetLastError()
  message = ctypes.wintypes.LPWSTR()
  status = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        message,
        0,
        nullptr);
  if not status:
    raise Exception('FormatMessage failed: %s' % GetLastError())
  return '%s (%s)' % (message, error)