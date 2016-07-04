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

nullptr = None

#define MB_OK                       0x00000000L
MB_OK = 0x00000000

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
  __fields__ = [
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
  __fields__ = [
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
  __fields__ = [
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
  __fields__ = [
    ('dwExitCode', ctypes.wintypes.DWORD)
  ]

#typedef struct _EXIT_PROCESS_DEBUG_INFO {
#    DWORD dwExitCode;
#} EXIT_PROCESS_DEBUG_INFO, *LPEXIT_PROCESS_DEBUG_INFO;

class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
  __fields__ = [
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
  __fields__ = [
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
  __fields__ = [
    ('lpBaseOfDll', ctypes.wintypes.LPVOID)
  ]

#typedef struct _OUTPUT_DEBUG_STRING_INFO {
#    LPSTR lpDebugStringData;
#    WORD fUnicode;
#    WORD nDebugStringLength;
#} OUTPUT_DEBUG_STRING_INFO, *LPOUTPUT_DEBUG_STRING_INFO;

class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
  __fields__ = [
    ('lpDebugStringData', ctypes.wintypes.LPSTR),
    ('fUnicode', ctypes.wintypes.WORD),
    ('nDebugStringLength', ctypes.wintypes.WORD)
  ]

#typedef struct _RIP_INFO {
#    DWORD dwError;
#    DWORD dwType;
#} RIP_INFO, *LPRIP_INFO;

class RIP_INFO(ctypes.Structure):
  __fields__ = [
    ('dwError', ctypes.wintypes.DWORD),
    ('dwType', ctypes.wintypes.DWORD)
  ]

#typedef struct _EXCEPTION_DEBUG_INFO {
#    EXCEPTION_RECORD ExceptionRecord;
#    DWORD dwFirstChance;
#} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
  __fields__ = [
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
    __fields__ = [
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

  __fields__ = [
    ('dwDebugEventCode', ctypes.wintypes.DWORD),
    ('dwProcessId', ctypes.wintypes.DWORD),
    ('dwThreadId', ctypes.wintypes.DWORD),
    ('u', u)
  ]

LPDEBUG_EVENT = ctypes.POINTER(DEBUG_EVENT)

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
