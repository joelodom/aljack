'''
Windows API wrapper by Joel Odom.  Does not contain everything, so add as needed.

Copyright (c) 2016-2018 by Joel Odom, Marietta, GA

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
International License. To view a copy of this license,
visit http://creativecommons.org/licenses/by-sa/4.0/.

Comments that resemble C code are probably snippets from Windows header files,
and may be owned by another copyright holder.
'''

import sys
import ctypes
import ctypes.wintypes

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 7:
  raise Exception(
    'Please run this script under Python 3.7 (or remove the version check if you feel brave).')

nullptr = None

TRUE = 1
FALSE = 0

# not sure if this is correct
ULONG_PTR = ctypes.wintypes.PULONG
SIZE_T = ctypes.c_size_t
ULONGLONG = ctypes.c_ulonglong

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
PVOID = ctypes.wintypes.LPVOID

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
    ('ExceptionAddress', PVOID),
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

#define STATUS_WAIT_0                    ((DWORD   )0x00000000L)
#define STATUS_ABANDONED_WAIT_0          ((DWORD   )0x00000080L)
#define STATUS_USER_APC                  ((DWORD   )0x000000C0L)
#define STATUS_TIMEOUT                   ((DWORD   )0x00000102L)
#define STATUS_PENDING                   ((DWORD   )0x00000103L)
#define DBG_EXCEPTION_HANDLED            ((DWORD   )0x00010001L)
#define DBG_CONTINUE                     ((DWORD   )0x00010002L)
#define STATUS_SEGMENT_NOTIFICATION      ((DWORD   )0x40000005L)
#define DBG_TERMINATE_THREAD             ((DWORD   )0x40010003L)
#define DBG_TERMINATE_PROCESS            ((DWORD   )0x40010004L)
#define DBG_CONTROL_C                    ((DWORD   )0x40010005L)
#define DBG_PRINTEXCEPTION_C             ((DWORD   )0x40010006L)
#define DBG_RIPEXCEPTION                 ((DWORD   )0x40010007L)
#define DBG_CONTROL_BREAK                ((DWORD   )0x40010008L)
#define DBG_COMMAND_EXCEPTION            ((DWORD   )0x40010009L)
#define STATUS_GUARD_PAGE_VIOLATION      ((DWORD   )0x80000001L)
#define STATUS_DATATYPE_MISALIGNMENT     ((DWORD   )0x80000002L)
#define STATUS_BREAKPOINT                ((DWORD   )0x80000003L)
#define STATUS_SINGLE_STEP               ((DWORD   )0x80000004L)
#define STATUS_LONGJUMP                  ((DWORD   )0x80000026L)
#define STATUS_UNWIND_CONSOLIDATE        ((DWORD   )0x80000029L)
#define DBG_EXCEPTION_NOT_HANDLED        ((DWORD   )0x80010001L)
#define STATUS_ACCESS_VIOLATION          ((DWORD   )0xC0000005L)
#define STATUS_IN_PAGE_ERROR             ((DWORD   )0xC0000006L)
#define STATUS_INVALID_HANDLE            ((DWORD   )0xC0000008L)
#define STATUS_INVALID_PARAMETER         ((DWORD   )0xC000000DL)
#define STATUS_NO_MEMORY                 ((DWORD   )0xC0000017L)
#define STATUS_ILLEGAL_INSTRUCTION       ((DWORD   )0xC000001DL)
#define STATUS_NONCONTINUABLE_EXCEPTION  ((DWORD   )0xC0000025L)
#define STATUS_INVALID_DISPOSITION       ((DWORD   )0xC0000026L)
#define STATUS_ARRAY_BOUNDS_EXCEEDED     ((DWORD   )0xC000008CL)
#define STATUS_FLOAT_DENORMAL_OPERAND    ((DWORD   )0xC000008DL)
#define STATUS_FLOAT_DIVIDE_BY_ZERO      ((DWORD   )0xC000008EL)
#define STATUS_FLOAT_INEXACT_RESULT      ((DWORD   )0xC000008FL)
#define STATUS_FLOAT_INVALID_OPERATION   ((DWORD   )0xC0000090L)
#define STATUS_FLOAT_OVERFLOW            ((DWORD   )0xC0000091L)
#define STATUS_FLOAT_STACK_CHECK         ((DWORD   )0xC0000092L)
#define STATUS_FLOAT_UNDERFLOW           ((DWORD   )0xC0000093L)
#define STATUS_INTEGER_DIVIDE_BY_ZERO    ((DWORD   )0xC0000094L)
#define STATUS_INTEGER_OVERFLOW          ((DWORD   )0xC0000095L)
#define STATUS_PRIVILEGED_INSTRUCTION    ((DWORD   )0xC0000096L)
#define STATUS_STACK_OVERFLOW            ((DWORD   )0xC00000FDL)
#define STATUS_DLL_NOT_FOUND             ((DWORD   )0xC0000135L)
#define STATUS_ORDINAL_NOT_FOUND         ((DWORD   )0xC0000138L)
#define STATUS_ENTRYPOINT_NOT_FOUND      ((DWORD   )0xC0000139L)
#define STATUS_CONTROL_C_EXIT            ((DWORD   )0xC000013AL)
#define STATUS_DLL_INIT_FAILED           ((DWORD   )0xC0000142L)
#define STATUS_FLOAT_MULTIPLE_FAULTS     ((DWORD   )0xC00002B4L)
#define STATUS_FLOAT_MULTIPLE_TRAPS      ((DWORD   )0xC00002B5L)
#define STATUS_REG_NAT_CONSUMPTION       ((DWORD   )0xC00002C9L)
#define STATUS_STACK_BUFFER_OVERRUN      ((DWORD   )0xC0000409L)
#define STATUS_INVALID_CRUNTIME_PARAMETER ((DWORD   )0xC0000417L)
#define STATUS_ASSERTION_FAILURE         ((DWORD   )0xC0000420L)

STATUS_WAIT_0                    = 0x00000000
STATUS_ABANDONED_WAIT_0          = 0x00000080
STATUS_USER_APC                  = 0x000000C0
STATUS_TIMEOUT                   = 0x00000102
STATUS_PENDING                   = 0x00000103
DBG_EXCEPTION_HANDLED            = 0x00010001
DBG_CONTINUE                     = 0x00010002
STATUS_SEGMENT_NOTIFICATION      = 0x40000005
DBG_TERMINATE_THREAD             = 0x40010003
DBG_TERMINATE_PROCESS            = 0x40010004
DBG_CONTROL_C                    = 0x40010005
DBG_PRINTEXCEPTION_C             = 0x40010006
DBG_RIPEXCEPTION                 = 0x40010007
DBG_CONTROL_BREAK                = 0x40010008
DBG_COMMAND_EXCEPTION            = 0x40010009
STATUS_GUARD_PAGE_VIOLATION      = 0x80000001
STATUS_DATATYPE_MISALIGNMENT     = 0x80000002
STATUS_BREAKPOINT                = 0x80000003
STATUS_SINGLE_STEP               = 0x80000004
STATUS_LONGJUMP                  = 0x80000026
STATUS_UNWIND_CONSOLIDATE        = 0x80000029
DBG_EXCEPTION_NOT_HANDLED        = 0x80010001
STATUS_ACCESS_VIOLATION          = 0xC0000005
STATUS_IN_PAGE_ERROR             = 0xC0000006
STATUS_INVALID_HANDLE            = 0xC0000008
STATUS_INVALID_PARAMETER         = 0xC000000D
STATUS_NO_MEMORY                 = 0xC0000017
STATUS_ILLEGAL_INSTRUCTION       = 0xC000001D
STATUS_NONCONTINUABLE_EXCEPTION  = 0xC0000025
STATUS_INVALID_DISPOSITION       = 0xC0000026
STATUS_ARRAY_BOUNDS_EXCEEDED     = 0xC000008C
STATUS_FLOAT_DENORMAL_OPERAND    = 0xC000008D
STATUS_FLOAT_DIVIDE_BY_ZERO      = 0xC000008E
STATUS_FLOAT_INEXACT_RESULT      = 0xC000008F
STATUS_FLOAT_INVALID_OPERATION   = 0xC0000090
STATUS_FLOAT_OVERFLOW            = 0xC0000091
STATUS_FLOAT_STACK_CHECK         = 0xC0000092
STATUS_FLOAT_UNDERFLOW           = 0xC0000093
STATUS_INTEGER_DIVIDE_BY_ZERO    = 0xC0000094
STATUS_INTEGER_OVERFLOW          = 0xC0000095
STATUS_PRIVILEGED_INSTRUCTION    = 0xC0000096
STATUS_STACK_OVERFLOW            = 0xC00000FD
STATUS_DLL_NOT_FOUND             = 0xC0000135
STATUS_ORDINAL_NOT_FOUND         = 0xC0000138
STATUS_ENTRYPOINT_NOT_FOUND      = 0xC0000139
STATUS_CONTROL_C_EXIT            = 0xC000013A
STATUS_DLL_INIT_FAILED           = 0xC0000142
STATUS_FLOAT_MULTIPLE_FAULTS     = 0xC00002B4
STATUS_FLOAT_MULTIPLE_TRAPS      = 0xC00002B5
STATUS_REG_NAT_CONSUMPTION       = 0xC00002C9
STATUS_STACK_BUFFER_OVERRUN      = 0xC0000409
STATUS_INVALID_CRUNTIME_PARAMETER= 0xC0000417
STATUS_ASSERTION_FAILURE         = 0xC0000420

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
  ctypes.wintypes.LPVOID ]

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

#WINBASEAPI
#HLOCAL
#WINAPI
#LocalFree(
#    __deref HLOCAL hMem
#    );

LocalFree = ctypes.windll.kernel32.LocalFree
LocalFree.restype = ctypes.wintypes.HLOCAL
LocalFree.argtypes = [ ctypes.wintypes.HLOCAL ]

#define ERROR_SEM_TIMEOUT                121L

ERROR_SEM_TIMEOUT = 121

#typedef struct _SECURITY_ATTRIBUTES {
#    DWORD nLength;
#    LPVOID lpSecurityDescriptor;
#    BOOL bInheritHandle;
#} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

class SECURITY_ATTRIBUTES(ctypes.Structure):
  _fields_ = [
    ('nLength', ctypes.wintypes.DWORD),
    ('lpSecurityDescriptor', ctypes.wintypes.LPVOID),
    ('bInheritHandle', ctypes.wintypes.BOOL)
  ]

LPSECURITY_ATTRIBUTES = ctypes.POINTER(SECURITY_ATTRIBUTES)

#typedef struct _STARTUPINFOW {
#    DWORD   cb;
#    LPWSTR  lpReserved;
#    LPWSTR  lpDesktop;
#    LPWSTR  lpTitle;
#    DWORD   dwX;
#    DWORD   dwY;
#    DWORD   dwXSize;
#    DWORD   dwYSize;
#    DWORD   dwXCountChars;
#    DWORD   dwYCountChars;
#    DWORD   dwFillAttribute;
#    DWORD   dwFlags;
#    WORD    wShowWindow;
#    WORD    cbReserved2;
#    LPBYTE  lpReserved2;
#    HANDLE  hStdInput;
#    HANDLE  hStdOutput;
#    HANDLE  hStdError;
#} STARTUPINFOW, *LPSTARTUPINFOW;

class STARTUPINFOW(ctypes.Structure):
  _fields_ = [
    ('cb', ctypes.wintypes.DWORD),
    ('lpReserved', ctypes.wintypes.LPWSTR),
    ('lpDesktop', ctypes.wintypes.LPWSTR),
    ('lpTitle', ctypes.wintypes.LPWSTR),
    ('dwX', ctypes.wintypes.DWORD),
    ('dwY', ctypes.wintypes.DWORD),
    ('dwXSize', ctypes.wintypes.DWORD),
    ('dwYSize', ctypes.wintypes.DWORD),
    ('dwXCountChars', ctypes.wintypes.DWORD),
    ('dwYCountChars', ctypes.wintypes.DWORD),
    ('dwFillAttribute', ctypes.wintypes.DWORD),
    ('dwFlags', ctypes.wintypes.DWORD),
    ('wShowWindow', ctypes.wintypes.WORD),
    ('cbReserved2', ctypes.wintypes.WORD),
    ('lpReserved2', ctypes.wintypes.LPBYTE),
    ('hStdInput', ctypes.wintypes.HANDLE),
    ('hStdOutput', ctypes.wintypes.HANDLE),
    ('hStdError', ctypes.wintypes.HANDLE)
  ]

LPSTARTUPINFOW = ctypes.POINTER(STARTUPINFOW)

#typedef struct _PROCESS_INFORMATION {
#    HANDLE hProcess;
#    HANDLE hThread;
#    DWORD dwProcessId;
#    DWORD dwThreadId;
#} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

class PROCESS_INFORMATION(ctypes.Structure):
  _fields_ = [
    ('hProcess', ctypes.wintypes.HANDLE),
    ('hThread', ctypes.wintypes.HANDLE),
    ('dwProcessId', ctypes.wintypes.DWORD),
    ('dwThreadId', ctypes.wintypes.DWORD)
  ]

LPPROCESS_INFORMATION = ctypes.POINTER(PROCESS_INFORMATION)

#WINBASEAPI
#BOOL
#WINAPI
#CreateProcessW(
#    __in_opt    LPCWSTR lpApplicationName,
#    __inout_opt LPWSTR lpCommandLine,
#    __in_opt    LPSECURITY_ATTRIBUTES lpProcessAttributes,
#    __in_opt    LPSECURITY_ATTRIBUTES lpThreadAttributes,
#    __in        BOOL bInheritHandles,
#    __in        DWORD dwCreationFlags,
#    __in_opt    LPVOID lpEnvironment,
#    __in_opt    LPCWSTR lpCurrentDirectory,
#    __in        LPSTARTUPINFOW lpStartupInfo,
#    __out       LPPROCESS_INFORMATION lpProcessInformation
#    );

CreateProcess = ctypes.windll.kernel32.CreateProcessW
CreateProcess.restype = ctypes.wintypes.BOOL
CreateProcess.argtypes = [ ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR,
  LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, ctypes.wintypes.BOOL,
  ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID, ctypes.wintypes.LPCWSTR,
  LPSTARTUPINFOW, LPPROCESS_INFORMATION ]

#//
#// Process dwCreationFlag values
#//

#define DEBUG_PROCESS                     0x00000001
#define DEBUG_ONLY_THIS_PROCESS           0x00000002
#define CREATE_SUSPENDED                  0x00000004
#define DETACHED_PROCESS                  0x00000008

#define CREATE_NEW_CONSOLE                0x00000010
#define NORMAL_PRIORITY_CLASS             0x00000020
#define IDLE_PRIORITY_CLASS               0x00000040
#define HIGH_PRIORITY_CLASS               0x00000080

#define REALTIME_PRIORITY_CLASS           0x00000100
#define CREATE_NEW_PROCESS_GROUP          0x00000200
#define CREATE_UNICODE_ENVIRONMENT        0x00000400
#define CREATE_SEPARATE_WOW_VDM           0x00000800

#define CREATE_SHARED_WOW_VDM             0x00001000
#define CREATE_FORCEDOS                   0x00002000
#define BELOW_NORMAL_PRIORITY_CLASS       0x00004000
#define ABOVE_NORMAL_PRIORITY_CLASS       0x00008000

#define INHERIT_PARENT_AFFINITY           0x00010000
#define INHERIT_CALLER_PRIORITY           0x00020000    // Deprecated
#define CREATE_PROTECTED_PROCESS          0x00040000
#define EXTENDED_STARTUPINFO_PRESENT      0x00080000

#define PROCESS_MODE_BACKGROUND_BEGIN     0x00100000
#define PROCESS_MODE_BACKGROUND_END       0x00200000

#define CREATE_BREAKAWAY_FROM_JOB         0x01000000
#define CREATE_PRESERVE_CODE_AUTHZ_LEVEL  0x02000000
#define CREATE_DEFAULT_ERROR_MODE         0x04000000
#define CREATE_NO_WINDOW                  0x08000000

#define PROFILE_USER                      0x10000000
#define PROFILE_KERNEL                    0x20000000
#define PROFILE_SERVER                    0x40000000
#define CREATE_IGNORE_SYSTEM_DEFAULT      0x80000000

DEBUG_PROCESS                     = 0x00000001
DEBUG_ONLY_THIS_PROCESS           = 0x00000002
CREATE_SUSPENDED                  = 0x00000004
DETACHED_PROCESS                  = 0x00000008

CREATE_NEW_CONSOLE                = 0x00000010
NORMAL_PRIORITY_CLASS             = 0x00000020
IDLE_PRIORITY_CLASS               = 0x00000040
HIGH_PRIORITY_CLASS               = 0x00000080

REALTIME_PRIORITY_CLASS           = 0x00000100
CREATE_NEW_PROCESS_GROUP          = 0x00000200
CREATE_UNICODE_ENVIRONMENT        = 0x00000400
CREATE_SEPARATE_WOW_VDM           = 0x00000800

CREATE_SHARED_WOW_VDM             = 0x00001000
CREATE_FORCEDOS                   = 0x00002000
BELOW_NORMAL_PRIORITY_CLASS       = 0x00004000
ABOVE_NORMAL_PRIORITY_CLASS       = 0x00008000

INHERIT_PARENT_AFFINITY           = 0x00010000
INHERIT_CALLER_PRIORITY           = 0x00020000    # // Deprecated
CREATE_PROTECTED_PROCESS          = 0x00040000
EXTENDED_STARTUPINFO_PRESENT      = 0x00080000

PROCESS_MODE_BACKGROUND_BEGIN     = 0x00100000
PROCESS_MODE_BACKGROUND_END       = 0x00200000

CREATE_BREAKAWAY_FROM_JOB         = 0x01000000
CREATE_PRESERVE_CODE_AUTHZ_LEVEL  = 0x02000000
CREATE_DEFAULT_ERROR_MODE         = 0x04000000
CREATE_NO_WINDOW                  = 0x08000000

PROFILE_USER                      = 0x10000000
PROFILE_KERNEL                    = 0x20000000
PROFILE_SERVER                    = 0x40000000
CREATE_IGNORE_SYSTEM_DEFAULT      = 0x80000000

#define SIZE_OF_80387_REGISTERS      80

SIZE_OF_80387_REGISTERS = 80

#typedef struct _FLOATING_SAVE_AREA {
#    DWORD   ControlWord;
#    DWORD   StatusWord;
#    DWORD   TagWord;
#    DWORD   ErrorOffset;
#    DWORD   ErrorSelector;
#    DWORD   DataOffset;
#    DWORD   DataSelector;
#    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
#    DWORD   Cr0NpxState;
#} FLOATING_SAVE_AREA;

class FLOATING_SAVE_AREA(ctypes.Structure):
  _fields_ = [
    ('ControlWord', ctypes.wintypes.DWORD),
    ('StatusWord', ctypes.wintypes.DWORD),
    ('TagWord', ctypes.wintypes.DWORD),
    ('ErrorOffset', ctypes.wintypes.DWORD),
    ('ErrorSelector', ctypes.wintypes.DWORD),
    ('DataOffset', ctypes.wintypes.DWORD),
    ('DataSelector', ctypes.wintypes.DWORD),
    ('RegisterArea', ctypes.wintypes.BYTE * SIZE_OF_80387_REGISTERS),
    ('Cr0NpxState', ctypes.wintypes.DWORD),
  ]

#define MAXIMUM_SUPPORTED_EXTENSION     512

MAXIMUM_SUPPORTED_EXTENSION = 512

#typedef struct _CONTEXT {
#
#    //
#    // The flags values within this flag control the contents of
#    // a CONTEXT record.
#    //
#    // If the context record is used as an input parameter, then
#    // for each portion of the context record controlled by a flag
#    // whose value is set, it is assumed that that portion of the
#    // context record contains valid context. If the context record
#    // is being used to modify a threads context, then only that
#    // portion of the threads context will be modified.
#    //
#    // If the context record is used as an IN OUT parameter to capture
#    // the context of a thread, then only those portions of the thread's
#    // context corresponding to set flags will be returned.
#    //
#    // The context record is never used as an OUT only parameter.
#    //
#
#    DWORD ContextFlags;
#
#    //
#    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
#    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
#    // included in CONTEXT_FULL.
#    //
#
#    DWORD   Dr0;
#    DWORD   Dr1;
#    DWORD   Dr2;
#    DWORD   Dr3;
#    DWORD   Dr6;
#    DWORD   Dr7;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
#    //
#
#    FLOATING_SAVE_AREA FloatSave;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
#    //
#
#    DWORD   SegGs;
#    DWORD   SegFs;
#    DWORD   SegEs;
#    DWORD   SegDs;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_INTEGER.
#    //
#
#    DWORD   Edi;
#    DWORD   Esi;
#    DWORD   Ebx;
#    DWORD   Edx;
#    DWORD   Ecx;
#    DWORD   Eax;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_CONTROL.
#    //
#
#    DWORD   Ebp;
#    DWORD   Eip;
#    DWORD   SegCs;              // MUST BE SANITIZED
#    DWORD   EFlags;             // MUST BE SANITIZED
#    DWORD   Esp;
#    DWORD   SegSs;
#
#    //
#    // This section is specified/returned if the ContextFlags word
#    // contains the flag CONTEXT_EXTENDED_REGISTERS.
#    // The format and contexts are processor specific
#    //
#
#    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
#
#} CONTEXT;

# *** It is important to remember that a CONTEXT is different on different architectures. ***
class CONTEXT(ctypes.Structure):
  _fields_ = [
    ('ContextFlags', ctypes.wintypes.DWORD),
    ('Dr0', ctypes.wintypes.DWORD),
    ('Dr1', ctypes.wintypes.DWORD),
    ('Dr2', ctypes.wintypes.DWORD),
    ('Dr3', ctypes.wintypes.DWORD),
    ('Dr6', ctypes.wintypes.DWORD),
    ('Dr7', ctypes.wintypes.DWORD),
    ('FloatSave', FLOATING_SAVE_AREA),
    ('SegGs', ctypes.wintypes.DWORD),
    ('SegFs', ctypes.wintypes.DWORD),
    ('SegEs', ctypes.wintypes.DWORD),
    ('SegDs', ctypes.wintypes.DWORD),
    ('Edi', ctypes.wintypes.DWORD),
    ('Esi', ctypes.wintypes.DWORD),
    ('Ebx', ctypes.wintypes.DWORD),
    ('Edx', ctypes.wintypes.DWORD),
    ('Ecx', ctypes.wintypes.DWORD),
    ('Eax', ctypes.wintypes.DWORD),
    ('Ebp', ctypes.wintypes.DWORD),
    ('Eip', ctypes.wintypes.DWORD),
    ('SegCs', ctypes.wintypes.DWORD),
    ('EFlags', ctypes.wintypes.DWORD),
    ('Esp', ctypes.wintypes.DWORD),
    ('SegSs', ctypes.wintypes.DWORD),
    ('ExtendedRegisters', ctypes.wintypes.BYTE * MAXIMUM_SUPPORTED_EXTENSION)
  ]

#typedef CONTEXT *PCONTEXT;

PCONTEXT = ctypes.POINTER(CONTEXT)

#typedef PCONTEXT LPCONTEXT;

LPCONTEXT = PCONTEXT

#WINBASEAPI
#BOOL
#WINAPI
#GetThreadContext(
#    __in    HANDLE hThread,
#    __inout LPCONTEXT lpContext
#    );

GetThreadContext = ctypes.windll.kernel32.GetThreadContext
GetThreadContext.restype = ctypes.wintypes.BOOL
GetThreadContext.argtypes = [ ctypes.wintypes.HANDLE, LPCONTEXT ]

##define CONTEXT_i386    0x00010000    // this assumes that i386 and
##define CONTEXT_i486    0x00010000    // i486 have identical context records
#
#// end_wx86
#
##define CONTEXT_CONTROL         (CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
##define CONTEXT_INTEGER         (CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
##define CONTEXT_SEGMENTS        (CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
##define CONTEXT_FLOATING_POINT  (CONTEXT_i386 | 0x00000008L) // 387 state
##define CONTEXT_DEBUG_REGISTERS (CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
##define CONTEXT_EXTENDED_REGISTERS  (CONTEXT_i386 | 0x00000020L) // cpu specific extensions
#
##define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER |\
#                      CONTEXT_SEGMENTS)
#
##define CONTEXT_ALL             (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
#                                 CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | \
#                                 CONTEXT_EXTENDED_REGISTERS)
#
##define CONTEXT_XSTATE          (CONTEXT_i386 | 0x00000040L)

CONTEXT_i386    = 0x00010000
CONTEXT_i486    = 0x00010000

CONTEXT_CONTROL         = (CONTEXT_i386 | 0x00000001)
CONTEXT_INTEGER         = (CONTEXT_i386 | 0x00000002)
CONTEXT_SEGMENTS        = (CONTEXT_i386 | 0x00000004)
CONTEXT_FLOATING_POINT  = (CONTEXT_i386 | 0x00000008)
CONTEXT_DEBUG_REGISTERS = (CONTEXT_i386 | 0x00000010)
CONTEXT_EXTENDED_REGISTERS  = (CONTEXT_i386 | 0x00000020)

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS)

CONTEXT_ALL             = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |
                         CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |
                         CONTEXT_EXTENDED_REGISTERS)

CONTEXT_XSTATE          = (CONTEXT_i386 | 0x00000040)

#define WOW64_SIZE_OF_80387_REGISTERS      80

WOW64_SIZE_OF_80387_REGISTERS = 80

#typedef struct _WOW64_FLOATING_SAVE_AREA {
#    DWORD   ControlWord;
#    DWORD   StatusWord;
#    DWORD   TagWord;
#    DWORD   ErrorOffset;
#    DWORD   ErrorSelector;
#    DWORD   DataOffset;
#    DWORD   DataSelector;
#    BYTE    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
#    DWORD   Cr0NpxState;
#} WOW64_FLOATING_SAVE_AREA;

class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
  _fields_ = [
    ('ControlWord', ctypes.wintypes.DWORD),
    ('StatusWord', ctypes.wintypes.DWORD),
    ('TagWord', ctypes.wintypes.DWORD),
    ('ErrorOffset', ctypes.wintypes.DWORD),
    ('ErrorSelector', ctypes.wintypes.DWORD),
    ('DataOffset', ctypes.wintypes.DWORD),
    ('DataSelector', ctypes.wintypes.DWORD),
    ('RegisterArea', ctypes.wintypes.BYTE * WOW64_SIZE_OF_80387_REGISTERS),
    ('Cr0NpxState', ctypes.wintypes.DWORD),
  ]

#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512

WOW64_MAXIMUM_SUPPORTED_EXTENSION = 512

#//
#// Context Frame
#//
#//  This frame has a several purposes: 1) it is used as an argument to
#//  NtContinue, 2) is is used to constuct a call frame for APC delivery,
#//  and 3) it is used in the user level thread creation routines.
#//
#//  The layout of the record conforms to a standard call frame.
#//
#
#typedef struct _WOW64_CONTEXT {
#
#    //
#    // The flags values within this flag control the contents of
#    // a CONTEXT record.
#    //
#    // If the context record is used as an input parameter, then
#    // for each portion of the context record controlled by a flag
#    // whose value is set, it is assumed that that portion of the
#    // context record contains valid context. If the context record
#    // is being used to modify a threads context, then only that
#    // portion of the threads context will be modified.
#    //
#    // If the context record is used as an IN OUT parameter to capture
#    // the context of a thread, then only those portions of the thread's
#    // context corresponding to set flags will be returned.
#    //
#    // The context record is never used as an OUT only parameter.
#    //
#
#    DWORD ContextFlags;
#
#    //
#    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
#    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
#    // included in CONTEXT_FULL.
#    //
#
#    DWORD   Dr0;
#    DWORD   Dr1;
#    DWORD   Dr2;
#    DWORD   Dr3;
#    DWORD   Dr6;
#    DWORD   Dr7;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
#    //
#
#    WOW64_FLOATING_SAVE_AREA FloatSave;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
#    //
#
#    DWORD   SegGs;
#    DWORD   SegFs;
#    DWORD   SegEs;
#    DWORD   SegDs;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_INTEGER.
#    //
#
#    DWORD   Edi;
#    DWORD   Esi;
#    DWORD   Ebx;
#    DWORD   Edx;
#    DWORD   Ecx;
#    DWORD   Eax;
#
#    //
#    // This section is specified/returned if the
#    // ContextFlags word contians the flag CONTEXT_CONTROL.
#    //
#
#    DWORD   Ebp;
#    DWORD   Eip;
#    DWORD   SegCs;              // MUST BE SANITIZED
#    DWORD   EFlags;             // MUST BE SANITIZED
#    DWORD   Esp;
#    DWORD   SegSs;
#
#    //
#    // This section is specified/returned if the ContextFlags word
#    // contains the flag CONTEXT_EXTENDED_REGISTERS.
#    // The format and contexts are processor specific
#    //
#
#    BYTE    ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
#
#} WOW64_CONTEXT;

# *** It is important to remember that a CONTEXT is different on different architectures. ***
class WOW64_CONTEXT(ctypes.Structure):
  _fields_ = [
    ('ContextFlags', ctypes.wintypes.DWORD),
    ('Dr0', ctypes.wintypes.DWORD),
    ('Dr1', ctypes.wintypes.DWORD),
    ('Dr2', ctypes.wintypes.DWORD),
    ('Dr3', ctypes.wintypes.DWORD),
    ('Dr6', ctypes.wintypes.DWORD),
    ('Dr7', ctypes.wintypes.DWORD),
    ('FloatSave', WOW64_FLOATING_SAVE_AREA),
    ('SegGs', ctypes.wintypes.DWORD),
    ('SegFs', ctypes.wintypes.DWORD),
    ('SegEs', ctypes.wintypes.DWORD),
    ('SegDs', ctypes.wintypes.DWORD),
    ('Edi', ctypes.wintypes.DWORD),
    ('Esi', ctypes.wintypes.DWORD),
    ('Ebx', ctypes.wintypes.DWORD),
    ('Edx', ctypes.wintypes.DWORD),
    ('Ecx', ctypes.wintypes.DWORD),
    ('Eax', ctypes.wintypes.DWORD),
    ('Ebp', ctypes.wintypes.DWORD),
    ('Eip', ctypes.wintypes.DWORD),
    ('SegCs', ctypes.wintypes.DWORD),
    ('EFlags', ctypes.wintypes.DWORD),
    ('Esp', ctypes.wintypes.DWORD),
    ('SegSs', ctypes.wintypes.DWORD),
    ('ExtendedRegisters', ctypes.wintypes.BYTE * WOW64_MAXIMUM_SUPPORTED_EXTENSION)
  ]

#typedef WOW64_CONTEXT *PWOW64_CONTEXT;

PWOW64_CONTEXT = ctypes.POINTER(WOW64_CONTEXT)

#WINBASEAPI
#BOOL
#WINAPI
#Wow64GetThreadContext(
#    __in    HANDLE hThread,
#    __inout PWOW64_CONTEXT lpContext
#    );

Wow64GetThreadContext = ctypes.windll.kernel32.Wow64GetThreadContext
Wow64GetThreadContext.restype = ctypes.wintypes.BOOL
Wow64GetThreadContext.argtypes = [ ctypes.wintypes.HANDLE, PWOW64_CONTEXT ]

##define WOW64_CONTEXT_i386      0x00010000    // this assumes that i386 and
##define WOW64_CONTEXT_i486      0x00010000    // i486 have identical context records
#
##define WOW64_CONTEXT_CONTROL               (WOW64_CONTEXT_i386 | 0x00000001L) // SS:SP, CS:IP, FLAGS, BP
##define WOW64_CONTEXT_INTEGER               (WOW64_CONTEXT_i386 | 0x00000002L) // AX, BX, CX, DX, SI, DI
##define WOW64_CONTEXT_SEGMENTS              (WOW64_CONTEXT_i386 | 0x00000004L) // DS, ES, FS, GS
##define WOW64_CONTEXT_FLOATING_POINT        (WOW64_CONTEXT_i386 | 0x00000008L) // 387 state
##define WOW64_CONTEXT_DEBUG_REGISTERS       (WOW64_CONTEXT_i386 | 0x00000010L) // DB 0-3,6,7
##define WOW64_CONTEXT_EXTENDED_REGISTERS    (WOW64_CONTEXT_i386 | 0x00000020L) // cpu specific extensions
#
##define WOW64_CONTEXT_FULL      (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)
#
##define WOW64_CONTEXT_ALL       (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS | \
#                                 WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS | \
#                                 WOW64_CONTEXT_EXTENDED_REGISTERS)
#
##define WOW64_CONTEXT_XSTATE                (WOW64_CONTEXT_i386 | 0x00000040L)

WOW64_CONTEXT_i386     = 0x00010000
WOW64_CONTEXT_i486     = 0x00010000

WOW64_CONTEXT_CONTROL              = (WOW64_CONTEXT_i386 | 0x00000001)
WOW64_CONTEXT_INTEGER              = (WOW64_CONTEXT_i386 | 0x00000002)
WOW64_CONTEXT_SEGMENTS             = (WOW64_CONTEXT_i386 | 0x00000004)
WOW64_CONTEXT_FLOATING_POINT       = (WOW64_CONTEXT_i386 | 0x00000008)
WOW64_CONTEXT_DEBUG_REGISTERS      = (WOW64_CONTEXT_i386 | 0x00000010)
WOW64_CONTEXT_EXTENDED_REGISTERS   = (WOW64_CONTEXT_i386 | 0x00000020)

WOW64_CONTEXT_FULL     = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS)

WOW64_CONTEXT_ALL      = (WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER | WOW64_CONTEXT_SEGMENTS |
                         WOW64_CONTEXT_FLOATING_POINT | WOW64_CONTEXT_DEBUG_REGISTERS |
                         WOW64_CONTEXT_EXTENDED_REGISTERS)

WOW64_CONTEXT_XSTATE               = (WOW64_CONTEXT_i386 | 0x00000040)

#WINBASEAPI
#BOOL
#WINAPI
#ReadProcessMemory(
#    __in      HANDLE hProcess,
#    __in      LPCVOID lpBaseAddress,
#    __out_bcount_part(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
#    __in      SIZE_T nSize,
#    __out_opt SIZE_T * lpNumberOfBytesRead
#    );

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
ReadProcessMemory.restype = ctypes.wintypes.BOOL
ReadProcessMemory.argtypes = [ ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID,
  ctypes.wintypes.LPVOID, SIZE_T, ctypes.POINTER(SIZE_T) ]

#WINBASEAPI
#BOOL
#WINAPI
#WriteProcessMemory(
#    __in      HANDLE hProcess,
#    __in      LPVOID lpBaseAddress,
#    __in_bcount(nSize) LPCVOID lpBuffer,
#    __in      SIZE_T nSize,
#    __out_opt SIZE_T * lpNumberOfBytesWritten
#    );

WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
WriteProcessMemory.restype = ctypes.wintypes.BOOL
WriteProcessMemory.argtypes = [ ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID,
  ctypes.wintypes.LPCVOID, SIZE_T, ctypes.POINTER(SIZE_T) ]

#typedef struct _MEMORY_BASIC_INFORMATION {
#    PVOID BaseAddress;
#    PVOID AllocationBase;
#    DWORD AllocationProtect;
#    SIZE_T RegionSize;
#    DWORD State;
#    DWORD Protect;
#    DWORD Type;
#} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
  _fields_ = [
    ('BaseAddress', PVOID),
    ('AllocationBase', PVOID),
    ('AllocationProtect', ctypes.wintypes.DWORD),
    ('RegionSize', SIZE_T),
    ('State', ctypes.wintypes.DWORD),
    ('Protect', ctypes.wintypes.DWORD),
    ('Type', ctypes.wintypes.DWORD)
  ]

PMEMORY_BASIC_INFORMATION = ctypes.POINTER(MEMORY_BASIC_INFORMATION)

#WINBASEAPI
#SIZE_T
#WINAPI
#VirtualQueryEx(
#    __in     HANDLE hProcess,
#    __in_opt LPCVOID lpAddress,
#    __out_bcount_part(dwLength, return) PMEMORY_BASIC_INFORMATION lpBuffer,
#    __in     SIZE_T dwLength
#    );

VirtualQueryEx = ctypes.windll.kernel32.VirtualQueryEx
VirtualQueryEx.restype = SIZE_T
VirtualQueryEx.argtypes = [ ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID,
  PMEMORY_BASIC_INFORMATION, SIZE_T ]

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

class IMAGE_DOS_HEADER(ctypes.Structure):
  _fields_ = [
    ('e_magic', ctypes.wintypes.WORD),
    ('e_cblp', ctypes.wintypes.WORD),
    ('e_cp', ctypes.wintypes.WORD),
    ('e_crlc', ctypes.wintypes.WORD),
    ('e_cparhdr', ctypes.wintypes.WORD),
    ('e_minalloc', ctypes.wintypes.WORD),
    ('e_maxalloc', ctypes.wintypes.WORD),
    ('e_ss', ctypes.wintypes.WORD),
    ('e_sp', ctypes.wintypes.WORD),
    ('e_csum', ctypes.wintypes.WORD),
    ('e_ip', ctypes.wintypes.WORD),
    ('e_cs', ctypes.wintypes.WORD),
    ('e_lfarlc', ctypes.wintypes.WORD),
    ('e_ovno', ctypes.wintypes.WORD),
    ('e_res', ctypes.wintypes.WORD * 4),
    ('e_oemid', ctypes.wintypes.WORD),
    ('e_oeminfo', ctypes.wintypes.WORD),
    ('e_res2', ctypes.wintypes.WORD * 10),
    ('e_lfanew', ctypes.wintypes.LONG)
  ]

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

IMAGE_FILE_MACHINE_UNKNOWN          = 0
IMAGE_FILE_MACHINE_I386             = 0x014c
IMAGE_FILE_MACHINE_R3000            = 0x0162
IMAGE_FILE_MACHINE_R4000            = 0x0166
IMAGE_FILE_MACHINE_R10000           = 0x0168
IMAGE_FILE_MACHINE_WCEMIPSV2        = 0x0169
IMAGE_FILE_MACHINE_ALPHA            = 0x0184
IMAGE_FILE_MACHINE_SH3              = 0x01a2
IMAGE_FILE_MACHINE_SH3DSP           = 0x01a3
IMAGE_FILE_MACHINE_SH3E             = 0x01a4
IMAGE_FILE_MACHINE_SH4              = 0x01a6
IMAGE_FILE_MACHINE_SH5              = 0x01a8
IMAGE_FILE_MACHINE_ARM              = 0x01c0
IMAGE_FILE_MACHINE_THUMB            = 0x01c2
IMAGE_FILE_MACHINE_AM33             = 0x01d3
IMAGE_FILE_MACHINE_POWERPC          = 0x01F0
IMAGE_FILE_MACHINE_POWERPCFP        = 0x01f1
IMAGE_FILE_MACHINE_IA64             = 0x0200
IMAGE_FILE_MACHINE_MIPS16           = 0x0266
IMAGE_FILE_MACHINE_ALPHA64          = 0x0284
IMAGE_FILE_MACHINE_MIPSFPU          = 0x0366
IMAGE_FILE_MACHINE_MIPSFPU16        = 0x0466
IMAGE_FILE_MACHINE_AXP64            = IMAGE_FILE_MACHINE_ALPHA64
IMAGE_FILE_MACHINE_TRICORE          = 0x0520
IMAGE_FILE_MACHINE_CEF              = 0x0CEF
IMAGE_FILE_MACHINE_EBC              = 0x0EBC
IMAGE_FILE_MACHINE_AMD64            = 0x8664
IMAGE_FILE_MACHINE_M32R             = 0x9041
IMAGE_FILE_MACHINE_CEE              = 0xC0EE

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

IMAGE_FILE_RELOCS_STRIPPED          = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
IMAGE_FILE_LINE_NUMS_STRIPPED       = 0x0004
IMAGE_FILE_LOCAL_SYMS_STRIPPED      = 0x0008
IMAGE_FILE_AGGRESIVE_WS_TRIM        = 0x0010
IMAGE_FILE_LARGE_ADDRESS_AWARE      = 0x0020
IMAGE_FILE_BYTES_REVERSED_LO        = 0x0080
IMAGE_FILE_32BIT_MACHINE            = 0x0100
IMAGE_FILE_DEBUG_STRIPPED           = 0x0200
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  = 0x0400
IMAGE_FILE_NET_RUN_FROM_SWAP        = 0x0800
IMAGE_FILE_SYSTEM                   = 0x1000
IMAGE_FILE_DLL                      = 0x2000
IMAGE_FILE_UP_SYSTEM_ONLY           = 0x4000
IMAGE_FILE_BYTES_REVERSED_HI        = 0x8000

#  typedef struct _IMAGE_FILE_HEADER {
#    WORD    Machine;
#    WORD    NumberOfSections;
#    DWORD   TimeDateStamp;
#    DWORD   PointerToSymbolTable;
#    DWORD   NumberOfSymbols;
#    WORD    SizeOfOptionalHeader;
#    WORD    Characteristics;
#} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

class IMAGE_FILE_HEADER(ctypes.Structure):
  _fields_ = [
    ('Machine', ctypes.wintypes.WORD),
    ('NumberOfSections', ctypes.wintypes.WORD),
    ('TimeDateStamp', ctypes.wintypes.DWORD),
    ('PointerToSymbolTable', ctypes.wintypes.DWORD),
    ('NumberOfSymbols', ctypes.wintypes.DWORD),
    ('SizeOfOptionalHeader', ctypes.wintypes.WORD),
    ('Characteristics', ctypes.wintypes.WORD)
  ]

#typedef struct _IMAGE_DATA_DIRECTORY {
#    DWORD   VirtualAddress;
#    DWORD   Size;
#} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
  _fields_ = [
    ('VirtualAddress', ctypes.wintypes.DWORD),
    ('Size', ctypes.wintypes.DWORD)
  ]

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

#typedef struct _IMAGE_OPTIONAL_HEADER {
#    //
#    // Standard fields.
#    //
#
#    WORD    Magic;
#    BYTE    MajorLinkerVersion;
#    BYTE    MinorLinkerVersion;
#    DWORD   SizeOfCode;
#    DWORD   SizeOfInitializedData;
#    DWORD   SizeOfUninitializedData;
#    DWORD   AddressOfEntryPoint;
#    DWORD   BaseOfCode;
#    DWORD   BaseOfData;
#
#    //
#    // NT additional fields.
#    //
#
#    DWORD   ImageBase;
#    DWORD   SectionAlignment;
#    DWORD   FileAlignment;
#    WORD    MajorOperatingSystemVersion;
#    WORD    MinorOperatingSystemVersion;
#    WORD    MajorImageVersion;
#    WORD    MinorImageVersion;
#    WORD    MajorSubsystemVersion;
#    WORD    MinorSubsystemVersion;
#    DWORD   Win32VersionValue;
#    DWORD   SizeOfImage;
#    DWORD   SizeOfHeaders;
#    DWORD   CheckSum;
#    WORD    Subsystem;
#    WORD    DllCharacteristics;
#    DWORD   SizeOfStackReserve;
#    DWORD   SizeOfStackCommit;
#    DWORD   SizeOfHeapReserve;
#    DWORD   SizeOfHeapCommit;
#    DWORD   LoaderFlags;
#    DWORD   NumberOfRvaAndSizes;
#    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
#} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
  _fields_ = [
    ('Magic', ctypes.wintypes.WORD),
    ('MajorLinkerVersion', ctypes.wintypes.BYTE),
    ('MinorLinkerVersion', ctypes.wintypes.BYTE),
    ('SizeOfCode', ctypes.wintypes.DWORD),
    ('SizeOfInitializedData', ctypes.wintypes.DWORD),
    ('SizeOfUninitializedData', ctypes.wintypes.DWORD),
    ('AddressOfEntryPoint', ctypes.wintypes.DWORD),
    ('BaseOfCode', ctypes.wintypes.DWORD),
    ('BaseOfData', ctypes.wintypes.DWORD),
    ('ImageBase', ctypes.wintypes.DWORD),
    ('SectionAlignment', ctypes.wintypes.DWORD),
    ('FileAlignment', ctypes.wintypes.DWORD),
    ('MajorOperatingSystemVersion', ctypes.wintypes.WORD),
    ('MinorOperatingSystemVersion', ctypes.wintypes.WORD),
    ('MajorImageVersion', ctypes.wintypes.WORD),
    ('MinorImageVersion', ctypes.wintypes.WORD),
    ('MajorSubsystemVersion', ctypes.wintypes.WORD),
    ('MinorSubsystemVersion', ctypes.wintypes.WORD),
    ('Win32VersionValue', ctypes.wintypes.DWORD),
    ('SizeOfImage', ctypes.wintypes.DWORD),
    ('SizeOfHeaders', ctypes.wintypes.DWORD),
    ('CheckSum', ctypes.wintypes.DWORD),
    ('Subsystem', ctypes.wintypes.WORD),
    ('DllCharacteristics', ctypes.wintypes.WORD),
    ('SizeOfStackReserve', ctypes.wintypes.DWORD),
    ('SizeOfStackCommit', ctypes.wintypes.DWORD),
    ('SizeOfHeapReserve', ctypes.wintypes.DWORD),
    ('SizeOfHeapCommit', ctypes.wintypes.DWORD),
    ('LoaderFlags', ctypes.wintypes.DWORD),
    ('NumberOfRvaAndSizes', ctypes.wintypes.DWORD),
    ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
  ]

#typedef struct _IMAGE_OPTIONAL_HEADER64 {
#    WORD        Magic;
#    BYTE        MajorLinkerVersion;
#    BYTE        MinorLinkerVersion;
#    DWORD       SizeOfCode;
#    DWORD       SizeOfInitializedData;
#    DWORD       SizeOfUninitializedData;
#    DWORD       AddressOfEntryPoint;
#    DWORD       BaseOfCode;
#    ULONGLONG   ImageBase;
#    DWORD       SectionAlignment;
#    DWORD       FileAlignment;
#    WORD        MajorOperatingSystemVersion;
#    WORD        MinorOperatingSystemVersion;
#    WORD        MajorImageVersion;
#    WORD        MinorImageVersion;
#    WORD        MajorSubsystemVersion;
#    WORD        MinorSubsystemVersion;
#    DWORD       Win32VersionValue;
#    DWORD       SizeOfImage;
#    DWORD       SizeOfHeaders;
#    DWORD       CheckSum;
#    WORD        Subsystem;
#    WORD        DllCharacteristics;
#    ULONGLONG   SizeOfStackReserve;
#    ULONGLONG   SizeOfStackCommit;
#    ULONGLONG   SizeOfHeapReserve;
#    ULONGLONG   SizeOfHeapCommit;
#    DWORD       LoaderFlags;
#    DWORD       NumberOfRvaAndSizes;
#    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
#} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
  _fields_ = [
    ('Magic', ctypes.wintypes.WORD),
    ('MajorLinkerVersion', ctypes.wintypes.BYTE),
    ('MinorLinkerVersion', ctypes.wintypes.BYTE),
    ('SizeOfCode', ctypes.wintypes.DWORD),
    ('SizeOfInitializedData', ctypes.wintypes.DWORD),
    ('SizeOfUninitializedData', ctypes.wintypes.DWORD),
    ('AddressOfEntryPoint', ctypes.wintypes.DWORD),
    ('BaseOfCode', ctypes.wintypes.DWORD),
    ('ImageBase', ULONGLONG),
    ('SectionAlignment', ctypes.wintypes.DWORD),
    ('FileAlignment', ctypes.wintypes.DWORD),
    ('MajorOperatingSystemVersion', ctypes.wintypes.WORD),
    ('MinorOperatingSystemVersion', ctypes.wintypes.WORD),
    ('MajorImageVersion', ctypes.wintypes.WORD),
    ('MinorImageVersion', ctypes.wintypes.WORD),
    ('MajorSubsystemVersion', ctypes.wintypes.WORD),
    ('MinorSubsystemVersion', ctypes.wintypes.WORD),
    ('Win32VersionValue', ctypes.wintypes.DWORD),
    ('SizeOfImage', ctypes.wintypes.DWORD),
    ('SizeOfHeaders', ctypes.wintypes.DWORD),
    ('CheckSum', ctypes.wintypes.DWORD),
    ('Subsystem', ctypes.wintypes.WORD),
    ('DllCharacteristics', ctypes.wintypes.WORD),
    ('SizeOfStackReserve', ULONGLONG),
    ('SizeOfStackCommit', ULONGLONG),
    ('SizeOfHeapReserve', ULONGLONG),
    ('SizeOfHeapCommit', ULONGLONG),
    ('LoaderFlags', ctypes.wintypes.DWORD),
    ('NumberOfRvaAndSizes', ctypes.wintypes.DWORD),
    ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
  ]

#define IMAGE_SIZEOF_SHORT_NAME              8
IMAGE_SIZEOF_SHORT_NAME = 8

#typedef struct _IMAGE_SECTION_HEADER {
#    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
#    union {
#            DWORD   PhysicalAddress;
#            DWORD   VirtualSize;
#    } Misc;
#    DWORD   VirtualAddress;
#    DWORD   SizeOfRawData;
#    DWORD   PointerToRawData;
#    DWORD   PointerToRelocations;
#    DWORD   PointerToLinenumbers;
#    WORD    NumberOfRelocations;
#    WORD    NumberOfLinenumbers;
#    DWORD   Characteristics;
#} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

class IMAGE_SECTION_HEADER(ctypes.Structure):
  class Misc(ctypes.Union):
    _fields_ = [
      ('PhysicalAddress', ctypes.wintypes.DWORD),
      ('VirtualSize', ctypes.wintypes.DWORD)
    ]

  _fields_ = [
    ('Name', ctypes.wintypes.BYTE * IMAGE_SIZEOF_SHORT_NAME),
    ('Misc', Misc),
    ('VirtualAddress', ctypes.wintypes.DWORD),
    ('SizeOfRawData', ctypes.wintypes.DWORD),
    ('PointerToRawData', ctypes.wintypes.DWORD),
    ('PointerToRelocations', ctypes.wintypes.DWORD),
    ('PointerToLinenumbers', ctypes.wintypes.DWORD),
    ('NumberOfRelocations', ctypes.wintypes.WORD),
    ('NumberOfLinenumbers', ctypes.wintypes.WORD),
    ('Characteristics', ctypes.wintypes.DWORD)
  ]

#WINBASEAPI
#FARPROC
#WINAPI
#GetProcAddress (
#    __in HMODULE hModule,
#    __in LPCSTR lpProcName
#    );

FARPROC = ctypes.wintypes.LPVOID # this may not be right

GetProcAddress = ctypes.windll.kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [ ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR ]

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

IMAGE_DIRECTORY_ENTRY_EXPORT         =  0
IMAGE_DIRECTORY_ENTRY_IMPORT         =  1
IMAGE_DIRECTORY_ENTRY_RESOURCE       =  2
IMAGE_DIRECTORY_ENTRY_EXCEPTION      =  3
IMAGE_DIRECTORY_ENTRY_SECURITY       =  4
IMAGE_DIRECTORY_ENTRY_BASERELOC      =  5
IMAGE_DIRECTORY_ENTRY_DEBUG          =  6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT      =  7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE   =  7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR      =  8
IMAGE_DIRECTORY_ENTRY_TLS            =  9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   = 11
IMAGE_DIRECTORY_ENTRY_IAT            = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

#typedef struct _IMAGE_IMPORT_DESCRIPTOR {
#    union {
#        DWORD   Characteristics;            // 0 for terminating null import descriptor
#        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
#    } DUMMYUNIONNAME;
#    DWORD   TimeDateStamp;                  // 0 if not bound,
#                                            // -1 if bound, and real date\time stamp
#                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
#                                            // O.W. date/time stamp of DLL bound to (Old BIND)
#
#    DWORD   ForwarderChain;                 // -1 if no forwarders
#    DWORD   Name;
#    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
#} IMAGE_IMPORT_DESCRIPTOR;
#typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;

class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
  class DUMMYUNIONNAME(ctypes.Union):
    _fields_ = [
      ('Characteristics', ctypes.wintypes.DWORD),
      ('OriginalFirstThunk', ctypes.wintypes.DWORD)
    ]

  _fields_ = [
    ('DUMMYUNIONNAME', DUMMYUNIONNAME),
    ('TimeDateStamp', ctypes.wintypes.DWORD),
    ('ForwarderChain', ctypes.wintypes.DWORD),
    ('Name', ctypes.wintypes.DWORD),
    ('FirstThunk', ctypes.wintypes.DWORD)
  ]

#typedef struct _IMAGE_IMPORT_BY_NAME {
#    WORD    Hint;
#    BYTE    Name[1];
#} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

class IMAGE_IMPORT_BY_NAME(ctypes.Structure):
  _fields_ = [
    ('Hint', ctypes.wintypes.WORD),
    ('Name', ctypes.wintypes.BYTE * 1) # GOOFED!!!  really the RVA of an ASCIIZ string
  ]

#define EXCEPTION_ACCESS_VIOLATION          STATUS_ACCESS_VIOLATION
#define EXCEPTION_DATATYPE_MISALIGNMENT     STATUS_DATATYPE_MISALIGNMENT
#define EXCEPTION_BREAKPOINT                STATUS_BREAKPOINT
#define EXCEPTION_SINGLE_STEP               STATUS_SINGLE_STEP
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     STATUS_ARRAY_BOUNDS_EXCEEDED
#define EXCEPTION_FLT_DENORMAL_OPERAND      STATUS_FLOAT_DENORMAL_OPERAND
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        STATUS_FLOAT_DIVIDE_BY_ZERO
#define EXCEPTION_FLT_INEXACT_RESULT        STATUS_FLOAT_INEXACT_RESULT
#define EXCEPTION_FLT_INVALID_OPERATION     STATUS_FLOAT_INVALID_OPERATION
#define EXCEPTION_FLT_OVERFLOW              STATUS_FLOAT_OVERFLOW
#define EXCEPTION_FLT_STACK_CHECK           STATUS_FLOAT_STACK_CHECK
#define EXCEPTION_FLT_UNDERFLOW             STATUS_FLOAT_UNDERFLOW
#define EXCEPTION_INT_DIVIDE_BY_ZERO        STATUS_INTEGER_DIVIDE_BY_ZERO
#define EXCEPTION_INT_OVERFLOW              STATUS_INTEGER_OVERFLOW
#define EXCEPTION_PRIV_INSTRUCTION          STATUS_PRIVILEGED_INSTRUCTION
#define EXCEPTION_IN_PAGE_ERROR             STATUS_IN_PAGE_ERROR
#define EXCEPTION_ILLEGAL_INSTRUCTION       STATUS_ILLEGAL_INSTRUCTION
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  STATUS_NONCONTINUABLE_EXCEPTION
#define EXCEPTION_STACK_OVERFLOW            STATUS_STACK_OVERFLOW
#define EXCEPTION_INVALID_DISPOSITION       STATUS_INVALID_DISPOSITION
#define EXCEPTION_GUARD_PAGE                STATUS_GUARD_PAGE_VIOLATION
#define EXCEPTION_INVALID_HANDLE            STATUS_INVALID_HANDLE
#define EXCEPTION_POSSIBLE_DEADLOCK         STATUS_POSSIBLE_DEADLOCK

EXCEPTION_ACCESS_VIOLATION         = STATUS_ACCESS_VIOLATION
EXCEPTION_DATATYPE_MISALIGNMENT    = STATUS_DATATYPE_MISALIGNMENT
EXCEPTION_BREAKPOINT               = STATUS_BREAKPOINT
EXCEPTION_SINGLE_STEP              = STATUS_SINGLE_STEP
EXCEPTION_ARRAY_BOUNDS_EXCEEDED    = STATUS_ARRAY_BOUNDS_EXCEEDED
EXCEPTION_FLT_DENORMAL_OPERAND     = STATUS_FLOAT_DENORMAL_OPERAND
EXCEPTION_FLT_DIVIDE_BY_ZERO       = STATUS_FLOAT_DIVIDE_BY_ZERO
EXCEPTION_FLT_INEXACT_RESULT       = STATUS_FLOAT_INEXACT_RESULT
EXCEPTION_FLT_INVALID_OPERATION    = STATUS_FLOAT_INVALID_OPERATION
EXCEPTION_FLT_OVERFLOW             = STATUS_FLOAT_OVERFLOW
EXCEPTION_FLT_STACK_CHECK          = STATUS_FLOAT_STACK_CHECK
EXCEPTION_FLT_UNDERFLOW            = STATUS_FLOAT_UNDERFLOW
EXCEPTION_INT_DIVIDE_BY_ZERO       = STATUS_INTEGER_DIVIDE_BY_ZERO
EXCEPTION_INT_OVERFLOW             = STATUS_INTEGER_OVERFLOW
EXCEPTION_PRIV_INSTRUCTION         = STATUS_PRIVILEGED_INSTRUCTION
EXCEPTION_IN_PAGE_ERROR            = STATUS_IN_PAGE_ERROR
EXCEPTION_ILLEGAL_INSTRUCTION      = STATUS_ILLEGAL_INSTRUCTION
EXCEPTION_NONCONTINUABLE_EXCEPTION = STATUS_NONCONTINUABLE_EXCEPTION
EXCEPTION_STACK_OVERFLOW           = STATUS_STACK_OVERFLOW
EXCEPTION_INVALID_DISPOSITION      = STATUS_INVALID_DISPOSITION
EXCEPTION_GUARD_PAGE               = STATUS_GUARD_PAGE_VIOLATION
EXCEPTION_INVALID_HANDLE           = STATUS_INVALID_HANDLE
#TODO EXCEPTION_POSSIBLE_DEADLOCK        = STATUS_POSSIBLE_DEADLOCK
