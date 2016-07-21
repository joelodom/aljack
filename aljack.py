#
# A PE analyzer by Joel Odom
#

import sys
import ctypes

import winapi
import utils
import winutils

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 5:
  raise Exception(
    'Please run this script under Python 3.5 (or remove the version check if you feel brave).')



#
# Analyze the PE file on disk
#

PE_FILE = r'E:\Dropbox\aljack\etc\stack1.exe'

#TODO: should be able to get this from memory now that we analyze in memory
pe_header = None # used later in debugging to find the address of modules

with open(PE_FILE, 'rb') as f:
  print('Information for PE file %s:' % PE_FILE)
  print()

  pe_header = winutils.analyze_pe_file(f)

print()

#
# Code to debug a runnnig process
#

image_base_address = None # populated below as image loads

# you can't really hook this way because this will point to a different virtual address space
#PRINTF_FUNC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_char_p)
#def printf_func(fmt):
#  print('PRINTF called with: %s' % fmt)
#  return len(fmt)
#printf_hook = PRINTF_FUNC(printf_func)

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

  callback_set = False

  while True: # debugger loop

    # wait for a debug event

    debug_event = winapi.DEBUG_EVENT()

    if not winapi.WaitForDebugEvent(ctypes.pointer(debug_event), winapi.INFINITE):
      #if winapi.GetLastError() == winapi.ERROR_SEM_TIMEOUT:
      #  continue
      raise Exception('WaitForDebugEvent failed')

    # handle the debug event

    print('Debug Event: %s' % winutils.debug_event_to_str(debug_event))
    print()

    if debug_event.dwDebugEventCode == winapi.EXCEPTION_DEBUG_EVENT:

      # EXCEPTION_DEBUG_EVENT
      exception_debug_info = debug_event.u.Exception
      print(utils.indent_string(winutils.exception_debug_info_to_str(
        process_info.hProcess, exception_debug_info)))
      print()

      if exception_debug_info.ExceptionRecord.ExceptionCode == winapi.EXCEPTION_BREAKPOINT:
        pass
        #print('BREAKPOINT!')

    elif debug_event.dwDebugEventCode == winapi.CREATE_PROCESS_DEBUG_EVENT:

      # CREATE_PROCESS_DEBUG_EVENT

      create_process_debug_info = debug_event.u.CreateProcessInfo
      print(utils.indent_string(
        winutils.create_process_debug_info_to_str(create_process_debug_info)))
      print()

      image_base_address = debug_event.u.CreateProcessInfo.lpBaseOfImage
      thread_handle = debug_event.u.CreateProcessInfo.hThread

      # reanalyze the PE file now that it's loaded
      f = winutils.MemoryMetaFile(process_info.hProcess, image_base_address)
      winutils.analyze_pe_file(f)
      exit(0)

    elif debug_event.dwDebugEventCode == winapi.LOAD_DLL_DEBUG_EVENT:

      # LOAD_DLL_DEBUG_EVENT
      load_dll_debug_info = debug_event.u.LoadDll
      print(utils.indent_string(winutils.load_dll_debug_info_to_str(
        process_info.hProcess, load_dll_debug_info)))
      print()

#      # dump the memory where the DLL (was / will be?) loaded
#      winutils.output_memory_bytes_until_failure(
#        process_info.hProcess, load_dll_debug_info.lpBaseOfDll)
#      exit(0)

    # INTERLUDE: output information on the thread we are experimentally monitoring

    if thread_handle != None:
      context = winapi.WOW64_CONTEXT()
      context.ContextFlags = winapi.WOW64_CONTEXT_ALL
      print('  Thread State:')
      if not winapi.Wow64GetThreadContext(thread_handle, ctypes.pointer(context)):
          raise Exception('GetThreadContext failed')
      print(utils.indent_string(winutils.wow64_context_to_str(context), '    '))
      print()

    if image_base_address != None:

      # show the import table
      import_table_rva = pe_header.image_optional_header.DataDirectory[
        winapi.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
      print('  Process Import Table (at RVA 0x%08x):' % import_table_rva)
      print()
      print(utils.indent_string(winutils.import_table_to_str(
        process_info.hProcess, image_base_address, import_table_rva), '    '))
      print()

      # see if we can find a function

      exit_address = winutils.lookup_function_from_imports(
        process_info.hProcess, image_base_address, import_table_rva, 'exit')

      if exit_address != None and not callback_set: # only do this once
#        print('  == IAT Hook Experiment == ')



#        print('  Address of exit: 0x%08x' % exit_address)
#
#        # see if we can change a function's address
#
#        gets_address = winutils.lookup_function_from_imports(
#          process_info.hProcess, image_base_address, import_table_rva, 'gets')
#        print('  Address of gets before: 0x%08x' % gets_address)
#
#        winutils.replace_function_address(
#          process_info.hProcess, image_base_address, import_table_rva, 'gets', exit_address)
#        gets_address = winutils.lookup_function_from_imports(
#          process_info.hProcess, image_base_address, import_table_rva, 'gets')
#        print('  Address of gets after: 0x%08x' % gets_address)
#        print()




#        # see if we can hook and send to Windows API
#
#        print('  Address of exit before: 0x%08x' % exit_address)
#
#        winutils.replace_function_address(
#          process_info.hProcess, image_base_address, import_table_rva, 'exit',
#          ctypes.windll.kernel32.DebugBreak) # uses different calling convention!!!
#        exit_address = winutils.lookup_function_from_imports(
#          process_info.hProcess, image_base_address, import_table_rva, 'exit')
#        print('  Address of exit after: 0x%08x' % exit_address)
#        print()

        callback_set = True

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
  print('Last Windows Error: %s' % winutils.get_last_error_string())
  print()
  raise ex
  #winapi.MessageBox(winapi.nullptr, error, str(ex), winapi.MB_ICONEXCLAMATION)

print('Done.')
