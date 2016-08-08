#
# A PE analyzer by Joel Odom
#

import sys
import ctypes

import winapi
import ui
import winutils

PE_FILE = r'E:\Dropbox\aljack\etc\stack1.exe' # TODO: for development only

# start with a Python version check

if sys.version_info.major != 3 or sys.version_info.minor != 5:
  raise Exception(
    'Please run this script under Python 3.5 (or remove the version check if you feel brave).')

#
# Code to debug a runnnig process
# TODO: this is experimental stuff to move bit-by-bit into a real work flow
#

def debug_running_process():
  image_base_address = None # populated below as image loads

  # you can't hook this way because this will point to a different virtual address space
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
        print(ui.indent_string(winutils.exception_debug_info_to_str(
          process_info.hProcess, exception_debug_info)))
        print()

        if exception_debug_info.ExceptionRecord.ExceptionCode == winapi.EXCEPTION_BREAKPOINT:
          pass
          #print('BREAKPOINT!')

      elif debug_event.dwDebugEventCode == winapi.CREATE_PROCESS_DEBUG_EVENT:

        # CREATE_PROCESS_DEBUG_EVENT

        create_process_debug_info = debug_event.u.CreateProcessInfo
        print(ui.indent_string(
          winutils.create_process_debug_info_to_str(create_process_debug_info)))
        print()

        image_base_address = debug_event.u.CreateProcessInfo.lpBaseOfImage
        thread_handle = debug_event.u.CreateProcessInfo.hThread

        # load PE header from memory

        f = winutils.MemoryMetaFile(process_info.hProcess, image_base_address)

        # read the DOS header
        dos_header = winutils.read_dos_header(f)

        # seek to and read the PE header
        f.seek(dos_header.e_lfanew)
        pe_header = winutils.read_pe_header(f)

      elif debug_event.dwDebugEventCode == winapi.LOAD_DLL_DEBUG_EVENT:

        # LOAD_DLL_DEBUG_EVENT
        load_dll_debug_info = debug_event.u.LoadDll
        print(ui.indent_string(winutils.load_dll_debug_info_to_str(
          process_info.hProcess, load_dll_debug_info)))
        print()

  #      # dump the memory where the DLL (was / will be?) loaded
  #      winutils.output_memory_bytes_until_failure(
  #        process_info.hProcess, load_dll_debug_info.lpBaseOfDll)
  #      exit(0)

        # analyze the DLL in memory
        f = winutils.MemoryMetaFile(process_info.hProcess, load_dll_debug_info.lpBaseOfDll)
        print(winutils.analyze_pe_file(f))
        exit(0)

      # INTERLUDE: output information on the thread we are experimentally monitoring

      if thread_handle != None:
        context = winapi.WOW64_CONTEXT()
        context.ContextFlags = winapi.WOW64_CONTEXT_ALL
        print('  Thread State:')
        if not winapi.Wow64GetThreadContext(thread_handle, ctypes.pointer(context)):
            raise Exception('GetThreadContext failed')
        print(ui.indent_string(winutils.wow64_context_to_str(context), '    '))
        print()

      if image_base_address != None:

        # show the import table
        import_table_rva = pe_header.image_optional_header.DataDirectory[
          winapi.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        print('  Process Import Table (at RVA 0x%08x):' % import_table_rva)
        print()
        print(ui.indent_string(winutils.import_table_to_str(
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
  exit(0)

#
# commands, aliases and help strings
#

ALIASES = {
  'lp': 'load-pe',
  'x': 'exit',
  'rp': 'run-pe'
}

HELP_STRINGS = {
  'load-pe': 'Analyze a PE file on disk',
  'exit': 'Exit this program',
  'run-pe': 'Run a PE file in analysis mode'
}

def get_help():
  help_text = ''
  for (command, help_string) in HELP_STRINGS.items():
    command_and_alias = command
    for (alias, original) in ALIASES.items():
      if original == command:
        command_and_alias = '%s (%s)' % (original, alias)
    help_text += ('%s %s\n' % (command_and_alias.ljust(16), help_string))
  return help_text

#
# run UI loop
#

class CommandHandler():
  def handle(self, command):

    # substitute a command for any alias

    replacement = ALIASES.get(command, None)
    if replacement:
      command = replacement

    # handle the command

    if command == 'exit':
      exit(0)
    elif command == 'load-pe':
      with open(PE_FILE, 'rb') as f:
        # TODO: this doesn't actually "load" the PE file, it just reads it for now
        analysis = winutils.analyze_pe_file(f)
        main_ui.output(analysis)
    elif command == 'run-pe':
      debug_running_process()
    else:
      help_text = get_help()
      main_ui.output(help_text)


command_handler = CommandHandler()
main_ui = ui.UI(command_handler)

while True:
  main_ui.refresh() # command handler will exit
