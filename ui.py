'''
UI utilities by Joel Odom.

Copyright (c) 2016-2018 by Joel Odom, Marietta, GA

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
International License. To view a copy of this license,
visit http://creativecommons.org/licenses/by-sa/4.0/.
'''

import os
import msvcrt
import sys


# TODO: Maybe create a generic command handler here?  At least stub the interface...



class StackUI(): # think of it as an interface, not a class
  '''
  An abstract class that defines an interface for a text-oriented UI.

  Inspired by RPN, but only intended for output.
  '''

  def set_prompt(self, text):
    '''
    Sets the prompt text.

    This should be a very short indication of the UI state.
    '''

  def set_short_message(self, text):
    '''
    Set the short message.

    This should be a one-line message to convey meta information, usually a short informational
    message about the most recent command.
    '''

  def push_output(self, text):
    '''
    Pushes output onto the output stack.
    '''

  def prompt(self):
    '''
    Starts the UI and prompts the user fer a command.

    Returns the command text.
    '''








#
# legacy implementation (TODO: needs a lot work)
#

class TextOutputBox():
  '''
  A UI component that simply displays text.
  '''

  def __init__(self, width, height):
    self.width = width # characters
    self.height = height # characters
    self.set_text('')

  def set_text(self, text):
    '''
    Set the text of this window.

    Lines longer than the window usuable width will be trimmed and lines below the
    usuable height will be discarded.  The usuable width and height are one character less
    than the actual width and height.
    '''

    self.lines = []

    # split into individual lines, ignoring lines below the usuable height
    lines = text.split('\n')[:self.height - 1]
    for line in lines:
      l = line[:self.width - 1] # ignore text past the usuable width
      self.lines.append('%s|' % l.ljust(self.width - 1))

    # add blank lines as necessary
    while len(self.lines) < self.height - 1:
      self.lines.append('%*s|' % (self.width - 1, ''))

    # add the bottom border line
    self.lines.append('-' * self.width)

    # sanity check
    assert(len(self.lines) == self.height)
    for line in self.lines:
      assert(len(line) == self.width)

  def get_line(self, i):
    '''
    Get the line at the specified index.

    The index is zero-based and should not exceed the (window height - 1).  The line will have the
    right border character added and the last line is a line of lower border characters.
    '''

    return self.lines[i]

OUTPUT_HEIGHTS = 59
INPUT_HEIGHT = 7 # must be at least 3
TOTAL_WIDTH = 70*3

class LegacyUI():

  output1 = TextOutputBox(TOTAL_WIDTH//3, OUTPUT_HEIGHTS)
  output2 = TextOutputBox(TOTAL_WIDTH//3, OUTPUT_HEIGHTS)
  output3 = TextOutputBox(TOTAL_WIDTH//3, OUTPUT_HEIGHTS)

  output_buffers = [] # outputs to the right of output3

  secondary_text = '' # meant to be only one line

  prompt_text = '' # text to display before the prompt

  def push_output(self, text):
    '''
    Displays output, pushing old output to the right.
    '''

    self.output_buffers.append(self.output3.lines)
    self.output3.lines = self.output2.lines
    self.output2.lines = self.output1.lines
    self.output1.set_text(text)

  def set_short_message(self, text):
    self.secondary_text = text

  def set_prompt(self, text):
    self.prompt_text = text

  def prompt(self):

    # display the output boxes
    os.system('cls')
    for i in range(OUTPUT_HEIGHTS):
      print('%s%s%s' % (
        self.output1.get_line(i), self.output2.get_line(i), self.output3.get_line(i)))

    # handle input box

    for i in range(INPUT_HEIGHT - 3):
      print()
    print(self.secondary_text)
    print()

    command = ''

    while True: # input loop

      # clear the current line and rewrite the command

      sys.stdout.write('\r')
      sys.stdout.write(' ' * TOTAL_WIDTH)
      sys.stdout.write('\r%s> %s' % (self.prompt_text, command))

      k = msvcrt.getch()

      if k == '\000' or k == b'\xe0': # an arrow key or something
        msvcrt.getch() # get the rest of the key information
        continue # drop it for now
      if k[0] == 27: # ESC
        # clear last output
        self.output1.lines = self.output2.lines
        self.output2.lines = self.output3.lines
        if len(self.output_buffers) > 0:
          self.output3.lines = self.output_buffers.pop()
        else:
          self.output3.set_text('')
        return self.prompt() # TODO: kind of sloppy
      elif k == b'\r':
        if len(command) == 0:
          return # nothing to report
        print()
        break # break and send command to handler
      elif k[0] == 8 and len(command) > 0: # backspace
        command = command[:-1]
      elif k[0] >= 32 and k[0] <= 126: # printable character range
        c = chr(k[0])
        sys.stdout.write(c)
        sys.stdout.flush()

        command += c

    return command
