#
# UI utilities by Joel Odom.
#

import os

DEFAULT_SPACER = '  ' # two spaces

def indent_string(s, spacer = DEFAULT_SPACER):
  return '%s%s' % (spacer, s.replace('\n', '\n%s' % spacer))

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

OUTPUT_HEIGHTS = 80
INPUT_HEIGHT = 10
TOTAL_WIDTH = 79*3

class UI():

  output1 = TextOutputBox(TOTAL_WIDTH//3, OUTPUT_HEIGHTS)
  output2 = TextOutputBox(TOTAL_WIDTH//3, OUTPUT_HEIGHTS)
  output3 = TextOutputBox(TOTAL_WIDTH//3, OUTPUT_HEIGHTS)

  input_box = TextOutputBox(TOTAL_WIDTH, INPUT_HEIGHT) # TODO: make some kind of input box

  def refresh(self):
    os.system('cls')
    for i in range(OUTPUT_HEIGHTS):
      print('%s%s%s' % (
        self.output1.get_line(i), self.output2.get_line(i), self.output3.get_line(i)))
    for i in range(INPUT_HEIGHT):
      print(self.input_box.get_line(i))
