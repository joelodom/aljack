'''
Various utilities by Joel Odom.

Copyright (c) 2016-2018 by Joel Odom, Marietta, GA

This work is licensed under the Creative Commons Attribution-ShareAlike 4.0
International License. To view a copy of this license,
visit http://creativecommons.org/licenses/by-sa/4.0/.
'''

DEFAULT_SPACER = '  ' # two spaces

def indent_string(s, spacer = DEFAULT_SPACER):
  return '%s%s' % (spacer, s.replace('\n', '\n%s' % spacer))

