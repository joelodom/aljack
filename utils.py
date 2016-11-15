#
# Various utilities by Joel Odom.
#

DEFAULT_SPACER = '  ' # two spaces

def indent_string(s, spacer = DEFAULT_SPACER):
  return '%s%s' % (spacer, s.replace('\n', '\n%s' % spacer))

