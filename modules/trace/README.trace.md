Trace Module
============

A wrapper DAQ module that records information about packet message verdicts,
injected packet messages, and IOCTL calls that it intercepts to a text file.
The Trace module presents the configuration stack as being capable of inline
interface operation, blocking, and injection.

Injected packet messages and unrecognized IOCTLs will have their contents
dumped in hex format.  Recognized IOCTLs will get more of a pretty-print style
output.  Verdicts on packet messages will be recorded on a single line with
some indentifying information from the packet message header.

By default, the output file will be named 'inline-out.txt' in the current
directory.  The default filename can be overridden with the 'file' variable. A
useful technique for debugging is to set the 'file' variable to /dev/stdout.

When running with multiple instances, the output filename will be mangled to
start with the instance ID followed by an underscore.  For example, the default
output filename would be '2_inline-out.txt' for the second instance.  The output
filename must be bare (no directory structure, relative nor absolute) in such a
configuration.
