# Simple C JIT

This is a *very* simple example of JIT in C, written over an afternoon. 

It assembles on-the-fly to x86\_64 assembly. I've tested it on Linux, and while
in theory it should work on most POSIX platforms, supporting a wide range of
platforms isn't exactly within scope for this simple project.

It implements a kind of forth-like language, but incredibly restricted. Only
simple arithmetic (addition and subtraction) as well as a few primitives ('.',
'emit' and 'cr') are supported. There's definitely wide scope to expand this
(for a start to have flow-control words). 

