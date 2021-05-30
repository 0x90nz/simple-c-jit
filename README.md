# Simple C JIT

This is a *very* simple example of JIT in C. The initial implementation was
written over the course of an afternoon and extended a little afterward so don't
expect too much. 

It assembles on-the-fly to x86\_64 assembly. I've tested it on Linux, and while
in theory it should work on most POSIX platforms, supporting a wide range of
platforms isn't exactly within scope for this simple project.

It implements a kind of forth-like language, but incredibly restricted. Only
simple arithmetic (addition and subtraction) as well as a few primitives ('.',
'emit', 'cr', 'dup') are supported. 

Control flow is restricted to jumps, there is no call stack, at least usable by
compiled code. Labels are declared by using any name beginning with `!` and are
used by `go![label name]` words. Such a word pops the top of the stack and will
jump to the label if that value was -1. Otherwise it will continue on. Note:
labels must be declared before they are used, there are no forward-jumps yet, as
I don't do multiple passes or label fixup.

There is very minimal safety as adding proper checks for e.g. for stack under or
overflow would be complicated and this is meant to be "simple". That means that
the stack *must* be even on exit, and it *must* not corrupt the application
data, or you'll just get segfaults.

For a simple "hello world" try this:

```text
33 100 108 114 111 87 32 111 108 108 101 72 emit emit emit emit emit emit emit emit emit emit emit emit cr
```

And for a more complicated one, using control structures, try this:

```text
10 33 100 108 114 111 87 32 111 108 108 101 72 !start dup emit 10 = not go!start
```

The interactive prompt can be exited with `.q` or `.quit` (or EOF). You can
disable execution by using `.e`, which is useful if debugging assembly output.

