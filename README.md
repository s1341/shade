shade
=====

This is a gdb plugin which can be used to visualize the dlmalloc heap.

It has been tested on 32bit android processes.


Usage
-----

Make sure that you have libc shared library loaded correctly in gdb.

Grab the libs from the device:
```
mkdir -p device_root/system
cd device_root/system
adb pull /system/lib .
```

Now set the solib search path in gdb:
```
gdb> set solib-search-path /path/to/device_root/system/lib
```

Now load shade:
```
gdb> source /path/to/shade/shade.py
```

You can now parse the heap using `dlparse`. You need to do this each time you land at a
breakpoint etc. so that you have fresh data structures.

You can then use the `dl*` commands. Read the source to see what's available.
