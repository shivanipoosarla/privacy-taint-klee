# KLEE-LeakLens

KLEE-LeakLens is a post-processing tool for analyzing privacy violations detected by a taint-aware KLEE symbolic execution run (via `klee-taint`).

## Features

- Parses KLEE output logs to identify when tainted inputs reach untrusted sinks.
- Extracts concrete test inputs from `.ktest` files.
- Generates JSON reports for each violating test case.
- Supports user-defined list of sink functions.

## Sample sinks.txt

```
printf
send
fprintf
write
log
```
