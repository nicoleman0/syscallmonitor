# System Call Monitor (Linux x86_64)

A ptrace-based tool for monitoring system calls in Linux processes. Tracks entry and exit points, arguments, return values, and timing.

## How It Works

System calls are intercepted at two points:

```text
User code
   |
   |  syscall instruction
   v
[STOP #1]  ← entry (arguments visible)
Kernel executes syscall
[STOP #2]  ← exit (return value visible)
   |
User code resumes
```

Entry shows intent. Exit shows result.

Example:

```text
open("/etc/passwd", O_RDONLY) → -1 (EACCES)
```

You see both what was attempted and what happened.

## Understanding orig_rax vs rax

| Register   | Meaning                          |
| ---------- | -------------------------------- |
| `orig_rax` | Syscall number **requested**     |
| `rax`      | Return value **after execution** |

### Why Two Registers?

The kernel preserves the syscall number because rax gets overwritten during execution:

1. User places syscall number in rax
2. Kernel saves it to orig_rax
3. Kernel executes syscall (uses rax internally)
4. Kernel writes return value to rax

At entry:

- orig_rax = syscall number
- rax = syscall number (unchanged)

At exit:

- orig_rax = syscall number (preserved)
- rax = return value

Example:

```c
syscall(SYS_openat, "/etc/passwd", O_RDONLY);
```

| Stage | orig_rax | rax |
| ----- | -------- | --- |
| Entry | 257      | 257 |
| Exit  | 257      | 3   |

Reading rax at entry vs exit gives you different information. At entry it's the syscall number. At exit it's the result.
