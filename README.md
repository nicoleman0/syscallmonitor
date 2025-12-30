# System Call Monitor (Linux x86_64)

## Basic Functionality

```csharp
User code
   |
   |  syscall instruction
   v
[STOP #1]  ← entry (args visible)
Kernel executes syscall
[STOP #2]  ← exit (return value visible)
   |
User code resumes
```

- Entry tells you intent
- Exit tells you impact

```bash
open("/etc/passwd") → -1
```

- Intent: sensitive file access
- Impact: failed (maybe blocked)

## Difference between orig_rax and rax

| Register   | Meaning                          |
| ---------- | -------------------------------- |
| `orig_rax` | Syscall number **requested**     |
| `rax`      | Return value **after execution** |

### Why two registers?

Because rax gets overwritten. When a syscall happens:

- User puts syscall number into rax
- Kernel copies it into orig_rax
- Kernel uses rax internally
- Kernel writes return value back into rax

So, at entry:

- orig_rax = syscall number
- rax = syscall number (still)

At exit:

- orig_rax = syscall number
- rax = return value

*Example:*

```c
syscall(SYS_openat, "/etc/passwd", O_RDONLY);
```