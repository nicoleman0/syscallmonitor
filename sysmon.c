#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

// Syscall lookup table structure
typedef struct {
    long number;
    const char *name;
} syscall_entry;

// Common x86_64 syscalls
static const syscall_entry syscall_table[] = {
    {0, "read"},
    {1, "write"},
    {2, "open"},
    {3, "close"},
    {4, "stat"},
    {5, "fstat"},
    {6, "lstat"},
    {7, "poll"},
    {8, "lseek"},
    {9, "mmap"},
    {10, "mprotect"},
    {11, "munmap"},
    {12, "brk"},
    {13, "rt_sigaction"},
    {14, "rt_sigprocmask"},
    {15, "rt_sigreturn"},
    {16, "ioctl"},
    {17, "pread64"},
    {18, "pwrite64"},
    {19, "readv"},
    {20, "writev"},
    {21, "access"},
    {22, "pipe"},
    {23, "select"},
    {24, "sched_yield"},
    {25, "mremap"},
    {26, "msync"},
    {27, "mincore"},
    {28, "madvise"},
    {29, "shmget"},
    {30, "shmat"},
    {31, "shmctl"},
    {32, "dup"},
    {33, "dup2"},
    {34, "pause"},
    {35, "nanosleep"},
    {36, "getitimer"},
    {37, "alarm"},
    {38, "setitimer"},
    {39, "getpid"},
    {40, "sendfile"},
    {41, "socket"},
    {42, "connect"},
    {43, "accept"},
    {44, "sendto"},
    {45, "recvfrom"},
    {46, "sendmsg"},
    {47, "recvmsg"},
    {48, "shutdown"},
    {49, "bind"},
    {50, "listen"},
    {51, "getsockname"},
    {52, "getpeername"},
    {53, "socketpair"},
    {54, "setsockopt"},
    {55, "getsockopt"},
    {56, "clone"},
    {57, "fork"},
    {58, "vfork"},
    {59, "execve"},
    {60, "exit"},
    {61, "wait4"},
    {62, "kill"},
    {63, "uname"},
    {78, "getdents"},
    {79, "getcwd"},
    {80, "chdir"},
    {81, "fchdir"},
    {82, "rename"},
    {83, "mkdir"},
    {84, "rmdir"},
    {85, "creat"},
    {86, "link"},
    {87, "unlink"},
    {88, "symlink"},
    {89, "readlink"},
    {90, "chmod"},
    {91, "fchmod"},
    {92, "chown"},
    {93, "fchown"},
    {94, "lchown"},
    {95, "umask"},
    {96, "gettimeofday"},
    {97, "getrlimit"},
    {98, "getrusage"},
    {99, "sysinfo"},
    {102, "getuid"},
    {104, "getgid"},
    {105, "setuid"},
    {106, "setgid"},
    {107, "geteuid"},
    {108, "getegid"},
    {217, "getdents64"},
    {257, "openat"},
    {262, "newfstatat"},
    {263, "unlinkat"},
    {316, "renameat2"},
    {318, "getrandom"},
    {-1, NULL}  // Sentinel value
};

// Function to lookup syscall name by number
const char* get_syscall_name(long syscall_num) {
    for (int i = 0; syscall_table[i].name != NULL; i++) {
        if (syscall_table[i].number == syscall_num) {
            return syscall_table[i].name;
        }
    }
    return "unknown";
}

// Function to read a string from child process memory using PTRACE_PEEKDATA
// Returns a dynamically allocated string (caller must free)
// Returns NULL on error
char* read_string(pid_t child, unsigned long addr, size_t max_len) {
    if (addr == 0) {
        return NULL;
    }

    char *str = malloc(max_len + 1);
    if (!str) {
        return NULL;
    }

    size_t i = 0;
    while (i < max_len) {
        // Read one word (8 bytes on x86_64) at a time
        long data = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (data == -1) {
            free(str);
            return NULL;
        }

        // Copy bytes from the word
        for (int j = 0; j < sizeof(long) && i < max_len; j++, i++) {
            char c = (data >> (j * 8)) & 0xFF;
            str[i] = c;
            
            // Stop at null terminator
            if (c == '\0') {
                return str;
            }
        }
    }

    // Null-terminate if we hit max_len
    str[max_len] = '\0';
    return str;
}

int main(int argc, char *argv[]) {
    pid_t child;
    int status;
    struct user_regs_struct regs;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        return 1;
    }

    child = fork();

    if (child == 0) {
        // Child: allow tracing
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    } else {
        // Parent: tracer
        waitpid(child, &status, 0);

        while (1) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            if (WIFEXITED(status))
                break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            long syscall_num = regs.orig_rax;
            const char* syscall_name = get_syscall_name(syscall_num);
            
            printf("Syscall: %lld (%s)", syscall_num, syscall_name);
            
            // Read string arguments for specific syscalls
            char *arg_str = NULL;
            if (syscall_num == 2) {  // open
                arg_str = read_string(child, regs.rdi, 256);
                if (arg_str) {
                    printf(" filename=\"%s\"", arg_str);
                    free(arg_str);
                }
            } else if (syscall_num == 257) {  // openat
                arg_str = read_string(child, regs.rsi, 256);
                if (arg_str) {
                    printf(" filename=\"%s\"", arg_str);
                    free(arg_str);
                }
            } else if (syscall_num == 59) {  // execve
                arg_str = read_string(child, regs.rdi, 256);
                if (arg_str) {
                    printf(" filename=\"%s\"", arg_str);
                    free(arg_str);
                }
            } else if (syscall_num == 21) {  // access
                arg_str = read_string(child, regs.rdi, 256);
                if (arg_str) {
                    printf(" pathname=\"%s\"", arg_str);
                    free(arg_str);
                }
            } else if (syscall_num == 4 || syscall_num == 6) {  // stat, lstat
                arg_str = read_string(child, regs.rdi, 256);
                if (arg_str) {
                    printf(" pathname=\"%s\"", arg_str);
                    free(arg_str);
                }
            } else if (syscall_num == 87) {  // unlink
                arg_str = read_string(child, regs.rdi, 256);
                if (arg_str) {
                    printf(" pathname=\"%s\"", arg_str);
                    free(arg_str);
                }
            } else if (syscall_num == 263) {  // unlinkat
                arg_str = read_string(child, regs.rsi, 256);
                if (arg_str) {
                    printf(" pathname=\"%s\"", arg_str);
                    free(arg_str);
                }
            }
            
            printf("\n");

            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            if (WIFEXITED(status))
                break;

            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            printf("Return: %lld\n", regs.rax);
        }
    }
    return 0;
}


