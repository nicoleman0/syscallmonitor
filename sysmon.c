#define _POSIX_C_SOURCE 199309L
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <stdbool.h>

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

// Add color support for better readability
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

// Configuration flags
typedef struct {
    bool show_timestamps;
    bool show_return_values;
    bool show_arguments;
    bool use_colors;
    bool filter_syscalls;
    long *filtered_syscalls;
    int filter_count;
    bool count_mode;
} monitor_config;

// Statistics structure
typedef struct {
    long syscall_num;
    const char *name;
    unsigned long count;
    unsigned long errors;
    double total_time_us;
} syscall_stats;

// Improved read_string with better error handling
char* read_string(pid_t child, unsigned long addr, size_t max_len) {
    if (addr == 0) {
        return NULL;
    }

    char *str = malloc(max_len + 1);
    if (!str) {
        return NULL;
    }

    size_t i = 0;
    errno = 0;
    
    while (i < max_len) {
        long data = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (data == -1 && errno != 0) {
            free(str);
            return NULL;
        }

        for (int j = 0; j < sizeof(long) && i < max_len; j++, i++) {
            char c = (data >> (j * 8)) & 0xFF;
            str[i] = c;
            
            if (c == '\0') {
                return str;
            }
        }
    }

    str[max_len] = '\0';
    return str;
}

// Read buffer data (for read/write syscalls)
char* read_buffer(pid_t child, unsigned long addr, size_t len, size_t max_display) {
    if (addr == 0 || len == 0) {
        return NULL;
    }

    size_t display_len = (len < max_display) ? len : max_display;
    char *buf = malloc(display_len * 4 + 4);  // Enough for escape sequences
    if (!buf) {
        return NULL;
    }

    size_t buf_pos = 0;
    for (size_t i = 0; i < display_len; i += sizeof(long)) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, child, addr + i, NULL);
        if (data == -1 && errno != 0) {
            break;
        }

        for (int j = 0; j < sizeof(long) && (i + j) < display_len; j++) {
            unsigned char c = (data >> (j * 8)) & 0xFF;
            
            // Print printable chars, escape others
            if (c >= 32 && c <= 126) {
                buf[buf_pos++] = c;
            } else if (c == '\n') {
                buf[buf_pos++] = '\\';
                buf[buf_pos++] = 'n';
            } else if (c == '\t') {
                buf[buf_pos++] = '\\';
                buf[buf_pos++] = 't';
            } else {
                buf_pos += sprintf(buf + buf_pos, "\\x%02x", c);
            }
        }
    }
    
    buf[buf_pos] = '\0';
    if (len > max_display) {
        strcat(buf, "...");
    }
    
    return buf;
}

// Format syscall arguments based on syscall type
void format_syscall_args(pid_t child, long syscall_num, struct user_regs_struct *regs, 
                         char *output, size_t output_size, monitor_config *config) {
    if (!config->show_arguments) {
        output[0] = '\0';
        return;
    }

    char *str;
    switch (syscall_num) {
        case 0:  // read
            snprintf(output, output_size, "(fd=%lld, buf=0x%llx, count=%lld)", 
                    regs->rdi, regs->rsi, regs->rdx);
            break;
        case 1:  // write
            str = read_buffer(child, regs->rsi, regs->rdx, 32);
            if (str) {
                snprintf(output, output_size, "(fd=%lld, \"%s\", count=%lld)", 
                        regs->rdi, str, regs->rdx);
                free(str);
            } else {
                snprintf(output, output_size, "(fd=%lld, buf=0x%llx, count=%lld)", 
                        regs->rdi, regs->rsi, regs->rdx);
            }
            break;
        case 2:  // open
        case 21: // access
        case 87: // unlink
            str = read_string(child, regs->rdi, 256);
            if (str) {
                snprintf(output, output_size, "(\"%s\", flags=%lld)", str, regs->rsi);
                free(str);
            }
            break;
        case 257: // openat
        case 263: // unlinkat
            str = read_string(child, regs->rsi, 256);
            if (str) {
                snprintf(output, output_size, "(dfd=%lld, \"%s\", flags=%lld)", 
                        regs->rdi, str, regs->rdx);
                free(str);
            }
            break;
        case 59:  // execve
            str = read_string(child, regs->rdi, 256);
            if (str) {
                snprintf(output, output_size, "(\"%s\", ...)", str);
                free(str);
            }
            break;
        case 9:  // mmap
            snprintf(output, output_size, "(addr=0x%llx, len=%lld, prot=%lld, flags=%lld)", 
                    regs->rdi, regs->rsi, regs->rdx, regs->r10);
            break;
        default:
            snprintf(output, output_size, "(0x%llx, 0x%llx, 0x%llx)", 
                    regs->rdi, regs->rsi, regs->rdx);
    }
}

// Get timestamp in microseconds
double get_timestamp_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

// Check if syscall should be filtered
bool should_filter_syscall(long syscall_num, monitor_config *config) {
    if (!config->filter_syscalls) {
        return false;
    }
    
    for (int i = 0; i < config->filter_count; i++) {
        if (config->filtered_syscalls[i] == syscall_num) {
            return false;  // Show this syscall
        }
    }
    return true;  // Filter it out
}

// Update syscall statistics
void update_stats(syscall_stats *stats, int stats_count, long syscall_num, 
                  long return_val, double elapsed_time, int *total_count) {
    for (int i = 0; i < *total_count; i++) {
        if (stats[i].syscall_num == syscall_num) {
            stats[i].count++;
            stats[i].total_time_us += elapsed_time;
            if (return_val < 0) {
                stats[i].errors++;
            }
            return;
        }
    }
    
    // New syscall
    if (*total_count < stats_count) {
        stats[*total_count].syscall_num = syscall_num;
        stats[*total_count].name = get_syscall_name(syscall_num);
        stats[*total_count].count = 1;
        stats[*total_count].errors = (return_val < 0) ? 1 : 0;
        stats[*total_count].total_time_us = elapsed_time;
        (*total_count)++;
    }
}

// Print statistics summary
void print_statistics(syscall_stats *stats, int count) {
    printf("\n%s=== Syscall Statistics ===%s\n", COLOR_CYAN, COLOR_RESET);
    printf("%-20s %10s %10s %15s %15s\n", 
           "Syscall", "Count", "Errors", "Total Time(ms)", "Avg Time(μs)");
    printf("%-20s %10s %10s %15s %15s\n", 
           "-------", "-----", "------", "--------------", "------------");
    
    for (int i = 0; i < count; i++) {
        double avg_time = stats[i].total_time_us / stats[i].count;
        printf("%-20s %10lu %10lu %15.2f %15.2f\n",
               stats[i].name,
               stats[i].count,
               stats[i].errors,
               stats[i].total_time_us / 1000.0,
               avg_time);
    }
}

int main(int argc, char *argv[]) {
    pid_t child;
    int status;
    struct user_regs_struct regs;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program>\n", argv[0]);
        return 1;
    }

    // Initialize configuration
    monitor_config config = {
        .show_timestamps = true,
        .show_return_values = true,
        .show_arguments = true,
        .use_colors = isatty(STDOUT_FILENO),
        .filter_syscalls = false,
        .filtered_syscalls = NULL,
        .filter_count = 0,
        .count_mode = false
    };

    // Statistics tracking
    syscall_stats stats[256] = {0};
    int stats_count = 0;

    // Parse command line options
    int opt_index = 1;
    while (opt_index < argc && argv[opt_index][0] == '-') {
        if (strcmp(argv[opt_index], "--no-timestamp") == 0) {
            config.show_timestamps = false;
        } else if (strcmp(argv[opt_index], "--no-return") == 0) {
            config.show_return_values = false;
        } else if (strcmp(argv[opt_index], "--no-args") == 0) {
            config.show_arguments = false;
        } else if (strcmp(argv[opt_index], "--no-color") == 0) {
            config.use_colors = false;
        } else if (strcmp(argv[opt_index], "-c") == 0 || 
                   strcmp(argv[opt_index], "--count") == 0) {
            config.count_mode = true;
        } else if (strcmp(argv[opt_index], "-h") == 0 || 
                   strcmp(argv[opt_index], "--help") == 0) {
            printf("Usage: %s [options] <program> [args...]\n", argv[0]);
            printf("Options:\n");
            printf("  --no-timestamp   Don't show timestamps\n");
            printf("  --no-return      Don't show return values\n");
            printf("  --no-args        Don't show syscall arguments\n");
            printf("  --no-color       Disable colored output\n");
            printf("  -c, --count      Show statistics summary\n");
            printf("  -h, --help       Show this help\n");
            return 0;
        }
        opt_index++;
    }

    if (opt_index >= argc) {
        fprintf(stderr, "Usage: %s [options] <program> [args...]\n", argv[0]);
        return 1;
    }

    child = fork();

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[opt_index], &argv[opt_index]);
        perror("execvp");
        exit(1);
    } else {
        waitpid(child, &status, 0);
        double start_time = 0;
        bool in_syscall = false;
        long current_syscall = -1;

        while (1) {
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);
            waitpid(child, &status, 0);

            if (WIFEXITED(status))
                break;

            // Syscall entry
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            long syscall_num = regs.orig_rax;
            
            if (!in_syscall) {
                // Syscall entry point
                current_syscall = syscall_num;
                
                if (should_filter_syscall(syscall_num, &config)) {
                    in_syscall = true;
                    continue;
                }

                start_time = get_timestamp_us();
                const char* syscall_name = get_syscall_name(syscall_num);
                
                char args_buf[512];
                format_syscall_args(child, syscall_num, &regs, args_buf, sizeof(args_buf), &config);
                
                if (!config.count_mode) {
                    if (config.show_timestamps) {
                        printf("[%12.6f] ", start_time / 1000000.0);
                    }
                    
                    if (config.use_colors) {
                        printf("%s%s%s%s", COLOR_BLUE, syscall_name, COLOR_RESET, args_buf);
                    } else {
                        printf("%s%s", syscall_name, args_buf);
                    }
                }
                
                in_syscall = true;
            } else {
                // Syscall exit point
                if (should_filter_syscall(current_syscall, &config)) {
                    in_syscall = false;
                    continue;
                }
                
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                long return_val = regs.rax;
                double elapsed = get_timestamp_us() - start_time;

                if (config.count_mode) {
                    update_stats(stats, 256, current_syscall, return_val, elapsed, &stats_count);
                } else if (config.show_return_values) {
                    if (config.use_colors) {
                        const char *color = (return_val < 0) ? COLOR_RED : COLOR_GREEN;
                        printf(" = %s%lld%s", color, return_val, COLOR_RESET);
                    } else {
                        printf(" = %lld", return_val);
                    }
                    printf(" <%0.6f ms>\n", elapsed / 1000.0);
                } else {
                    printf("\n");
                }
                
                in_syscall = false;
            }
        }

        if (config.count_mode) {
            print_statistics(stats, stats_count);
        }
        
        if (config.filtered_syscalls) {
            free(config.filtered_syscalls);
        }
    }
    return 0;
}


