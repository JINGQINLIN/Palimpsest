from __future__ import annotations

from pathlib import Path

from pipeline.paths import STUB_HEADER_FILENAME


STUB_HEADER = r"""#ifndef RECOPILOT_STUBS_H
#define RECOPILOT_STUBS_H

#ifndef NULL
#define NULL ((void *)0)
#endif

/* Ghidra pseudo types */
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef void code;

typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef unsigned long long qword;

typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long long size_t;
typedef long long ssize_t;
typedef int pid_t;

typedef struct {
    ulonglong lo;
    ulonglong hi;
} _OWORD;
typedef unsigned char _BYTE;
typedef unsigned short _WORD;
typedef unsigned int _DWORD;
typedef unsigned long long _QWORD;

/* Ghidra decompiler helper macros */
#define CONCAT22(hi, lo) ((((uint)(ushort)(hi)) << 16) | (uint)(ushort)(lo))
#define CONCAT31(hi, lo) ((((uint)(hi) & 0x00ffffffU) << 8) | (uint)(byte)(lo))
#define CONCAT44(hi, lo) ((((ulonglong)(uint)(hi)) << 32) | (ulonglong)(uint)(lo))
#define CARRY4(x, y) ((uint)(x) > (0xffffffffU - (uint)(y)))
#define SCARRY4(x, y) ((((int)(x) < 0) == ((int)(y) < 0)) && \
                       (((int)((uint)(x) + (uint)(y)) < 0) != ((int)(x) < 0)))
#define SBORROW4(x, y) ((((int)(x) < 0) != ((int)(y) < 0)) && \
                        (((int)((uint)(x) - (uint)(y)) < 0) != ((int)(x) < 0)))

/* Common libc and Linux APIs */
int system(const char *command);
int execve(const char *pathname, char *const argv[], char *const envp[]);
int execle(const char *path, const char *arg, ...);
int execl(const char *path, const char *arg, ...);
int execlp(const char *file, const char *arg, ...);
void *popen(const char *command, const char *type);
pid_t fork(void);

int sprintf(char *str, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
char *strcpy(char *dest, const char *src);
char *strncpy(char *dest, const char *src, size_t n);
char *strcat(char *dest, const char *src);
char *strncat(char *dest, const char *src, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);

int socket(int domain, int type, int protocol);
ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 void *src_addr, void *addrlen);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const void *dest_addr, unsigned int addrlen);
uint16_t ntohs(uint16_t net16);
uint32_t ntohl(uint32_t net32);
uint16_t htons(uint16_t host16);
uint32_t htonl(uint32_t host32);
int ioctl(int fd, unsigned long request, ...);
int open(const char *pathname, int flags, ...);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
int close(int fd);
void (*signal(int signum, void (*handler)(int)))(int);
int select(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout);
void syslog(int priority, const char *format, ...);
char *getenv(const char *name);
int setenv(const char *name, const char *value, int overwrite);

int doSystemCmd(const char *format, ...);
int CsteSystem(const char *command);
int ExecShell(const char *command);
int ___system(const char *command);

#endif /* RECOPILOT_STUBS_H */
"""


def write_stub_header(codeql_dir: Path) -> None:
    codeql_dir.mkdir(parents=True, exist_ok=True)
    (codeql_dir / STUB_HEADER_FILENAME).write_text(STUB_HEADER, encoding="utf-8")
