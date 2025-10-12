# zirc
BSD-friendly IRC client

Usage: ./zirc irc.libera.chat 6697 nick "#channel" "password"

Required Build Dependencies

pkg install readline openssl

The following external libraries must be available on your system and are linked using the -l flags in your compilation command.

OpenSSL / LibreSSL - Provides the necessary cryptographic functions and TLS/SSL protocol implementation (used for secure ports like 6697).

On modern BSD systems (especially OpenBSD), this usually refers to LibreSSL, which is often part of the base system or easily installed via packages/ports.
-lssl -lcrypto 

GNU Readline - Provides command-line editing, history management, and the crucial rl_callback_handler_install for non-blocking input.

-lreadline - This is a non-standard library and must be explicitly installed via the system's package or ports collection.

System Libraries
The core socket, network, and standard C functions are typically provided by the Standard C Library (libc) and other base libraries, so they do not require extra linker flags:

Network: sys/socket.h, netdb.h (for getaddrinfo)

Standard C/POSIX: stdio.h, stdlib.h, unistd.h, time.h, signal.h


Your current build command:
cc -Wall -O2 -std=c99 zirc_plus.c -lssl -lcrypto -lreadline -o zirc_plus

Build Command Breakdown:

1. cc: The C compiler.

2. -lssl -lcrypto: Links the TLS/SSL functionality.

3. -lreadline: Links the interactive command-line functionality.

4. -std=c99: Specifies the C99 standard, which is widely supported.

5. -o zirc_plus: Names the resulting executable file.
