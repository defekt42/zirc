# zirc
OpenBSD Hardened IRC Client that is terminal-based and written in C with Libevent + OpenSSL/TLS, designed for security.

## TL;DR: ZIRC-SEC v1.8 Security

- **Pledge (OpenBSD)**: Limits system calls (`stdio`, `inet`, `dns`, `rpath`, `tty`), tightening post-connection.
- **Unveil (OpenBSD)**: Restricts filesystem to SSL certs (read) and `/dev/tty` (read/write).
- **TLS 1.2+**: Strong encryption, certificate verification, secure ciphers.
- **Memory Zeroization**: Wipes passwords with `OPENSSL_cleanse`.
- **Robust Parsing**: Validates IRC messages, blocks CR/LF injection.
- **ANSI Stripping**: Prevents malicious terminal sequences (v1.7 fix).
- **Rate Limiting**: Caps at 25 msg/sec to avoid DoS.
- **Error Handling**: Checks calls, cleans resources, re-entrancy guards.
- **Reconnection**: 10 attempts max, race condition fixes (v1.7).
- **Buffer Safety**: Bounds checking, NULL checks, secure compilation.
- **Input Sanitization**: Filters invalid chars, rejects CR/LF in passwords.
- **Password Security**: Echo off, command-line warnings, zeroization.

**Long Winded**: Combines `pledge`, `unveil`, TLS, and parsing for robust security, with v1.7/v1.8 fixes. Degrades gracefully on non-OpenBSD systems.
Security Features:
The ZIRC-SEC v1.8 IRC client is designed with a strong focus on security, incorporating multiple features to protect against common vulnerabilities and ensure safe operation. Below is a detailed description of its security-focused features, based on the provided code and comments:
1. TLS 1.2+ with Certificate Verification
•  Enforced TLS 1.2 or Higher: The client uses SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) to ensure strong encryption and protect against protocol downgrade attacks.
•  Mandatory Certificate Verification: Configured with SSL_VERIFY_PEER and hostname validation via X509_VERIFY_PARAM_set1_host, preventing man-in-the-middle (MITM) attacks. Failed verifications terminate the connection and trigger a reconnection.
•  Secure Cipher Configuration: Excludes weak ciphers (e.g., !aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!SEED) and disables compression (SSL_OP_NO_COMPRESSION) and renegotiation (SSL_OP_NO_RENEGOTIATION) to mitigate TLS vulnerabilities.
2. Sandboxing with pledge() and unveil() (OpenBSD)
•  Pledge System Call Restriction: On OpenBSD, pledge() restricts system calls to a minimal set (stdio inet dns rpath tty initially, tightening to stdio inet rpath tty post-connection), reducing the attack surface if compromised.
•  Unveil Filesystem Restrictions: unveil() limits filesystem access to essential paths (e.g., /etc/ssl/cert.pem, /dev/tty for password input). After configuration, unveil(NULL, NULL) locks down further access, preventing unauthorized file operations.
•  Graceful Degradation: On non-OpenBSD systems, the client warns users if sandboxing is unavailable, ensuring transparency about reduced security.
3. Memory Zeroization for Sensitive Data
•  Secure Data Wiping: Passwords and sensitive data are wiped using OPENSSL_cleanse() before deallocation (e.g., in get_secure_password and cleanup_and_exit_internal), preventing exposure in memory dumps or attacks.
•  Terminal Echo Control: Password input disables terminal echo (ECHO flag cleared via tcsetattr), ensuring passwords are not displayed during entry.
4. Robust IRC Message Parsing
•  Comprehensive Parsing: Handles IRC numerics, hostmasks, and CTCP with strict validation in handle_server_msg, preventing protocol-level attacks.
•  CR/LF Injection Prevention: User input and server messages are sanitized in sendln, replacing \r and \n with spaces to block protocol manipulation.
5. ANSI Escape Sequence Stripping
•  Terminal Attack Prevention: Strips raw ANSI escape sequences from server output in print_ts, safely handling valid IRC color codes (e.g., \x03 for colors, \x02 for bold) while dropping unauthorized sequences (e.g., CSI, OSC) that could manipulate the terminal.
•  Critical Fix (v1.7): Addresses ANSI escape sequence consumption to prevent bypass vulnerabilities, with bounds checking in the color code parser to avoid buffer overflows.
6. Rate Limiting
•  Message Rate Control: Enforces a limit of 25 messages per second in sendln, using send_count and last_send_time to mitigate flood-based denial-of-service (DoS) attacks and prevent accidental abuse.
7. Comprehensive Error Handling
•  Checked System Calls: All system calls are validated, with detailed error messages via ERR_error_string_n (OpenSSL) and strerror (system errors), ensuring no silent failures.
•  Resource Cleanup: Guaranteed on all error paths, preventing resource leaks (e.g., sockets, memory, file descriptors) that could be exploited. cleanup_and_exit_internal uses re-entrancy guards to avoid double-free or race conditions.
8. Reconnection and Resource Management
•  Race Condition Prevention: Reconnection logic in schedule_reconnect and reconnect_cb includes protections against race conditions and resource leaks. A v1.7 fix ensures proper cleanup of reconnection guards.
•  Controlled Reconnection: Limits to 10 attempts (MAX_RECONNECT_ATTEMPTS) with exponential backoff (up to 60 seconds), preventing infinite loops or excessive resource use.
9. Buffer Overflow and Null Pointer Protections
•  Bounds Checking: Enforced in string operations (e.g., snprintf, strncpy) with truncation warnings if buffers are exceeded (e.g., in write_raw_line).
•  Critical Fixes (v1.7): Adds NULL checks after strdup to prevent crashes and includes bounds checking in the color code parser to avoid buffer overflows.
10. Non-Blocking Cleanup
•  Graceful Shutdown: Uses deferred_cleanup_cb with a libevent timer for non-blocking cleanup, ensuring resources are released safely without deadlocks, even under heavy load or errors.
11. Secure Compilation Flags
•  Hardened Binary: Compiled with -fstack-protector-strong (stack-smashing protection), -fPIE -pie (position-independent executables), and -Wformat -Wformat-security (format string vulnerability prevention), hardening against common exploits.
12. Input Sanitization
•  Valid Character Filtering: User input is sanitized in handle_user_input and sanitize, allowing only valid characters (ASCII >= 0x20 or specific IRC control codes), replacing invalid ones with ?.
•  Password Validation: Rejects CR/LF in passwords, preventing injection attacks.
13. Secure Password Handling
•  Command-Line Warning: Alerts users to the risks of command-line password visibility in process lists, recommending the prompt option for secure input.
•  Secure Storage and Validation: Passwords are stored in dynamically allocated memory, zeroized after use, and validated for length and content to prevent overflows or injections.

ZIRC-SEC v1.8 employs a defense-in-depth approach, integrating TLS encryption, sandboxing, memory safety, input sanitization, and robust error handling. Features like pledge(), unveil(), ANSI escape stripping, rate limiting, and secure password management address specific attack vectors. Critical fixes in v1.7 and new unveil() support in v1.8 enhance vulnerability patching and filesystem restrictions, making this client a robust choice for secure IRC communication.


Usage: ./zirc-sec-stable-v1.8 irc.libera.chat 6697 your_nick prompt

zirc-sec-stable build:
cc -o zirc-sec-stable-v1.8 zirc-sec-stable-v1.8.c -I/usr/local/include -L/usr/local/lib -lssl -lcrypto -levent_openssl -levent_core -levent_extra -levent -O2 -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wformat -Wformat-security


Copyright © 2025 by defekt

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted, provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED “AS IS” AND DEFEKT DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL DEFEKT BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
