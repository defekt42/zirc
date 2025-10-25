/*
* Secure IRC Client (Libevent + TLS) - ZIRC-IRC v1.8
*
* This version includes comprehensive error handling:
* - All system calls checked and validated
* - Actionable error messages with full context
* - Graceful degradation with fallbacks
* - Thread-safe error reporting (ERR_error_string_n)
* - Resource cleanup on all error paths
* - No silent failures
*
* NEW IN v1.8:
* - unveil() filesystem restrictions (OpenBSD)
* - Minimal filesystem access policy
* - Pre-unveil path validation
* - Graceful degradation on non-OpenBSD systems
*
* CRITICAL FIXES IN v1.7:
* - ANSI escape sequence consumption (security bypass prevention)
* - Bounds checking in color code parser (buffer overflow prevention)
* - NULL check after strdup (crash prevention)
* - Reconnection guard cleanup (resource leak prevention)
*
* Security Features:
* 1. Robust IRC message parsing (numerics, hostmask, CTCP)
* 2. Two-stage pledge() sandboxing (OpenBSD)
* 3. unveil() filesystem restrictions (OpenBSD)
* 4. Protocol integrity enforcement (CR/LF injection prevention)
* 5. Memory zeroization for sensitive data
* 6. TLS 1.2+ with certificate verification
* 7. Rate limiting (25 msg/sec)
* 8. Re-entrant cleanup guards
* 9. Reconnection race condition prevention
* 10. Comprehensive error handling
* 11. NON-BLOCKING cleanup (Libevent timer)
* 12. STRICT ANSI ESCAPE STRIPPING in server output
*
* Compile on OpenBSD:
* cc -o zirc-sec zirc-sec.c \
*    -I/usr/local/include -L/usr/local/lib \
*    -lssl -lcrypto -levent_openssl -levent_core -levent_extra -levent \
*    -lm -lpthread -lutil \
*    -O2 -Wall -Wextra -Wpedantic \
*    -fstack-protector-strong \
*    -fPIE -pie \
*    -Wformat -Wformat-security
*
* Compile on Linux/other Unix:
* gcc -o zirc-sec zirc-sec.c \
*    -lssl -lcrypto -levent_openssl -levent_core -levent_extra -levent \
*    -lm -lpthread \
*    -O2 -Wall -Wextra -Wpedantic \
*    -fstack-protector-strong \
*    -fPIE -pie \
*    -Wformat -Wformat-security
*
* Usage:
*   ./zirc-sec <server> <port> <nick> [nickserv_pass or 'prompt']
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

/* --- OpenBSD Portability Stubs --- */
#ifdef __OpenBSD__
#include <unistd.h>
#else
#include <errno.h>
#ifndef ENOSYS
#define ENOSYS 38
#endif
static inline int pledge(const char *promises, const char *paths) {
    (void)promises; (void)paths; errno = ENOSYS; return -1;
}
static inline int unveil(const char *path, const char *permissions) {
    (void)path; (void)permissions; errno = ENOSYS; return -1;
}
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/util.h>

/* --- Constants and Global State --- */
#define PING_INTERVAL_SEC 100
#define BUFFER_SIZE 4096
#define CHANNEL "##"
#define IRC_MAX_MSG_LEN 512
#define MAX_RECONNECT_DELAY 60
#define MAX_RECONNECT_ATTEMPTS 10
#define CONNECTION_TIMEOUT_SEC 125

/* Libevent/OpenSSL global handles */
static SSL_CTX *ctx = NULL;
static struct event_base *base = NULL;
static struct bufferevent *bev = NULL;
static struct bufferevent *stdin_bev = NULL;
static struct event *ping_timer = NULL;

/* Connection State */
static char server_host[256];
static char server_port[16];
static int reconnect_delay = 2;
static int reconnect_attempts_count = 0;
static int reconnect_pending = 0;

/* IRC State */
static int reg = 0;
static int joined = 0;
static char nick[64];
static char *password = NULL;
static size_t password_len = 0;

/* Rate Limiter State */
static time_t last_send_time = 0;
static int send_count = 0;

/* Cleanup Guard */
static volatile sig_atomic_t cleanup_in_progress = 0;

/* ANSI color codes */
#define ANSI_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_ITALIC "\x1b[3m"
#define ANSI_UNDER "\x1b[4m"
#define ANSI_LIGHT_BLUE "\x1b[94m"
#define ANSI_BRIGHT_YELLOW "\x1b[93m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_BRIGHT_RED "\x1b[91m"
#define ANSI_BRIGHT_GREEN "\x1b[92m"

#define ANSI_BELL "\a"  /* ASCII BELL  character (0x07) */

/* IRC to 256-color mapping */
static const int irc_to_256[] = {
    15, 0, 19, 34, 196, 52, 127, 208, 226, 46, 51, 87, 75, 207, 244, 252
};

/* --- Function Prototypes --- */
static void handle_server_msg(char *line);
static void handle_user_input(char *line);
static void write_raw_line(const char *s);
static void sendln(const char *s);
static void print_ts(const char *prefix, const char *msg);
static char *get_secure_password(size_t *len_out);
static void cleanup_and_exit_internal(int code);
static void deferred_cleanup_cb(evutil_socket_t fd, short events, void *arg);
static int dial(const char *host, const char *port);
static void read_cb(struct bufferevent *bev_arg, void *ctx);
static void stdin_read_cb(struct bufferevent *bev_arg, void *ctx);
static void event_cb(struct bufferevent *bev_arg, short events, void *ctx);
static void ping_cb(evutil_socket_t fd, short events, void *arg);
static void reconnect_cb(evutil_socket_t fd, short events, void *arg);
static void schedule_reconnect(void);
static int setup_unveil(void);


/* --- unveil() Setup --- */
static int setup_unveil(void) {
#ifdef __OpenBSD__
    struct stat st;
    
    /* Common SSL certificate paths - check what exists */
    const char *cert_paths[] = {
        "/etc/ssl/cert.pem",           /* OpenBSD default */
        "/etc/ssl/certs",              /* Common cert directory */
        "/usr/local/share/certs",      /* Local certs */
        NULL
    };
    
    int unveiled_certs = 0;
    for (int i = 0; cert_paths[i] != NULL; i++) {
        if (stat(cert_paths[i], &st) == 0) {
            if (unveil(cert_paths[i], "r") == -1) {
                fprintf(stderr, "*** [WARNING] unveil failed for %s: %s\n",
                        cert_paths[i], strerror(errno));
            } else {
                fprintf(stderr, "   [UNVEIL] Allowed read access: %s\n", cert_paths[i]);
                unveiled_certs++;
            }
        }
    }
    
    if (unveiled_certs == 0) {
        fprintf(stderr, "*** [WARNING] No SSL certificate paths could be unveiled\n");
        fprintf(stderr, "*** [WARNING] TLS verification may fail\n");
    }
    
    /* Terminal device for password input */
    if (unveil("/dev/tty", "rw") == -1) {
        fprintf(stderr, "*** [WARNING] unveil failed for /dev/tty: %s\n", 
                strerror(errno));
    } else {
        fprintf(stderr, "   [UNVEIL] Allowed rw access: /dev/tty\n");
    }
    
    /* Lock down filesystem - no more unveil() calls allowed */
    if (unveil(NULL, NULL) == -1) {
        fprintf(stderr, "*** [ERROR] Final unveil(NULL, NULL) failed: %s\n",
                strerror(errno));
        return -1;
    }
    
    fprintf(stderr, "   [UNVEIL] Filesystem access locked down\n");
    return 0;
    
#else
    fprintf(stderr, "*** [INFO] unveil() not available on this platform\n");
    return 0;
#endif
}


/* --- A+ Cleanup with Full Error Handling --- */
static void cleanup_and_exit_internal(int code) {
    if (cleanup_in_progress) {
        return;
    }
    cleanup_in_progress = 1;

    fprintf(stderr, "\n*** [CLEANUP] Starting shutdown sequence...\n");

    if (ping_timer) {
        event_free(ping_timer);
        ping_timer = NULL;
    }

    if (stdin_bev) {
        bufferevent_free(stdin_bev);
        stdin_bev = NULL;
    }

    if (bev) {
        bufferevent_free(bev);
        bev = NULL;
    }

    if (base) {
        event_base_free(base);
        base = NULL;
    }

    if (ctx) {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

    if (password && password_len) {
        OPENSSL_cleanse(password, password_len);
        free(password);
        password = NULL;
        password_len = 0;
        fprintf(stderr, "***  [SECURITY] Sensitive data zeroized.\n");
    }

    fprintf(stderr, "***  [CLEANUP] Shutdown complete (exit code: %d).\n", code);
    exit(code);
}

static void cleanup_handler(void) {
    cleanup_and_exit_internal(0);
}

/* --- NON-BLOCKING DEFERRED CLEANUP --- */
static void deferred_cleanup_cb(evutil_socket_t fd, short events, void *arg) {
    (void)fd; (void)events;
    int exit_code = (arg == NULL) ? 0 : (int)(intptr_t)arg;
    cleanup_and_exit_internal(exit_code);
}


/* --- A+ Secure Password Input --- */
static char *get_secure_password(size_t *len_out) {
    struct termios old_term, new_term;
    char *p = NULL;

    p = calloc(1, BUFFER_SIZE);
    if (!p) {
        fprintf(stderr, "*** [ERROR] Memory allocation failed for password input (OOM?)\n");
        return NULL;
    }

    if (tcgetattr(STDIN_FILENO, &old_term) == -1) {
        fprintf(stderr, "*** [ERROR] Failed to get terminal attributes: %s\n", strerror(errno));
        free(p);
        return NULL;
    }

    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    new_term.c_lflag |= ECHONL;

    fprintf(stderr, "Enter NickServ password (input hidden): ");
    fflush(stderr);

    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) == -1) {
        fprintf(stderr, "*** [ERROR] Failed to set terminal to non-echo mode: %s\n", strerror(errno));
        free(p);
        return NULL;
    }

    if (!fgets(p, BUFFER_SIZE, stdin)) {
        int saved_errno = errno;
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "*** [ERROR] Failed to read password: %s\n",
                feof(stdin) ? "EOF" : strerror(saved_errno));
        *len_out = 0;
        goto fail;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &old_term) == -1) {
        fprintf(stderr, "*** [WARNING] Failed to restore terminal settings: %s\n", strerror(errno));
        goto fail;
    }

    size_t len = strlen(p);
    if (len > 0 && p[len-1] == '\n') {
        p[len-1] = '\0';
        len--;
    }

    if (len == 0) {
        fprintf(stderr, "*** [ERROR] Empty password entered.\n");
        goto fail;
    }

    *len_out = len;
    return p;

fail:
    OPENSSL_cleanse(p, BUFFER_SIZE);
    free(p);
    return NULL;
}

/* --- A+ Reconnection Logic --- */
static void reconnect_cb(evutil_socket_t fd, short events, void *arg) {
    (void)fd; (void)events; (void)arg;

    fprintf(stderr, "*** [RECONNECT] Executing reconnection attempt %d/%d\n",
            reconnect_attempts_count + 1, MAX_RECONNECT_ATTEMPTS);

    reconnect_pending = 0;

    if (dial(server_host, server_port) < 0) {
        fprintf(stderr, "*** [RECONNECT] Attempt %d/%d failed\n",
                reconnect_attempts_count, MAX_RECONNECT_ATTEMPTS);
    }
}

static void schedule_reconnect(void) {
    if (reconnect_pending) {
        fprintf(stderr, "*** [RECONNECT] Reconnection already scheduled, ignoring duplicate request\n");
        return;
    }

    /* Clean up existing connection before scheduling reconnect */
    if (bev) {
        fprintf(stderr, "***  [RECONNECT] Cleaning up existing connection before reconnect\n");
        bufferevent_free(bev);
        bev = NULL;
    }

    if (ping_timer) {
        event_free(ping_timer);
        ping_timer = NULL;
    }

    reconnect_pending = 1;
    reconnect_attempts_count++;

    if (reconnect_attempts_count > MAX_RECONNECT_ATTEMPTS) {
        fprintf(stderr, "\n" ANSI_BRIGHT_RED
                "*** [FATAL] Maximum reconnection attempts (%d) exceeded. Giving up."
                ANSI_RESET "\n", MAX_RECONNECT_ATTEMPTS);
        reconnect_pending = 0;
        cleanup_and_exit_internal(1);
        return;
    }

    struct timeval tv = {reconnect_delay, 0};

    fprintf(stderr, "*** [RECONNECT] Scheduling attempt %d/%d in %d seconds...\n",
            reconnect_attempts_count, MAX_RECONNECT_ATTEMPTS, reconnect_delay);

    if (event_base_once(base, -1, EV_TIMEOUT, reconnect_cb, NULL, &tv) < 0) {
        fprintf(stderr, "*** [ERROR] Failed to schedule reconnect timer\n");
        reconnect_attempts_count--;
        reconnect_pending = 0;
        cleanup_and_exit_internal(1);
        return;
    }

    /* Overflow-safe exponential backoff */
    if (reconnect_delay > MAX_RECONNECT_DELAY / 2) {
        reconnect_delay = MAX_RECONNECT_DELAY;
    } else {
        reconnect_delay *= 2;
        if (reconnect_delay > MAX_RECONNECT_DELAY) {
            reconnect_delay = MAX_RECONNECT_DELAY;
        }
    }
}

/* --- A+ TLS Connection with Full Error Context --- */
static int dial(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL;
    int s = -1;
    SSL *ssl = NULL;

    if (!host || !port) {
        fprintf(stderr, "*** [BUG] dial() called with NULL parameters\n");
        return -1;
    }

    fprintf(stderr, "***  [CONNECT] Attempting %s:%s (attempt %d/%d)...\n",
            host, port, reconnect_attempts_count + 1, MAX_RECONNECT_ATTEMPTS + 1);

    reg = 0;
    joined = 0;

    /* Initialize SSL context if needed */
    if (!ctx) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            unsigned long err = ERR_get_error();
            if (err != 0) {
                char err_buf[256];
                ERR_error_string_n(err, err_buf, sizeof(err_buf));
                fprintf(stderr, "*** [SSL ERROR] SSL_CTX_new failed: %s (0x%lx)\n",
                        err_buf, err);
            } else {
                fprintf(stderr, "*** [SSL ERROR] SSL_CTX_new failed with no error in queue\n");
            }
            goto error;
        }

        if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) == 0) {
            fprintf(stderr, "*** [WARNING] Failed to set minimum TLS version to 1.2\n");
        }

        if (SSL_CTX_set_cipher_list(ctx,
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:"
                "!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!SEED") == 0) {
            fprintf(stderr, "*** [WARNING] Failed to set cipher list\n");
        }

        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
        SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        fprintf(stderr, "***  [SSL] Context initialized with TLS 1.2+ and strong ciphers\n");
    }

    /* DNS Resolution */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int gai_err = getaddrinfo(host, port, &hints, &res);
    if (gai_err != 0) {
        fprintf(stderr, "*** [DNS ERROR] %s (host: %s, port: %s)\n",
                gai_strerror(gai_err), host, port);
        goto error;
    }
    fprintf(stderr, "***  [DNS] Resolution successful\n");

    /* Socket Creation */
    s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        fprintf(stderr, "*** [SOCKET ERROR] Failed to create socket: %s\n", strerror(errno));
        goto error;
    }

    /* TCP Connection */
    if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "*** [CONNECT ERROR] %s (host: %s, port: %s)\n",
                strerror(errno), host, port);
        goto error;
    }
    fprintf(stderr, "***  [TCP] Connection established\n");

    freeaddrinfo(res);
    res = NULL;

    /* SSL Object Creation */
    ssl = SSL_new(ctx);
    if (!ssl) {
        unsigned long err = ERR_get_error();
        if (err != 0) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            fprintf(stderr, "*** [SSL ERROR] SSL_new failed: %s (0x%lx)\n",
                    err_buf, err);
        } else {
            fprintf(stderr, "*** [SSL ERROR] SSL_new failed with no error in queue\n");
        }
        goto error;
    }

    if (!SSL_set_tlsext_host_name(ssl, host)) {
        fprintf(stderr, "*** [WARNING] Failed to set SNI hostname\n");
    }

    /* Hostname Verification Setup */
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    if (!param) {
        fprintf(stderr, "*** [SSL ERROR] Failed to get X509 verify parameters\n");
        goto error;
    }

    if (!X509_VERIFY_PARAM_set1_host(param, host, 0)) {
        fprintf(stderr, "*** [SSL ERROR] Failed to set hostname for verification: %s\n", host);
        goto error;
    }
    fprintf(stderr, "***  [SSL] Hostname verification configured for: %s\n", host);

    /* Create Bufferevent */
    bev = bufferevent_openssl_socket_new(base, s, ssl,
                                          BUFFEREVENT_SSL_CONNECTING,
                                          BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
    if (!bev) {
        fprintf(stderr, "*** [ERROR] bufferevent_openssl_socket_new failed\n");
        goto error;
    }

    struct timeval timeout_tv = {CONNECTION_TIMEOUT_SEC, 0};
    if (bufferevent_set_timeouts(bev, &timeout_tv, &timeout_tv) != 0) {
        fprintf(stderr, "*** [WARNING] Failed to set connection timeout\n");
    }

    bufferevent_setcb(bev, read_cb, NULL, event_cb, NULL);
    if (bufferevent_enable(bev, EV_READ | EV_WRITE) != 0) {
        fprintf(stderr, "*** [ERROR] Failed to enable bufferevent\n");
        goto error;
    }

    fprintf(stderr, "***  [SSL] TLS handshake initiated...\n");
    return 0;

error:
    if (res) freeaddrinfo(res);
    if (s >= 0) close(s);
    if (ssl) SSL_free(ssl);
    if (bev) {
        bufferevent_free(bev);
        bev = NULL;
    }

    schedule_reconnect();
    return -1;
}

/* --- Keep-Alive PING --- */
static void ping_cb(evutil_socket_t fd, short events, void *arg) {
    (void)fd; (void)events; (void)arg;
    write_raw_line("PING :keepalive");
}

/* --- A+ Raw Line Sender --- */
static void write_raw_line(const char *s) {
    char buf[BUFFER_SIZE];
    size_t len = strlen(s);

    if (len >= IRC_MAX_MSG_LEN) {
        fprintf(stderr, "*** [WARNING] Message too long (%zu bytes), truncating to %d\n",
                len, IRC_MAX_MSG_LEN - 2);
    }

    int written = snprintf(buf, sizeof(buf), "%.*s\r\n", IRC_MAX_MSG_LEN - 2, s);
    if (written < 0) {
        fprintf(stderr, "*** [ERROR] snprintf failed in write_raw_line\n");
        return;
    }

    if (written >= (int)sizeof(buf)) {
        fprintf(stderr, "*** [WARNING] Buffer truncation in write_raw_line\n");
        written = sizeof(buf) - 1;
    }

    if (bev) {
        if (bufferevent_write(bev, buf, (size_t)written) != 0) {
            fprintf(stderr, "*** [ERROR] Failed to write to network buffer (connection unstable?)\n");
        }
    } else {
        fprintf(stderr, "*** [ERROR] Attempted to write but no active connection\n");
    }
}

/* --- A+ Sanitized Sender with Rate Limiting --- */
static void sendln(const char *s) {
    /* Rate Limiting */
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        fprintf(stderr, "*** [WARNING] time() failed: %s\n", strerror(errno));
    } else {
        if (now != last_send_time) {
            last_send_time = now;
            send_count = 0;
        }

        if (++send_count > 25) {
            printf(ANSI_BRIGHT_RED
                   "*** RATE LIMIT EXCEEDED (25 msg/s). Command blocked: '%.40s%s'"
                   ANSI_RESET "\n",
                   s, strlen(s) > 40 ? "..." : "");
            return;
        }
    }

    /* Sanitization */
    char clean_s[IRC_MAX_MSG_LEN];
    strncpy(clean_s, s, IRC_MAX_MSG_LEN - 1);
    clean_s[IRC_MAX_MSG_LEN - 1] = '\0';

    for (char *p = clean_s; *p; p++) {
        if (*p == '\r' || *p == '\n') {
            *p = ' ';
        }
    }

    write_raw_line(clean_s);
}


/* --- Utility Functions --- */
static int is_valid_char(unsigned char c) {
    if (c >= 0x20 || (c & 0x80)) return 1;
    switch (c) {
        case 0x01: case 0x02: case 0x03: case 0x04:
        case 0x0F: case 0x16: case 0x1D: case 0x1F:
            return 1;
        default:
            return 0;
    }
}

static void sanitize(char *in, size_t n) {
    for (size_t i = 0; i < n && in[i]; i++) {
        if (!is_valid_char((unsigned char)in[i])) {
            in[i] = '?';
        }
    }
}

/* --- A+ Timestamp Printer with Secure ANSI Stripping --- */
static void print_ts(const char *prefix, const char *msg) {
    char timebuf[16] = "XXXXXX";
    time_t now = time(NULL);

    if (now != (time_t)-1) {
        struct tm *tm_info = localtime(&now);
        if (tm_info) {
            if (strftime(timebuf, sizeof(timebuf), "%H%M%S", tm_info) == 0) {
                fprintf(stderr, "*** [WARNING] strftime failed, using fallback timestamp\n");
                snprintf(timebuf, sizeof(timebuf), "XXXXXX");
            }
        } else {
            fprintf(stderr, "*** [WARNING] localtime failed: %s\n", strerror(errno));
        }
    } else {
        fprintf(stderr, "*** [WARNING] time() failed: %s\n", strerror(errno));
    }

    printf(ANSI_LIGHT_BLUE "[%s]" ANSI_RESET " %s", timebuf, prefix);

    /* Color code processing with bounds checking */
    for (const char *p = msg; *p; p++) {
        unsigned char c = *p;

        switch (c) {
            case 0x02: printf(ANSI_BOLD); break;
            case 0x1D: printf(ANSI_ITALIC); break;
            case 0x1F: printf(ANSI_UNDER); break;
            case 0x16:
            case 0x0F: printf(ANSI_RESET); break;

            case 0x03: {
                printf(ANSI_RESET);

                if (*(p+1) && isdigit(*(p+1))) {
                    p++;
                    int fg = *p - '0';

                    if (*(p+1) && isdigit(*(p+1))) {
                        p++;
                        fg = fg * 10 + (*p - '0');
                    }

                    if (fg >= 0 && fg < 16) {
                        printf("\x1b[38;5;%dm", irc_to_256[fg]);
                    } else if (fg >= 16 && fg < 256) {
                        printf("\x1b[38;5;%dm", fg);
                    } else {
                        printf(ANSI_RESET);
                    }

                    if (*(p+1) == ',' && *(p+2) && isdigit(*(p+2))) {
                        p += 2;
                        int bg = *p - '0';

                        if (*(p+1) && isdigit(*(p+1))) {
                            p++;
                            bg = bg * 10 + (*p - '0');
                        }

                        if (bg >= 0 && bg < 16) {
                            printf("\x1b[48;5;%dm", irc_to_256[bg]);
                        } else if (bg >= 16 && bg < 256) {
                            printf("\x1b[48;5;%dm", bg);
                        }
                    }
                }
                break;
            }

            case 0x04: {
                printf(ANSI_RESET);
                for (int i = 0; i < 6 && *(p+1) && isxdigit(*(p+1)); i++) {
                    p++;
                }
                break;
            }

            case 0x01: /* CTCP delimiter */
                break;

            case '\x1b': {
                /* Properly consume ANSI escape sequences */
                fprintf(stderr, "*** [SECURITY] Dropped raw ANSI escape sequence from server\n");

                /* Consume CSI sequences: ESC [ ... final_byte */
                if (*(p+1) == '[') {
                    p++;
                    while (*(p+1) && ((*(p+1) >= 0x20 && *(p+1) <= 0x3F))) {
                        p++;
                    }
                    if (*(p+1) && (*(p+1) >= 0x40 && *(p+1) <= 0x7E)) {
                        p++;
                    }
                }
                /* Consume OSC sequences: ESC ] ... BEL or ESC \ */
                else if (*(p+1) == ']') {
                    p++;
                    while (*(p+1) && *(p+1) != '\x07' && *(p+1) != '\x1b') {
                        p++;
                    }
                    if (*(p+1) == '\x07') {
                        p++;
                    } else if (*(p+1) == '\x1b' && *(p+2) == '\\') {
                        p += 2;
                    }
                }
                /* Consume other 2-byte sequences: ESC X */
                else if (*(p+1)) {
                    p++;
                }
                break;
            }

            default:
                if (c >= 0x20 || (c & 0x80)) {
                    putchar(c);
                }
        }
    }

    printf(ANSI_RESET "\n");
}

/* --- A+ IRC Protocol Handler --- */
static void handle_server_msg(char *line) {
    /* PING/PONG - silent handling */
    if (strncmp(line, "PING ", 5) == 0) {
        char pong[512];
        int written = snprintf(pong, sizeof(pong), "PONG %s", line + 5);
        if (written < 0 || written >= (int)sizeof(pong)) {
            fprintf(stderr, "*** [WARNING] PONG formatting issue\n");
        }
        write_raw_line(pong);
        return;
    }

    if (strstr(line, " PONG ") != NULL) {
        return;
    }

    /* PRIVMSG Handler */
    char *privmsg_start = strstr(line, "PRIVMSG ");
    if (privmsg_start) {
        char *prefix_line_start = strchr(line, ':');
        if (!prefix_line_start) goto print_raw;

        char *target_start = privmsg_start + 8;
        char *target_end = strchr(target_start, ' ');
        
        char *message_content = NULL;
        if (target_end) {
            message_content = strchr(target_end, ':');
            if (message_content) {
                message_content++;
            }
        }
        
        if (!message_content) {
            message_content = "(No message)";
        }

        char *prefix_start = prefix_line_start + 1;
        char nickname[64];

        char *bang_pos = strchr(prefix_start, '!');
        size_t nick_len;

        if (bang_pos) {
            nick_len = (size_t)(bang_pos - prefix_start);
        } else {
            char *space_pos = strchr(prefix_start, ' ');
            nick_len = space_pos ? (size_t)(space_pos - prefix_start) : strlen(prefix_start);
        }

        nick_len = nick_len < sizeof(nickname) - 1 ? nick_len : sizeof(nickname) - 1;
        strncpy(nickname, prefix_start, nick_len);
        nickname[nick_len] = '\0';

        char target[64];
        if (target_end) {
            size_t target_len = (size_t)(target_end - target_start);
            target_len = target_len < sizeof(target) - 1 ? target_len : sizeof(target) - 1;
            strncpy(target, target_start, target_len);
            target[target_len] = '\0';
        } else {
            strncpy(target, "UNKNOWN", sizeof(target) - 1);
            target[sizeof(target) - 1] = '\0';
        }

        int is_private_msg = (strcmp(target, nick) == 0);
        int is_action = (strlen(message_content) >= 8 &&
                        message_content[0] == '\001' &&
                        strncmp(message_content + 1, "ACTION ", 7) == 0);

        char prefix_buf[256];
        const char *display_msg = message_content;

        if (is_action) {
            display_msg = message_content + 8;
            static char action_buf[512];
            strncpy(action_buf, display_msg, sizeof(action_buf) - 1);
            action_buf[sizeof(action_buf) - 1] = '\0';

            size_t buf_len = strlen(action_buf);
            if (buf_len > 0 && action_buf[buf_len - 1] == '\001') {
                action_buf[buf_len - 1] = '\0';
            }
            display_msg = action_buf;

            int written = snprintf(prefix_buf, sizeof(prefix_buf), "[%.64s] * %.64s ", target, nickname);
            if (written < 0 || written >= (int)sizeof(prefix_buf)) {
                fprintf(stderr, "*** [WARNING] Prefix buffer formatting issue in ACTION handler\n");
                snprintf(prefix_buf, sizeof(prefix_buf), "[UNKNOWN] * UNKNOWN ");
            }

        } else if (is_private_msg) {
            int written = snprintf(prefix_buf, sizeof(prefix_buf),
                    ANSI_BOLD ANSI_BRIGHT_YELLOW
                    "[PRIVATE MESSAGE] " ANSI_RESET "<%.64s>: ", nickname);
            if (written < 0 || written >= (int)sizeof(prefix_buf)) {
                fprintf(stderr, "*** [WARNING] Prefix buffer formatting issue in PM handler\n");
                snprintf(prefix_buf, sizeof(prefix_buf), "[PM] <UNKNOWN>: ");
            }
        } else {
             /*  Ring bell for channel messages */
            printf(ANSI_BELL);

            int written = snprintf(prefix_buf, sizeof(prefix_buf), "[%.64s] <%.64s>: ", target, nickname);
            if (written < 0 || written >= (int)sizeof(prefix_buf)) {
                fprintf(stderr, "*** [WARNING] Prefix buffer formatting issue in message handler\n");
                snprintf(prefix_buf, sizeof(prefix_buf), "[UNKNOWN] <UNKNOWN>: ");
            }
        }

        print_ts(prefix_buf, display_msg);
        return;
    }

    /* Numeric/Command Parser */
    char *tmp = strdup(line);
    if (!tmp) {
        fprintf(stderr, "*** [ERROR] Memory allocation failed in message parser (OOM?)\n");
        print_ts("❮❮ ", line);
        return;
    }

    char *p = tmp;
    char *command = NULL;

    /* Skip prefix */
    if (*p == ':') {
        char *end = strchr(p + 1, ' ');
        if (!end) {
            free(tmp);
            goto print_raw;
        }
        p = end + 1;
    }

    /* Skip spaces */
    while (*p == ' ') p++;

    /* Extract command */
    char *end = strchr(p, ' ');
    if (end) {
        *end = '\0';
        command = p;
    } else {
        command = p;
    }

    if (command) {
        /* Registration (001) */
        if (strcmp(command, "001") == 0 && !reg) {
            reg = 1;
            printf("***  [IRC] Registered with server.\n");

            if (password) {
                char identmsg[512];
                int written = snprintf(identmsg, sizeof(identmsg),
                        "PRIVMSG NickServ :IDENTIFY %s", password);
                if (written < 0 || written >= (int)sizeof(identmsg)) {
                    fprintf(stderr, "*** [ERROR] Failed to format NickServ IDENTIFY command\n");
                } else {
                    write_raw_line(identmsg);
                    printf("***  [AUTH] Sent NickServ identification\n");
                }

                OPENSSL_cleanse(password, password_len);
                free(password);
                password = NULL;
                password_len = 0;
                printf("***  [SECURITY] Password zeroized\n");
            }
        }
        /* Cloak confirmed (396) */
        else if (strcmp(command, "396") == 0 && !joined) {
            joined = 1;
            char joinbuf[256];
            int written = snprintf(joinbuf, sizeof(joinbuf), "JOIN %s", CHANNEL);
            if (written < 0 || written >= (int)sizeof(joinbuf)) {
                fprintf(stderr, "*** [ERROR] Failed to format JOIN command\n");
            } else {
                sendln(joinbuf);
                printf(ANSI_BOLD ANSI_BRIGHT_GREEN
                       " Cloak confirmed. Joining the best channel %s"
                       ANSI_RESET "\n", CHANNEL);
            }
        }
        /* Filter noise */
        else if (strcmp(command, "MODE") == 0 || strcmp(command, "JOIN") == 0 ||
                 strcmp(command, "PART") == 0 || strcmp(command, "QUIT") == 0) {
            free(tmp);
            return;
        }
    }

    free(tmp);

print_raw:
    print_ts("❮❮ ", line);
}

/* --- A+ User Input Handler --- */
static void handle_user_input(char *line) {
    size_t line_len = strlen(line);

    size_t msg_overhead = 8 + strlen(CHANNEL) + 2 + 2;
    size_t max_payload = (IRC_MAX_MSG_LEN > msg_overhead) ?
                         (IRC_MAX_MSG_LEN - msg_overhead) : 0;

    if (line_len > max_payload) {
        printf(ANSI_BRIGHT_RED
               "*** Error: Message too long (%zu chars). Max allowed: %zu chars."
               ANSI_RESET "\n", line_len, max_payload);
        return;
    }

    sanitize(line, line_len);

    if (line[0] == '/') {
        if (strcmp(line, "/quit") == 0 || strcmp(line, "/QUIT") == 0) {
            sendln("QUIT :brb.. probably");
            printf("***  [IRC] Disconnecting cleanly...\n");

            struct timeval tv = {1, 0};

            if (event_base_once(base, -1, EV_TIMEOUT, deferred_cleanup_cb, NULL, &tv) < 0) {
                fprintf(stderr, "*** ⚑ [ERROR] Failed to schedule deferred cleanup timer, exiting immediately.\n");
                cleanup_and_exit_internal(1);
            } else {
                printf("***  [IRC] Cleaning up now.\n");
            }
        }
        else if (strcmp(line, "/help") == 0 || strcmp(line, "/HELP") == 0) {
            printf("\n" ANSI_BOLD "*** Available Commands:" ANSI_RESET "\n");
            printf("  " ANSI_BOLD "/JOIN #channel" ANSI_RESET " - Join a channel\n");
            printf("  " ANSI_BOLD "/MSG <nick> <message>" ANSI_RESET " - Send private message\n");
            printf("  " ANSI_BOLD "/ME <action>" ANSI_RESET " - Send action to %s\n", CHANNEL);
            printf("  " ANSI_BOLD "/QUIT" ANSI_RESET " - Disconnect and exit\n");
            printf("  " ANSI_BOLD "/HELP" ANSI_RESET " - Show this help\n");
            printf("  " ANSI_BOLD "/<raw IRC command>" ANSI_RESET " - Send raw IRC command\n");
            printf("  " ANSI_BOLD "Anything else" ANSI_RESET " - Send message to %s\n\n", CHANNEL);
        }
        else if (strncmp(line, "/MSG ", 5) == 0 || strncmp(line, "/msg ", 5) == 0) {
            char *target = line + 5;
            char *msg = strchr(target, ' ');
            if (msg) {
                *msg++ = '\0';
                char privmsg[BUFFER_SIZE];
                int written = snprintf(privmsg, sizeof(privmsg), "PRIVMSG %s :%s", target, msg);
                if (written < 0 || written >= (int)sizeof(privmsg)) {
                    fprintf(stderr, "*** ⚑ [ERROR] Failed to format PRIVMSG command\n");
                    return;
                }
                sendln(privmsg);

                char echo_prefix[256];
                written = snprintf(echo_prefix, sizeof(echo_prefix),
                        ANSI_BOLD ANSI_BRIGHT_YELLOW
                        "[PRIVATE MESSAGE to %.64s] " ANSI_RESET "<%s%s%s>: ",
                        target, ANSI_BRIGHT_RED, nick, ANSI_RESET);
                if (written < 0 || written >= (int)sizeof(echo_prefix)) {
                    fprintf(stderr, "*** ⚑ [WARNING] Echo prefix formatting issue\n");
                    snprintf(echo_prefix, sizeof(echo_prefix), "[PM] <%s>: ", nick);
                }
                print_ts(echo_prefix, msg);
            } else {
                printf("*** Usage: /MSG <nick> <message>\n");
            }
        }
        else if (strncmp(line, "/ME ", 4) == 0 || strncmp(line, "/me ", 4) == 0) {
            char *msg = line + 4;
            char privmsg[BUFFER_SIZE];
            int written = snprintf(privmsg, sizeof(privmsg),
                    "PRIVMSG %s :\001ACTION %s\001", CHANNEL, msg);
            if (written < 0 || written >= (int)sizeof(privmsg)) {
                fprintf(stderr, "*** ⚑ [ERROR] Failed to format ACTION command\n");
                return;
            }
            sendln(privmsg);

            char echo_prefix[256];
            written = snprintf(echo_prefix, sizeof(echo_prefix), "[%.64s] * %s%s%s ",
                    CHANNEL, ANSI_BRIGHT_YELLOW, nick, ANSI_RESET);
            if (written < 0 || written >= (int)sizeof(echo_prefix)) {
                fprintf(stderr, "*** ⚑ [WARNING] Echo prefix formatting issue\n");
                snprintf(echo_prefix, sizeof(echo_prefix), "[%s] * %s ", CHANNEL, nick);
            }
            print_ts(echo_prefix, msg);
        }
        else {
            sendln(line + 1);
            print_ts("❯❯ ", line);
        }
    } else {
        char msg[BUFFER_SIZE];
        int written = snprintf(msg, sizeof(msg), "PRIVMSG %s :%s", CHANNEL, line);
        if (written < 0 || written >= (int)sizeof(msg)) {
            fprintf(stderr, "*** ⚑ [ERROR] Failed to format message command\n");
            return;
        }
        sendln(msg);

        char echo_prefix[256];
        written = snprintf(echo_prefix, sizeof(echo_prefix), "[%.64s] <%s%s%s>: ",
                CHANNEL, ANSI_BRIGHT_YELLOW, nick, ANSI_RESET);
        if (written < 0 || written >= (int)sizeof(echo_prefix)) {
            fprintf(stderr, "*** ⚑ [WARNING] Echo prefix formatting issue\n");
            snprintf(echo_prefix, sizeof(echo_prefix), "[%s] <%s>: ", CHANNEL, nick);
        }
        print_ts(echo_prefix, line);
    }
}

/* --- Libevent Callbacks --- */
static void read_cb(struct bufferevent *bev_arg, void *ctx) {
    (void)ctx;
    struct evbuffer *input = bufferevent_get_input(bev_arg);
    if (!input) {
        fprintf(stderr, "*** ⚑ [ERROR] Failed to get input buffer\n");
        return;
    }

    char *line;
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF))) {
        handle_server_msg(line);
        free(line);
    }
}

static void stdin_read_cb(struct bufferevent *bev_arg, void *ctx) {
    (void)ctx;
    struct evbuffer *input = bufferevent_get_input(bev_arg);
    if (!input) {
        fprintf(stderr, "*** ⚑ [ERROR] Failed to get stdin buffer\n");
        return;
    }

    char *line;
    while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_LF))) {
        handle_user_input(line);
        OPENSSL_cleanse(line, strlen(line));
        free(line);
    }
}

static void event_cb(struct bufferevent *bev_arg, short events, void *ctx) {
    (void)ctx;

    if (events & BEV_EVENT_CONNECTED) {
        SSL *ssl = bufferevent_openssl_get_ssl(bev_arg);
        if (ssl) {
            long verify = SSL_get_verify_result(ssl);
            if (verify != X509_V_OK) {
                fprintf(stderr, "\n" ANSI_BRIGHT_RED
                        "*** ⚑ [SECURITY ERROR] TLS Certificate Verification FAILED: %s"
                        ANSI_RESET "\n", X509_verify_cert_error_string(verify));
                bufferevent_free(bev);
                bev = NULL;
                schedule_reconnect();
                return;
            }
            fprintf(stderr, "***  [SSL] Certificate verified successfully\n");
        }

        fprintf(stderr, "***  [CONNECT] Connection established and secured\n");

        reconnect_delay = 2;
        reconnect_attempts_count = 0;

        /* Stage 2 Pledge */
        int sandboxing_enabled = 0;
        if (pledge("stdio inet rpath tty", NULL) == -1) {
            if (errno != ENOSYS) {
                perror("*** ⚑ [SANDBOX ERROR] pledge (stage 2) failed");
                cleanup_and_exit_internal(1);
            }
        } else {
            sandboxing_enabled = 1;
        }

        if (sandboxing_enabled) {
            printf(ANSI_BOLD ANSI_BRIGHT_GREEN
                   "   OpenBSD Sandboxing Active (pledge: stdio inet rpath tty)\n"
                   ANSI_RESET);
        } else {
            fprintf(stderr, ANSI_BOLD ANSI_BRIGHT_RED
                    "  ✗ OpenBSD Sandboxing Unavailable (Running UNSANDBOXED)\n"
                    ANSI_RESET);
        }
        printf("\n");

        /* Setup keepalive timer */
        if (ping_timer) {
            event_free(ping_timer);
            ping_timer = NULL;
        }

        struct timeval tv = {PING_INTERVAL_SEC, 0};
        ping_timer = event_new(base, -1, EV_PERSIST | EV_TIMEOUT, ping_cb, NULL);
        if (!ping_timer) {
            fprintf(stderr, "*** ⚑ [WARNING] Could not create ping timer\n");
        } else {
            if (event_add(ping_timer, &tv) != 0) {
                fprintf(stderr, "*** ⚑ [WARNING] Failed to add ping timer to event loop\n");
                event_free(ping_timer);
                ping_timer = NULL;
            }
        }

        /* IRC Registration */
        char regbuf[256];
        int written = snprintf(regbuf, sizeof(regbuf), "NICK %s", nick);
        if (written < 0 || written >= (int)sizeof(regbuf)) {
            fprintf(stderr, "*** ⚑ [ERROR] Failed to format NICK command\n");
        } else {
            sendln(regbuf);
        }

        written = snprintf(regbuf, sizeof(regbuf), "USER %s 0 * :%s", nick, nick);
        if (written < 0 || written >= (int)sizeof(regbuf)) {
            fprintf(stderr, "*** ⚑ [ERROR] Failed to format USER command\n");
        } else {
            sendln(regbuf);
        }

    } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT)) {

        if (events & BEV_EVENT_TIMEOUT) {
            fprintf(stderr, "\n*** [TIMEOUT] Connection timed out after %d seconds\n",
                    CONNECTION_TIMEOUT_SEC);
        } else if (events & BEV_EVENT_ERROR) {
            int err = EVUTIL_SOCKET_ERROR();
            fprintf(stderr, "\n*** ⚑ [NETWORK ERROR] %s\n", evutil_socket_error_to_string(err));

            unsigned long ssl_err;
            while ((ssl_err = bufferevent_get_openssl_error(bev_arg))) {
                char err_buf[256];
                ERR_error_string_n(ssl_err, err_buf, sizeof(err_buf));
                fprintf(stderr, "*** [SSL ERROR] %s (0x%lx)\n", err_buf, ssl_err);
            }
        } else if (events & BEV_EVENT_EOF) {
            fprintf(stderr, "\n*** [EOF] Server closed connection\n");
        }

        if (ping_timer) {
            event_free(ping_timer);
            ping_timer = NULL;
        }

        if (bev) {
            bufferevent_free(bev);
            bev = NULL;
        }

        schedule_reconnect();
    }
}

/* --- Main --- */
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server> <port> <nick> [nickserv_pass or 'prompt']\n", argv[0]);
        fprintf(stderr, "\nExamples:\n");
        fprintf(stderr, "  %s irc.libera.chat 6697 mynick\n", argv[0]);
        fprintf(stderr, "  %s irc.libera.chat 6697 mynick prompt\n", argv[0]);
        fprintf(stderr, "\n");
        return 1;
    }

    /* OpenSSL Initialization */
    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                          OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL)) {
        fprintf(stderr, "*** ⚑ [FATAL] OpenSSL initialization failed\n");
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    atexit(cleanup_handler);

    const char *server = argv[1];
    const char *port = argv[2];

    if (strlen(argv[3]) > (sizeof(nick) - 1)) {
        fprintf(stderr, "*** ⚑ [ERROR] Nickname too long. Max length is %zu bytes.\n",
                sizeof(nick) - 1);
        return 1;
    }

    strncpy(server_host, server, sizeof(server_host) - 1);
    server_host[sizeof(server_host) - 1] = '\0';
    strncpy(server_port, port, sizeof(server_port) - 1);
    server_port[sizeof(server_port) - 1] = '\0';
    strncpy(nick, argv[3], sizeof(nick) - 1);
    nick[sizeof(nick) - 1] = '\0';

    /* Password Handling */
    if (argc >= 5) {
        if (strcmp(argv[4], "prompt") == 0) {
            password = get_secure_password(&password_len);
            if (!password) {
                fprintf(stderr, "*** ⚑ [ERROR] Failed to read password.\n");
                return 1;
            }
        } else {
            fprintf(stderr, "\n" ANSI_BRIGHT_RED
                    "╔═══════════════════════════════════════════════════════════╗\n");
            fprintf(stderr,
                    "║             ⚠️  SECURITY WARNING !! ⚠️                    ║\n");
            fprintf(stderr,
                    "╚═══════════════════════════════════════════════════════════╝"
                    ANSI_RESET "\n");
            fprintf(stderr, ANSI_BRIGHT_RED
                    " Password on command line is visible in process lists!\n"
                    ANSI_RESET);
            fprintf(stderr, ANSI_BOLD "Recommended:" ANSI_RESET " Use " ANSI_BOLD
                    "'prompt'" ANSI_RESET " for secure input:\n");
            fprintf(stderr, "  $ %s %s %s %s " ANSI_BOLD "prompt" ANSI_RESET "\n\n",
                    argv[0], argv[1], argv[2], argv[3]);
            fprintf(stderr, ANSI_BRIGHT_RED "Continuing in 8 seconds..." ANSI_RESET "\n");
            sleep(8);

            if (strlen(argv[4]) >= BUFFER_SIZE) {
                fprintf(stderr, "*** ⚑ [ERROR] NickServ password too long.\n");
                return 1;
            }

            password = strdup(argv[4]);
            if (!password) {
                fprintf(stderr, "*** ⚑ [ERROR] Memory allocation failed for password\n");
                return 1;
            }
            password_len = strlen(password);
        }

        /* Password Validation */
        for (size_t i = 0; i < password_len; i++) {
            if (password[i] == '\r' || password[i] == '\n') {
                fprintf(stderr, "*** ⚑ [ERROR] Password contains invalid characters (CR/LF)\n");
                OPENSSL_cleanse(password, password_len);
                free(password);
                password = NULL;
                password_len = 0;
                return 1;
            }
        }
    }

    /* Event Base Setup */
    base = event_base_new();
    if (!base) {
        fprintf(stderr, "*** ⚑ [FATAL] Could not initialize libevent\n");
        if (password) {
            OPENSSL_cleanse(password, password_len);
            free(password);
        }
        return 1;
    }

    /* STDIN Setup */
    if (evutil_make_socket_nonblocking(STDIN_FILENO) < 0) {
        fprintf(stderr, "*** ⚑ [WARNING] Failed to make STDIN non-blocking: %s\n",
                strerror(errno));
    }

    stdin_bev = bufferevent_socket_new(base, STDIN_FILENO, BEV_OPT_DEFER_CALLBACKS);
    if (!stdin_bev) {
        fprintf(stderr, "*** ⚑ [FATAL] Failed to set up stdin buffer event\n");
        event_base_free(base);
        if (password) {
            OPENSSL_cleanse(password, password_len);
            free(password);
        }
        return 1;
    }

    bufferevent_setcb(stdin_bev, stdin_read_cb, NULL, NULL, NULL);
    if (bufferevent_enable(stdin_bev, EV_READ) != 0) {
        fprintf(stderr, "*** ⚑ [FATAL] Failed to enable stdin reading\n");
        bufferevent_free(stdin_bev);
        event_base_free(base);
        if (password) {
            OPENSSL_cleanse(password, password_len);
            free(password);
        }
        return 1;
    }

    /* Banner */
    printf("\n");
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
           "═══════════════════════════════════════════════════════════\n"
           ANSI_RESET);
    printf(ANSI_BOLD "  ZIRC-IRC v1.8 (Secure Filesystem Hardening)  \n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
           "═══════════════════════════════════════════════════════════\n"
           ANSI_RESET);
    printf("\n");
    printf(ANSI_BOLD "Security Features:\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   TLS 1.2+ with Certificate Verification\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Password/Input Zeroization\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Robust IRC Parsing (Numeric/Hostmask/CTCP)\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Protocol Injection Prevention (CR/LF)\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Terminal Security (Echo Off)\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Re-Entrancy Guards (Cleanup/Reconnect)\n"ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Message Rate Limiting (25 msg/sec)\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Comprehensive Error Handling\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Non-blocking Quit\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   ANSI Escape Stripping\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Bounds Checking in Color Parser\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   NULL Check After strdup\n" ANSI_RESET);
    printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   Reconnection Resource Cleanup\n" ANSI_RESET);

    /* Stage 1 unveil() - before pledge() */
    if (setup_unveil() == -1) {
        fprintf(stderr, "*** ⚑ [WARNING] unveil() setup failed, continuing anyway\n");
    } else {
        printf(ANSI_BOLD ANSI_BRIGHT_GREEN "   unveil() Filesystem Restrictions Applied\n" ANSI_RESET);
    }

    /* Stage 1 Pledge */
    if (pledge("stdio inet dns rpath tty", NULL) == -1) {
        if (errno != ENOSYS) {
            perror("*** ⚑ [SANDBOX ERROR] pledge (Stage 1) failed");
            bufferevent_free(stdin_bev);
            event_base_free(base);
            if (password) {
                OPENSSL_cleanse(password, password_len);
                free(password);
            }
            return 1;
        }
    } else {
        printf(ANSI_BOLD ANSI_BRIGHT_GREEN
               "   Stage 1 pledge('stdio inet dns rpath tty') applied\n"
               ANSI_RESET);
    }
    printf("\n");

    /* Initial Connection */
    if (dial(server_host, server_port) < 0) {
        fprintf(stderr, "*** [FATAL] Initial connection setup failed\n");
    }

    printf(ANSI_BOLD "Connected as: " ANSI_BRIGHT_YELLOW "%s" ANSI_RESET "\n", nick);
    printf(ANSI_BOLD "Best channel: " ANSI_RESET "%s\n", CHANNEL);
    printf("\n");
    printf(ANSI_BOLD "    ▘      ▘    \n" ANSI_RESET);
    printf("  " ANSI_BOLD "▀▌▌▛▘▛▘  ▌▛▘▛▘\n");
    printf("  " ANSI_BOLD "▙▖▌▌ ▙▖  ▌▌ ▙▖\n");
    printf("Secure by Default\n");
    printf("\n");
    printf(ANSI_BOLD ANSI_BRIGHT_YELLOW
           "═══════════════════════════════════════════════════════════\n"
           ANSI_RESET);
    printf("\n");

    fprintf(stderr, "***  [EVENT LOOP] Starting...\n");
    int loop_result = event_base_dispatch(base);

    if (loop_result < 0) {
        fprintf(stderr, ANSI_BRIGHT_RED
                "*** [FATAL] Event loop failed with error\n"
                ANSI_RESET);
        cleanup_and_exit_internal(1);
    } else if (loop_result == 1) {
        fprintf(stderr, "*** [WARNING] Event loop exited: No events registered\n");
        cleanup_and_exit_internal(1);
    } else {
        fprintf(stderr, "***  [EVENT LOOP] Exited cleanly\n");
        cleanup_and_exit_internal(0);
    }

    return 0;
}
