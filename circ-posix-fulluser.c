/*
- IRC Client with TLS Support
- Features: Non-blocking I/O, dynamic keep-alive, color support, logging
-
- Compile:
- gcc -o irc irc_client.c -lssl -lcrypto -O2 -Wall
-
- Usage:
- ./irc <server> <port> <nick> [nickserv_password]
- Example: ./irc irc.libera.chat 6697 mynick mypassword
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PING_TIMEOUT 150
#define BUFFER_SIZE 4096
#define CHANNEL "##" // Default channel for sending PRIVMSG if no command is used
#define LOGFILE "irc.log"

/* Global state */
static SSL *ssl_conn = NULL;
static FILE *logfp = NULL;
static time_t last_msg_time;
static int reg = 0; // Registration status
static char nick[64];
static char nspass[256];

/* ANSI color codes for terminal output */
#define ANSI_RESET "\x1b[0m"
#define ANSI_BOLD "\x1b[1m"
#define ANSI_ITALIC "\x1b[3m"
#define ANSI_UNDER "\x1b[4m"
#define ANSI_LIGHT_BLUE "\x1b[94m" // Bright Blue for timestamp
#define ANSI_BRIGHT_YELLOW "\x1b[93m" // Bright Yellow/Orange for DM prefix

/* IRC color code (0-15) to ANSI 256-color mapping */
static const int irc_to_256[] = {
    15,    /* 0 - white */
    0,     /* 1 - black */
    19,    /* 2 - blue (navy) */
    34,    /* 3 - green */
    196,   /* 4 - red */
    52,    /* 5 - brown/maroon */
    127,   /* 6 - purple */
    208,   /* 7 - orange */
    226,   /* 8 - yellow */
    46,    /* 9 - light green */
    51,    /* 10 - cyan (teal) */
    87,    /* 11 - light cyan */
    75,    /* 12 - light blue */
    207,   /* 13 - pink */
    244,   /* 14 - grey */
    252    /* 15 - light grey */
};

/* Convert IRC color code (0-99) to ANSI 256-color escape */
static void print_color_256(int color) {
    if (color >= 0 && color < 16) {
        /* Standard IRC colors */
        printf("\x1b[38;5;%dm", irc_to_256[color]);
    } else if (color >= 0 && color < 256) {
        /* Extended colors - map to 256 color palette */
        printf("\x1b[38;5;%dm", color);
    }
}

/* Convert IRC background color to ANSI 256-color escape */
static void print_bg_color_256(int color) {
    if (color >= 0 && color < 16) {
        printf("\x1b[48;5;%dm", irc_to_256[color]);
    } else if (color >= 0 && color < 256) {
        printf("\x1b[48;5;%dm", color);
    }
}

/* Function prototypes */
static int dial(const char *host, const char *port);
static void write_raw_line(const char *s);
static void sendln(const char *s);
static void sanitize(char *in, size_t n);
static void print_ts(FILE *f, const char *prefix, const char *msg);
static void handle_server_msg(char *line);
static void handle_user_input(char *line);
static void cleanup(void);

/*
- Establish TLS connection to IRC server
- Returns: socket fd on success, -1 on failure
*/
static int dial(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int s, ret;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((ret = getaddrinfo(host, port, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    /* Try each address until we successfully connect */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) continue;

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(s);
    }

    freeaddrinfo(res);

    if (rp == NULL) {
        fprintf(stderr, "Failed to connect\n");
        return -1;
    }

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
        close(s);
        return -1;
    }

    /* Create SSL connection */
    ssl_conn = SSL_new(ctx);
    SSL_set_fd(ssl_conn, s);

    if (SSL_connect(ssl_conn) != 1) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_conn);
        SSL_CTX_free(ctx);
        close(s);
        return -1;
    }

    printf("TLS connection established to %s:%s\n", host, port);

    /* Set non-blocking mode */
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    
    /* The SSL_CTX is now owned by the ssl_conn and will be freed with it */
    SSL_CTX_free(ctx); 

    return s;
}

/*
- Writes a line to the IRC server (adds CRLF) without logging.
*/
static void write_raw_line(const char *s) {
    char buf[BUFFER_SIZE];
    int len = snprintf(buf, sizeof(buf), "%s\r\n", s);

    if (len > 0 && len < sizeof(buf)) {
        if (ssl_conn) {
            SSL_write(ssl_conn, buf, len);
        }
    }
}

/*
- Send a line to the IRC server (adds CRLF) and logs it.
*/
static void sendln(const char *s) {
    write_raw_line(s); // Send to server

    if (logfp) {
        fprintf(logfp, ">>> %s\n", s); // Log the line
        fflush(logfp);
    }
}

/*
- Check if character is printable ASCII or valid UTF-8 continuation byte
*/
static int is_valid_char(unsigned char c) {
    /* Printable ASCII (32-126) */
    if (c >= 0x20 && c <= 0x7E) return 1;
    /* UTF-8 continuation bytes and multi-byte starters */
    if (c >= 0x80) return 1;
    /* IRC formatting codes: BOLD (0x02), COLOR (0x03), RESET (0x0F), 
       REVERSE (0x16), ITALIC (0x1D), UNDERLINE (0x1F), HEX COLOR (0x04) 
       CTCP Delimiter (0x01) */
    if (c == 0x02 || c == 0x03 || c == 0x0F || 
        c == 0x16 || c == 0x1D || c == 0x1F || c == 0x04 || c == 0x01) return 1;
    return 0;
}

/*
- Sanitize user input - preserves ASCII, UTF-8, and IRC formatting codes
- Replaces invalid control characters with '?'
*/
static void sanitize(char *in, size_t n) {
    for (size_t i = 0; i < n && in[i]; i++) {
        unsigned char c = in[i];
        if (!is_valid_char(c)) {
            in[i] = '?';
        }
    }
}

/*
- Print message with timestamp and IRC color code parsing
- Supports IRC formatting: bold, italic, underline, colors (256-color)
- Writes raw message to logfile if provided
*/
static void print_ts(FILE *f, const char *prefix, const char *msg) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timebuf[16];

    strftime(timebuf, sizeof(timebuf), "%H%M%S", tm_info);
    
    /* Print timestamp in bright blue, then reset color for prefix */
    printf(ANSI_LIGHT_BLUE "[%s]" ANSI_RESET " %s", timebuf, prefix);

    /* Write to logfile without formatting */
    if (f) {
        fprintf(f, "[%s] %s%s\n", timebuf, prefix, msg);
        fflush(f);
    }
    
    /* Parse and render IRC formatting codes */
    for (const char *p = msg; *p; p++) {
        unsigned char c = *p;

        switch (c) {
            case 0x02: /* Bold */
                printf(ANSI_BOLD);
                break;
            case 0x1D: /* Italic */
                printf(ANSI_ITALIC);
                break;
            case 0x1F: /* Underline */
                printf(ANSI_UNDER);
                break;
            case 0x16: /* Reverse/Inverse - treat as reset */
                printf(ANSI_RESET);
                break;
            case 0x0F: /* Reset all formatting */
                printf(ANSI_RESET);
                break;
            case 0x04: /* Hex color code (mIRC extension) */
                /* Skip hex color codes for display */
                if (isxdigit(*(p+1))) { p++;
                if (isxdigit(*(p+1))) p++;
                if (isxdigit(*(p+1))) p++;
                if (isxdigit(*(p+1))) p++;
                if (isxdigit(*(p+1))) p++;
                if (isxdigit(*(p+1))) p++;
                }
                break;
            case 0x03: /* Color */
                if (isdigit(*(p+1))) {
                    /* Parse foreground color */
                    int fg = (*(++p)) - '0';
                    if (isdigit(*(p+1))) {
                        fg = fg * 10 + (*(++p)) - '0';
                    }
                    print_color_256(fg);

                    /* Check for background color */
                    if (*(p+1) == ',') {
                        p++; /* skip comma */
                        if (isdigit(*(p+1))) {
                            int bg = (*(++p)) - '0';
                            if (isdigit(*(p+1))) {
                                bg = bg * 10 + (*(++p)) - '0';
                            }
                            print_bg_color_256(bg);
                        }
                    }
                } else {
                    /* Color code without number = reset colors */
                    printf(ANSI_RESET);
                }
                break;
            default:
                /* Print regular character (supports UTF-8) */
                // Ignore CTCP delimiters (\001) but print printable ASCII and UTF-8
                if (c >= 0x20 || c >= 0x80) {
                    putchar(c);
                }
        }
    }

    printf(ANSI_RESET "\n");
}

/*
- Handle incoming IRC server messages
*/
static void handle_server_msg(char *line) {
    /* Strip CRLF */
    char *end = line + strlen(line) - 1;
    while (end >= line && (*end == '\r' || *end == '\n')) {
        *end-- = '\0';
    }

    if (strlen(line) == 0) return;
    
    /* Handle PING requests from server - Respond but DO NOT print to console or log */
    if (strncmp(line, "PING ", 5) == 0) {
        char pong[512];
        snprintf(pong, sizeof(pong), "PONG %s", line + 5);
        write_raw_line(pong);
        return;
    }

    /* Tokenization for command parsing and registration checks. */
    char *words[10];
    int nwords = 0;
    char line_copy[BUFFER_SIZE];
    strncpy(line_copy, line, sizeof(line_copy) - 1);
    line_copy[sizeof(line_copy) - 1] = '\0';
    
    char *tok = strtok(line_copy, " ");
    while (tok && nwords < 10) {
        words[nwords++] = tok;
        tok = strtok(NULL, " ");
    }
    
    if (nwords < 2) return;

    /* 1. Handle Successful Registration (001 numeric) */
    if (nwords >= 2 && strcmp(words[1], "001") == 0 && !reg) {
        reg = 1;
        printf("*** Registered with server. Use /JOIN <#channel> to start chatting.\n");

        /* Identify with NickServ if password provided */
        if (nspass[0]) {
            char identmsg[512];
            // 1. Construct the raw command with password
            snprintf(identmsg, sizeof(identmsg),
                     "PRIVMSG NickServ :IDENTIFY %s", nspass);
            
            // 2. Send the command without logging
            write_raw_line(identmsg); 

            // 3. Manually log the command with password hidden
            if (logfp) {
                fprintf(logfp, ">>> PRIVMSG NickServ :IDENTIFY ******\n");
                fflush(logfp);
            }

            // 4. Console message update
            printf("*** Sent NickServ identification (Password is hidden in log)\n");
        }
        
        // This message is a welcome, so we let it fall through to the general print at the end.
    }

    /* 2. Filter out MODE messages (Suppress command output) */
    if (nwords >= 2 && strcmp(words[1], "MODE") == 0) {
        return; 
    }

    /* 3. Handle and format PRIVMSG (Chat messages, including ACTION and DMs) */
    if (nwords >= 4 && strcmp(words[1], "PRIVMSG") == 0) {
        
        // Extract the full prefix (e.g., :defekt!~user@host)
        char *full_prefix_raw = words[0]; 
        char prefix_to_show[128]; 
        
        // Start after the leading colon, if present
        char *prefix_start = full_prefix_raw[0] == ':' ? full_prefix_raw + 1 : full_prefix_raw;
        
        // Copy the entire prefix (nick!user@host)
        size_t full_prefix_len = strlen(prefix_start);

        if (full_prefix_len >= sizeof(prefix_to_show)) {
            full_prefix_len = sizeof(prefix_to_show) - 1;
        }
        strncpy(prefix_to_show, prefix_start, full_prefix_len);
        prefix_to_show[full_prefix_len] = '\0';
        
        // Extract Nickname from prefix_to_show (everything before '!')
        char nickname[64];
        char *bang_pos = strchr(prefix_to_show, '!');
        if (bang_pos) {
            size_t nick_len = bang_pos - prefix_to_show;
            strncpy(nickname, prefix_to_show, nick_len);
            nickname[nick_len] = '\0';
        } else {
            strncpy(nickname, prefix_to_show, sizeof(nickname) - 1);
            nickname[sizeof(nickname) - 1] = '\0';
        }

        // Target is words[2] (e.g., "#channel" or "mynick")
        char *target = words[2];
        
        // Extract Message Content (everything after the last colon)
        char *message_content = line;
        
        // Find the colon that separates the message from the command/target
        char *colon_pos = strchr(message_content, ':'); // Find first colon (prefix)
        if (colon_pos) {
            colon_pos = strchr(colon_pos + 1, ':'); // Find the colon before the actual message content
        }
        
        if (colon_pos) {
            message_content = colon_pos + 1;
        } else {
            message_content = "(No message content)";
        }
        
        // Check for CTCP ACTION message
        int is_action = 0;
        // ACTION format: \001ACTION <message>\001 (min length 8)
        if (strlen(message_content) >= 8 && message_content[0] == '\001' && 
            strncmp(message_content + 1, "ACTION ", 7) == 0) {
            
            is_action = 1;
            // Advance message content past \001ACTION 
            message_content += 8; 
            
            // Remove trailing \001 if present
            size_t msg_len = strlen(message_content);
            if (msg_len > 0 && message_content[msg_len - 1] == '\001') {
                message_content[msg_len - 1] = '\0';
            }
        }
        
        char prefix_buf[256];
        char formatted_msg_buf[BUFFER_SIZE];
        const char *display_msg; // Pointer to the message we will print

        /* Check if it's a Private Message (DM) to the current user */
        int is_private_msg = (strcmp(target, nick) == 0);
        
        if (is_private_msg) {
            /* DM: Prefix is highlighted, message is wrapped in IRC Orange Color (Code 7) */
            // Console prefix: Bold, Underlined, Bright Yellow/Orange tag
            snprintf(prefix_buf, sizeof(prefix_buf), ANSI_BOLD ANSI_BRIGHT_YELLOW 
                     "[PRIVATE MESSAGE] " ANSI_RESET "<%s>: ", nickname);

            // Wrap message content in IRC Orange Color (\00307) and reset (\017)
            snprintf(formatted_msg_buf, sizeof(formatted_msg_buf), "\00307%s\017", 
                     message_content);
            display_msg = formatted_msg_buf;

        } else if (is_action) {
            // Format for ACTION: [TARGET] * nickname MESSAGE
            snprintf(prefix_buf, sizeof(prefix_buf), "[%s] * %s ", 
                     target, nickname); 
            display_msg = message_content;

        } else {
            // Format for standard channel PRIVMSG: [TARGET] <nick!user@host>: MESSAGE
            snprintf(prefix_buf, sizeof(prefix_buf), "[%s] <%s>: ", 
                     target, prefix_to_show);
            display_msg = message_content;
        }
        
        print_ts(logfp, prefix_buf, display_msg);
        return; // Message handled, stop processing.
    }


    /* 4. Catch-all for all other messages (NOTICE, JOIN, PART, 001, etc.) */
    print_ts(logfp, "❮❮ ", line);
}

/*
- Handle user input from stdin
*/
static void handle_user_input(char *line) {
    /* Strip newline */
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';

    if (strlen(line) == 0) return;

    sanitize(line, strlen(line));

    /* Handle slash commands */
    if (line[0] == '/') {
        if (strncmp(line, "/MSG ", 5) == 0 || strncmp(line, "/msg ", 5) == 0) {
            /* Parse /MSG target message */
            char *target = line + 5;
            char *msg = strchr(target, ' ');
            if (msg) {
                *msg++ = '\0';
                char privmsg[BUFFER_SIZE];
                snprintf(privmsg, sizeof(privmsg), "PRIVMSG %s :%s",
                         target, msg);
                sendln(privmsg);
                print_ts(logfp, "❯❯❯ ", line);
            }
        /* New: /ME command (CTCP ACTION) */
        } else if (strncmp(line, "/ME ", 4) == 0 || strncmp(line, "/me ", 4) == 0) {
            char *msg = line + 4; // Message starts after "/ME "
            char privmsg[BUFFER_SIZE];
            // IRC CTCP ACTION format: PRIVMSG <target> :\001ACTION <message>\001
            // Used octal escape (\001) instead of hex (\x01) to fix compilation error.
            snprintf(privmsg, sizeof(privmsg), "PRIVMSG %s :\001ACTION %s\001",
                     CHANNEL, msg);
            sendln(privmsg);
            print_ts(logfp, "-> ", line);
        } else {
            /* Raw IRC command (remove leading '/') */
            sendln(line + 1);
            print_ts(logfp, "-> ", line);
        }
    } else {
        /* Regular channel message (sends to the default CHANNEL define) */
        char msg[BUFFER_SIZE];
        snprintf(msg, sizeof(msg), "PRIVMSG %s :%s", CHANNEL, line);
        sendln(msg);
        print_ts(logfp, "-> ", line);
    }
}

/*
- Cleanup resources
*/
static void cleanup(void) {
    if (ssl_conn) {
        write_raw_line("QUIT :Goodbye"); // Use raw write for QUIT
        SSL_shutdown(ssl_conn);
        SSL_free(ssl_conn);
        /* Note: SSL_CTX is freed inside dial, so no need to free here */
    }
    if (logfp) fclose(logfp);
}

/*
- Main event loop with dynamic keep-alive management
*/
int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server> <port> <nick> [nickserv_pass]\n",
                argv[0]);
        return 1;
    }

    const char *server = argv[1];
    const char *port = argv[2];
    
    /* Safely copy nick and password, ensuring null termination */
    strncpy(nick, argv[3], sizeof(nick) - 1);
    nick[sizeof(nick) - 1] = '\0';

    if (argc >= 5) {
        strncpy(nspass, argv[4], sizeof(nspass) - 1);
        nspass[sizeof(nspass) - 1] = '\0';
    } else {
        nspass[0] = '\0'; /* Ensure empty if no password given */
    }

    /* Open log file */
    logfp = fopen(LOGFILE, "a");
    if (!logfp) {
        perror("fopen logfile");
        /* Execution continues even if logging fails */
    }

    /* Connect to server */
    int s = dial(server, port);
    if (s < 0) {
        if (logfp) fclose(logfp);
        return 1;
    }

    /* Register with IRC server */
    char regbuf[256];
    snprintf(regbuf, sizeof(regbuf), "NICK %s", nick);
    sendln(regbuf);
    snprintf(regbuf, sizeof(regbuf), "USER %s 0 * :%s", nick, nick);
    sendln(regbuf);

    /* Set stdin to non-blocking */
    int stdin_flags = fcntl(0, F_GETFL, 0);
    if (fcntl(0, F_SETFL, stdin_flags | O_NONBLOCK) == -1) {
        perror("fcntl stdin");
    }

    /* Initialize keep-alive timer */
    last_msg_time = time(NULL);

    /* Main event loop */
    struct pollfd fds[2];
    char server_buf[BUFFER_SIZE];
    char stdin_buf[BUFFER_SIZE];
    int server_buflen = 0;

    atexit(cleanup);

    while (1) {
        /* Calculate dynamic timeout until next PING */
        time_t now = time(NULL);
        int elapsed = now - last_msg_time;
        int timeout_ms = (PING_TIMEOUT - elapsed) * 1000;

        if (timeout_ms <= 0) {
            /* Time to send keep-alive PING */
            sendln("PING :keepalive");
            last_msg_time = now;
            timeout_ms = PING_TIMEOUT * 1000;
        }
        
        /* Channel join is now exclusively manual. */

        /* Setup poll */
        fds[0].fd = s;
        fds[0].events = POLLIN;
        fds[1].fd = 0; /* stdin */
        fds[1].events = POLLIN;

        int ret = poll(fds, 2, timeout_ms);

        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        
        /* Handle server data */
        if (fds[0].revents & POLLIN) {
            int n = SSL_read(ssl_conn, server_buf + server_buflen,
                             sizeof(server_buf) - server_buflen - 1);

            if (n > 0) {
                last_msg_time = time(NULL); /* Reset keep-alive timer */
                server_buflen += n;
                server_buf[server_buflen] = '\0';

                /* Process complete lines */
                char *line_start = server_buf;
                char *line_end;
                while ((line_end = strstr(line_start, "\r\n")) != NULL) {
                    *line_end = '\0';
                    handle_server_msg(line_start);
                    line_start = line_end + 2;
                }

                /* Move incomplete line to buffer start */
                size_t remaining = strlen(line_start);
                server_buflen = (int)remaining;
                if (server_buflen > 0) {
                    memmove(server_buf, line_start, server_buflen + 1);
                }
            } else if (n == 0) {
                printf("*** Connection closed by server\n");
                break;
            } else {
                int err = SSL_get_error(ssl_conn, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    fprintf(stderr, "*** SSL Read Error: %d\n", err);
                    break;
                }
            }
        }

        /* Handle user input */
        if (fds[1].revents & POLLIN) {
            if (fgets(stdin_buf, sizeof(stdin_buf), stdin)) {
                handle_user_input(stdin_buf);
            }
        }

        /* Check for connection errors */
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            printf("*** Connection error or hangup detected\n");
            break;
        }
    }

    return 0;
}
