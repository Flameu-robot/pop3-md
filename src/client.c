#ifdef _WIN32
    #define _WIN32_WINNT 0x0600
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET sock_t;
    #define SOCK_INVALID INVALID_SOCKET
    #define sock_close   closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    typedef int sock_t;
    #define SOCK_INVALID (-1)
    #define sock_close   close
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#ifdef _WIN32
    static char *strcasestr(const char *haystack, const char *needle)
    {
        size_t needle_len = strlen(needle);
        for (; *haystack; haystack++)
            if (strncasecmp(haystack, needle, needle_len) == 0)
                return (char *)haystack;
        return NULL;
    }
    #define BUFFER_LINE_MAX 2048
#else
    #define BUFFER_LINE_MAX 2048
#endif

#define GMAIL_HOST "pop.gmail.com"
#define GMAIL_PORT 995

typedef struct {
    sock_t   fd;
    SSL_CTX *ctx;
    SSL     *ssl;
} Conn;

typedef struct {
    char   ctype[256];
    char   cenc[64];
    char   filename[512];
    int    is_attach;
    char  *data;
    size_t data_len;
} MimePart;

static sock_t tcp_connect(const char *host, int port)
{
    struct addrinfo hints, *res, *p;
    char port_str[8];
    sock_t s = SOCK_INVALID;

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return SOCK_INVALID;

    for (p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == SOCK_INVALID) continue;
        if (connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        sock_close(s);
        s = SOCK_INVALID;
    }
    freeaddrinfo(res);
    return s;
}

static int ssl_connect(Conn *c, const char *host, int port)
{
    printf("Connecting to %s:%d ...\n", host, port);

    c->fd = tcp_connect(host, port);
    if (c->fd == SOCK_INVALID) {
        fprintf(stderr, "[ERROR] TCP connect failed\n");
        return -1;
    }
    printf("[OK] TCP connected\n");

#ifdef _WIN32
    DWORD tv = 20000;
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv = {20, 0};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) {
        fprintf(stderr, "[ERROR] SSL_CTX_new failed\n");
        sock_close(c->fd);
        return -1;
    }

    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, NULL);

    c->ssl = SSL_new(c->ctx);
    if (!c->ssl) {
        fprintf(stderr, "[ERROR] SSL_new failed\n");
        SSL_CTX_free(c->ctx);
        sock_close(c->fd);
        return -1;
    }

    SSL_set_tlsext_host_name(c->ssl, host);
    SSL_set_fd(c->ssl, (int)c->fd);

    if (SSL_connect(c->ssl) != 1) {
        fprintf(stderr, "[ERROR] SSL handshake failed\n");
        SSL_free(c->ssl);
        SSL_CTX_free(c->ctx);
        sock_close(c->fd);
        return -1;
    }

    printf("[OK] SSL: %s, %s\n", SSL_get_version(c->ssl), SSL_get_cipher(c->ssl));
    return 0;
}

static void ssl_close(Conn *c)
{
    if (c->ssl) { SSL_shutdown(c->ssl); SSL_free(c->ssl); c->ssl = NULL; }
    if (c->ctx) { SSL_CTX_free(c->ctx); c->ctx = NULL; }
    if (c->fd != SOCK_INVALID) { sock_close(c->fd); c->fd = SOCK_INVALID; }
}

static int recv_line(Conn *c, char *buf, int max)
{
    int pos = 0;
    char ch;

    while (pos < max - 1) {
        int r = SSL_read(c->ssl, &ch, 1);
        if (r <= 0) {
            int err = SSL_get_error(c->ssl, r);
            if (err == SSL_ERROR_WANT_READ) continue;
            return -1;
        }
        if (ch == '\n') break;
        if (ch != '\r') buf[pos++] = ch;
    }
    buf[pos] = '\0';
    return pos;
}

static int send_cmd(Conn *c, const char *cmd)
{
    char buf[BUFFER_LINE_MAX];
    int n = snprintf(buf, sizeof(buf) - 2, "%s", cmd);
    buf[n++] = '\r';
    buf[n++] = '\n';

    int sent = 0;
    while (sent < n) {
        int r = SSL_write(c->ssl, buf + sent, n - sent);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

static int is_ok(const char *line)
{
    return strncmp(line, "+OK", 3) == 0;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64val(char c)
{
    const char *p = strchr(B64, c);
    return p ? (int)(p - B64) : -1;
}

static unsigned char *b64_decode(const char *in, size_t in_len, size_t *out_len)
{
    char *clean = (char *)malloc(in_len + 4);
    if (!clean) return NULL;
    
    size_t cl = 0;
    for (size_t i = 0; i < in_len; i++)
        if (!isspace((unsigned char)in[i]))
            clean[cl++] = in[i];
    while (cl % 4) clean[cl++] = '=';
    clean[cl] = '\0';

    unsigned char *out = (unsigned char *)malloc((cl / 4) * 3 + 4);
    if (!out) { free(clean); return NULL; }

    size_t j = 0;
    for (size_t i = 0; i + 3 < cl + 1; i += 4) {
        int v0 = b64val(clean[i]);
        int v1 = b64val(clean[i+1]);
        int v2 = (clean[i+2]=='=') ? 0 : b64val(clean[i+2]);
        int v3 = (clean[i+3]=='=') ? 0 : b64val(clean[i+3]);
        if (v0 < 0 || v1 < 0) break;
        out[j++] = (unsigned char)((v0 << 2) | (v1 >> 4));
        if (clean[i+2] != '=') out[j++] = (unsigned char)((v1 << 4) | (v2 >> 2));
        if (clean[i+3] != '=') out[j++] = (unsigned char)((v2 << 6) | v3);
    }
    free(clean);
    *out_len = j;
    return out;
}

static const char *find_header(const char *msg, const char *name)
{
    size_t nlen = strlen(name);
    const char *p = msg;

    while (*p) {
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
        while (*p && *p != '\n') p++;
        if (*p) p++;
    }
    return NULL;
}

static void copy_header(const char *src, char *dst, size_t max)
{
    size_t i = 0;
    while (*src && *src != '\r' && *src != '\n' && i < max - 1)
        dst[i++] = *src++;
    dst[i] = '\0';
}

static void get_param(const char *hval, const char *param, char *out, size_t max)
{
    char search[128];
    snprintf(search, sizeof(search), "%s=", param);
    const char *p = strcasestr(hval, search);
    if (!p) { out[0] = '\0'; return; }
    
    p += strlen(search);
    int q = (*p == '"');
    if (q) p++;
    
    size_t i = 0;
    while (*p && i < max - 1) {
        if (q && *p == '"') break;
        if (!q && (*p==';'||*p=='\r'||*p=='\n'||*p==' ')) break;
        out[i++] = *p++;
    }
    out[i] = '\0';
}

static const char *body_start(const char *s)
{
    const char *p = strstr(s, "\r\n\r\n");
    if (p) return p + 4;
    p = strstr(s, "\n\n");
    return p ? p + 2 : NULL;
}

static void parse_part(const char *start, size_t len, MimePart *part)
{
    memset(part, 0, sizeof(*part));
    char tmp[512];

    const char *ct = find_header(start, "Content-Type");
    if (ct) {
        copy_header(ct, tmp, sizeof(tmp));
        char *semi = strchr(tmp, ';');
        if (semi) {
            size_t tl = (size_t)(semi - tmp);
            while (tl > 0 && isspace((unsigned char)tmp[tl-1])) tl--;
            strncpy(part->ctype, tmp, tl < sizeof(part->ctype) ? tl : sizeof(part->ctype)-1);
        } else {
            size_t tl = strlen(tmp);
            while (tl > 0 && isspace((unsigned char)tmp[tl-1])) tl--;
            tmp[tl] = '\0';
            strncpy(part->ctype, tmp, sizeof(part->ctype)-1);
        }
        get_param(ct, "name", part->filename, sizeof(part->filename));
    }

    const char *cd = find_header(start, "Content-Disposition");
    if (cd) {
        if (strncasecmp(cd, "attachment", 10) == 0) part->is_attach = 1;
        char fn[512] = {0};
        get_param(cd, "filename", fn, sizeof(fn));
        if (fn[0]) strncpy(part->filename, fn, sizeof(part->filename)-1);
    }

    const char *ce = find_header(start, "Content-Transfer-Encoding");
    if (ce) copy_header(ce, part->cenc, sizeof(part->cenc));

    const char *body = body_start(start);
    if (!body) return;

    size_t off = (size_t)(body - start);
    size_t blen = (off < len) ? (len - off) : 0;
    while (blen > 0 && (body[blen-1]=='\r'||body[blen-1]=='\n')) blen--;

    part->data = (char *)body;
    part->data_len = blen;
}

static void parse_mime(const char *raw, size_t raw_len,
                       char *subject, char *from, MimePart *parts, int *nparts)
{
    memset(subject, 0, 512);
    memset(from, 0, 256);
    *nparts = 0;

    const char *p;
    if ((p = find_header(raw, "Subject"))) copy_header(p, subject, 512);
    if ((p = find_header(raw, "From")))    copy_header(p, from, 256);

    p = find_header(raw, "Content-Type");
    if (p && strncasecmp(p, "multipart/", 10) == 0) {
        char boundary[256] = {0};
        get_param(p, "boundary", boundary, sizeof(boundary));

        if (boundary[0]) {
            char delim[260];
            snprintf(delim, sizeof(delim), "--%s", boundary);
            size_t dlen = strlen(delim);

            const char *cur = raw, *end = raw + raw_len;
            *nparts = 0;

            while (cur < end && *nparts < 10) {
                const char *d = strstr(cur, delim);
                if (!d) break;
                cur = d + dlen;
                if (cur[0] == '-' && cur[1] == '-') break;
                if (cur[0] == '\r') cur++;
                if (cur[0] == '\n') cur++;

                const char *next = strstr(cur, delim);
                size_t plen = next ? (size_t)(next - cur) : (size_t)(end - cur);
                while (plen > 0 && (cur[plen-1]=='\r'||cur[plen-1]=='\n')) plen--;

                parse_part(cur, plen, &parts[(*nparts)++]);
                if (next) cur = next; else break;
            }
            return;
        }
    }

    parse_part(raw, raw_len, &parts[0]);
    *nparts = 1;
}

static int pop3_user(Conn *c, const char *user)
{
    char cmd[BUFFER_LINE_MAX], resp[BUFFER_LINE_MAX];
    snprintf(cmd, sizeof(cmd), "USER %s", user);
    if (send_cmd(c, cmd) < 0) return -1;
    if (recv_line(c, resp, sizeof(resp)) < 0) return -1;
    return is_ok(resp) ? 0 : -1;
}

static int pop3_pass(Conn *c, const char *pass)
{
    char cmd[BUFFER_LINE_MAX], resp[BUFFER_LINE_MAX];
    snprintf(cmd, sizeof(cmd), "PASS %s", pass);
    if (send_cmd(c, cmd) < 0) return -1;
    if (recv_line(c, resp, sizeof(resp)) < 0) return -1;
    return is_ok(resp) ? 0 : -1;
}

static int pop3_stat(Conn *c, int *count, size_t *bytes)
{
    char resp[BUFFER_LINE_MAX];
    if (send_cmd(c, "STAT") < 0) return -1;
    if (recv_line(c, resp, sizeof(resp)) < 0) return -1;
    if (!is_ok(resp)) return -1;
    unsigned long b = 0;
    sscanf(resp, "+OK %d %lu", count, &b);
    *bytes = (size_t)b;
    return 0;
}

static int pop3_list(Conn *c)
{
    char resp[BUFFER_LINE_MAX];
    if (send_cmd(c, "LIST") < 0) return -1;
    if (recv_line(c, resp, sizeof(resp)) < 0) return -1;
    if (!is_ok(resp)) return -1;

    printf("\n  ID   Size(bytes)\n");
    printf("  ---  -----------\n");
    while (1) {
        if (recv_line(c, resp, sizeof(resp)) < 0) return -1;
        if (strcmp(resp, ".") == 0) break;
        printf("  %s\n", resp);
    }
    return 0;
}

static int pop3_retr(Conn *c, int msg_id, char **out_buf, size_t *out_len)
{
    char cmd[BUFFER_LINE_MAX], resp[BUFFER_LINE_MAX];
    snprintf(cmd, sizeof(cmd), "RETR %d", msg_id);
    printf("\n>> Downloading message #%d...\n", msg_id);
    if (send_cmd(c, cmd) < 0) return -1;
    if (recv_line(c, resp, sizeof(resp)) < 0) return -1;
    if (!is_ok(resp)) return -1;

    size_t cap = 1048576;
    size_t used = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return -1;

    long lines = 0;
    for (;;) {
        int n = recv_line(c, resp, sizeof(resp));
        if (n < 0) { free(buf); return -1; }
        if (strcmp(resp, ".") == 0) break;

        const char *src = (resp[0]=='.' && resp[1]=='.') ? resp + 1 : resp;
        size_t slen = strlen(src);
        size_t need = used + slen + 2;

        if (need > cap) {
            while (cap < need) cap *= 2;
            char *tmp = (char *)realloc(buf, cap);
            if (!tmp) { free(buf); return -1; }
            buf = tmp;
        }

        memcpy(buf + used, src, slen);
        used += slen;
        buf[used++] = '\r';
        buf[used++] = '\n';
        lines++;
    }
    buf[used] = '\0';

    printf("   Downloaded: %ld lines, %zu bytes\n", lines, used);
    *out_buf = buf;
    *out_len = used;
    return 0;
}

static void show_message(int msg_id, const char *raw, size_t raw_len)
{
    char subject[512], from[256];
    MimePart parts[10];
    int nparts = 0;

    parse_mime(raw, raw_len, subject, from, parts, &nparts);

    printf("\n====== Message #%d ======\n", msg_id);
    printf("From   : %s\n", from);
    printf("Subject: %s\n", subject);
    printf("Parts  : %d\n\n", nparts);

    int attach_count = 0;
    for (int i = 0; i < nparts; i++) {
        MimePart *p = &parts[i];
        if (!p->filename[0] && !p->is_attach) continue;
        if (!p->data || !p->data_len) continue;

        attach_count++;
        printf("[Attachment #%d] %s\n", attach_count, p->filename);
        printf("  Type: %s\n", p->ctype);
        printf("  Size: %zu bytes\n", p->data_len);

        if (strncasecmp(p->cenc, "base64", 6) == 0) {
            printf("  Decoding Base64...\n");
            size_t dec_len = 0;
            unsigned char *dec = b64_decode(p->data, p->data_len, &dec_len);
            if (dec) {
                printf("  Decoded: %zu bytes\n", dec_len);
                FILE *f = fopen(p->filename, "wb");
                if (f) {
                    fwrite(dec, 1, dec_len, f);
                    fclose(f);
                    printf("  [OK] Saved: %s\n\n", p->filename);
                }
                free(dec);
            }
        } else {
            FILE *f = fopen(p->filename, "wb");
            if (f) {
                fwrite(p->data, 1, p->data_len, f);
                fclose(f);
                printf("  [OK] Saved: %s\n\n", p->filename);
            }
        }
    }

    if (attach_count == 0) {
        printf("[No attachments]\n");
    }
}

static void pop3_quit(Conn *c)
{
    send_cmd(c, "QUIT");
    char resp[BUFFER_LINE_MAX];
    recv_line(c, resp, sizeof(resp));
}

static void show_menu(void)
{
    printf("\n==============================\n");
    printf("  [l] - List messages\n");
    printf("  [d] - Download message\n");
    printf("  [q] - Quit\n");
    printf("==============================\n");
    printf("Choice: ");
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Usage: %s <user@gmail.com> <app_password>\n\n", argv[0]);
        printf("Setup:\n");
        printf("  1. POP3: https://mail.google.com/mail/u/0/#settings/fwdandpop\n");
        printf("  2. Pass: https://myaccount.google.com/apppasswords\n");
        return 1;
    }

    const char *user = argv[1];
    const char *pass = argv[2];

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    printf("=======================================\n");
    printf(" POP3 Client - Gmail SSL (Interactive)\n");
    printf("=======================================\n");
    printf(" User: %s\n", user);
    printf("=======================================\n\n");

    Conn conn;
    memset(&conn, 0, sizeof(conn));
    conn.fd = SOCK_INVALID;

    if (ssl_connect(&conn, GMAIL_HOST, GMAIL_PORT) < 0)
        return 1;

    char resp[BUFFER_LINE_MAX];
    printf("Waiting for greeting...\n");
    if (recv_line(&conn, resp, sizeof(resp)) < 0) {
        fprintf(stderr, "[ERROR] No greeting\n");
        return 1;
    }

    printf("[OK] Connected\n\n");

    printf("Authentication...\n");
    if (pop3_user(&conn, user) < 0 || pop3_pass(&conn, pass) < 0) {
        fprintf(stderr, "[ERROR] Auth failed\n");
        fprintf(stderr, "Get password: https://myaccount.google.com/apppasswords\n");
        return 1;
    }
    printf("[OK] Authenticated\n");

    int total_count = 0;
    size_t total_size = 0;
    if (pop3_stat(&conn, &total_count, &total_size) < 0) {
        fprintf(stderr, "[ERROR] STAT failed\n");
        return 1;
    }
    printf("[OK] Mailbox: %d messages, %zu bytes\n", total_count, total_size);

    char choice[32];
    while (1) {
        show_menu();
        fgets(choice, sizeof(choice), stdin);

        if (choice[0] == 'l' || choice[0] == 'L') {
            if (pop3_list(&conn) < 0) {
                fprintf(stderr, "[ERROR] LIST failed\n");
                break;
            }
        }
        else if (choice[0] == 'd' || choice[0] == 'D') {
            printf("Enter message ID (1-%d): ", total_count);
            fgets(choice, sizeof(choice), stdin);
            int msg_id = atoi(choice);

            if (msg_id < 1 || msg_id > total_count) {
                printf("[ERROR] Invalid ID\n");
                continue;
            }

            char *raw = NULL;
            size_t raw_len = 0;
            if (pop3_retr(&conn, msg_id, &raw, &raw_len) < 0) {
                fprintf(stderr, "[ERROR] RETR failed\n");
                continue;
            }

            char eml_path[64];
            snprintf(eml_path, sizeof(eml_path), "message_%d.eml", msg_id);
            FILE *f = fopen(eml_path, "wb");
            if (f) {
                fwrite(raw, 1, raw_len, f);
                fclose(f);
                printf("Saved raw: %s\n", eml_path);
            }

            show_message(msg_id, raw, raw_len);
            free(raw);
        }
        else if (choice[0] == 'q' || choice[0] == 'Q') {
            break;
        }
        else {
            printf("[ERROR] Invalid choice\n");
        }
    }

    printf("\nQuitting...\n");
    pop3_quit(&conn);
    ssl_close(&conn);
#ifdef _WIN32
    WSACleanup();
#endif
    printf("[OK] Goodbye\n");
    return 0;
}