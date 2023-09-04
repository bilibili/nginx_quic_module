#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <quic_stack_api.h>
#include <ngx_quic_module.h>


static ngx_int_t ngx_http_quic_headers_filter_init(ngx_conf_t *cf);
static void *ngx_http_quic_create_conf(ngx_conf_t *cf);

static char *ngx_http_use_quic(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy);

typedef struct {
    ngx_quic_core_stack_conf_t  *qscf;

} ngx_http_quic_conf_t;

#define NGX_QUIC_SESSION_SEND_HEADER        1
#define NGX_QUIC_SESSION_SEND_BODY          2
#define NGX_QUIC_SESSION_CHUNK_BODY_BEGIN   3
#define NGX_QUIC_SESSION_CHUNK_BODY_ING     4
#define NGX_QUIC_SESSION_SEND_END           99


typedef struct ngx_http_quic_session_s ngx_http_quic_session_t;

struct ngx_http_quic_session_s {
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_quic_stack_t              *stack;
    tQuicRequestID                 req_id;
    off_t                          body_send_size;
    int                            send_state;
};


static int
ngx_http_quic_on_request_header(const tQuicRequestID* id, const char *data, size_t len, void **ctx, void *server_conf);
static int
ngx_http_quic_on_request_body(const tQuicRequestID *id, void *ctx, void *server_conf);
static int
ngx_http_quic_on_request_close(const tQuicRequestID *id, void *ctx, void *server_conf);

static int
ngx_http_quic_create_request(const tQuicRequestID *id, void **ctx, void *server_conf);

static ngx_connection_t*
ngx_http_quic_create_connection(const tQuicRequestID *id, ngx_quic_stack_t* stack, ngx_http_core_srv_conf_t *cscf);
static void
ngx_http_quic_destroy_connection(ngx_connection_t* c);


static void
ngx_http_quic_close_handler(ngx_event_t *ev);
static ngx_int_t
ngx_http_quic_process_request_line(ngx_http_request_t *r);
static ngx_int_t
ngx_http_quic_process_request_headers(ngx_http_request_t *r);
static ngx_int_t
ngx_http_quic_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc);
static ngx_int_t
ngx_http_quic_process_host(ngx_http_request_t *r, ngx_table_elt_t *h);

static ssize_t
ngx_http_quic_recv(ngx_connection_t *c, u_char *buf, size_t size);
static ssize_t
ngx_http_quic_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
static ssize_t
ngx_http_quic_send(ngx_connection_t *c, u_char *buf, size_t size);
static void
ngx_http_quic_close_session(ngx_http_quic_session_t *s);
static ngx_chain_t*
ngx_http_quic_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit);
static void
ngx_http_quic_on_can_write_once(void *ctx);


static ngx_command_t  ngx_http_quic_commands[] = {

    { ngx_string("enable_quic"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_use_quic,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_quic_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_quic_headers_filter_init,     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_quic_create_conf,             /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_quic_module = {
    NGX_MODULE_V1,
    &ngx_http_quic_module_ctx,             /* module context */
    ngx_http_quic_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* initialize quic stack with server name, certification, http callbacks. */
static char *
ngx_http_use_quic(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_quic_conf_t        *qcf = conf;
    ngx_http_core_srv_conf_t    *cscf;

    ngx_str_t                   *value;
    ngx_uint_t                   i;
    ngx_str_t                    name;
    ngx_http_server_name_t      *sn;
    ngx_quic_core_stack_conf_t  *qscf;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_str_t                   *cert, *key;
    ngx_uint_t                   cert_n, key_n, sn_n;
    tQuicServerCtx              *server_ctx;

    cscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);

    value = cf->args->elts;

    qscf = ngx_quic_get_server_by_name(cf->cycle, &value[1]);

    if (qscf == NULL) {
      ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "quic stack \"%V\" not exist", &value[1]);
      return NGX_CONF_ERROR;
    }


    // get cert/key path from http/server config
    sscf = ngx_http_get_module_srv_conf(cscf->ctx, ngx_http_ssl_module);
    cert = sscf->certificates->elts;
    cert_n = sscf->certificates->nelts;
    key = sscf->certificate_keys->elts;
    key_n = sscf->certificate_keys->nelts;
    if (cert == NULL || cert_n < 1 || key == NULL || key_n < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"enable_quic\" directive should specific after ssl config");
        return NGX_CONF_ERROR;
    }

    // get server name from http/server config
    sn = cscf->server_names.elts;
    sn_n = cscf->server_names.nelts;
    if (sn == NULL || sn_n < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"enable_quic\" directive should specific after server_name config");
        return NGX_CONF_ERROR;
    }

    server_ctx = ngx_palloc(cf->pool, sizeof(tQuicServerCtx));
    for (i = 0; i < sn_n; i++) {
        name = sn[i].name;
        server_ctx->module_idx = ngx_http_core_module.index;
        server_ctx->on_request_header_impl = (void*)ngx_http_quic_on_request_header;
        server_ctx->on_request_body_impl = (void*)ngx_http_quic_on_request_body;
        server_ctx->on_request_close_impl = (void*)ngx_http_quic_on_request_close;
        server_ctx->server_conf = (void*) cscf;
        ngx_quic_add_server_name(qscf, server_ctx, &cert[0], &key[0], &name);
    }

    qcf->qscf = qscf;

    return NGX_CONF_OK;
}

static void *ngx_http_quic_create_conf(ngx_conf_t *cf)
{
    ngx_http_quic_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quic_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}

static ngx_connection_t* ngx_http_quic_create_connection(
    const tQuicRequestID *id,
    ngx_quic_stack_t* stack,
    ngx_http_core_srv_conf_t *cscf)
{
    u_char                          buf[NGX_SOCKADDR_STRLEN];
    ngx_pool_t                     *pool;
    ngx_log_t                      *log;
    ngx_http_log_ctx_t             *log_ctx;
    ngx_event_t                    *rev, *wev;
    ngx_connection_t               *c;
    ngx_http_connection_t          *hc;
    struct sockaddr                *self_sockaddr;
    socklen_t                       self_socklen;
    struct sockaddr                *peer_sockaddr;
    socklen_t                       peer_socklen;
    ngx_str_t                       addr_text;

    //TODO: make configurable
    pool = ngx_create_pool(4096, stack->log);
    if (pool == NULL) {
        return NULL;
    }

    log = ngx_pcalloc(pool, sizeof(ngx_log_t));
    if (log == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    log_ctx = ngx_pcalloc(pool, sizeof(ngx_http_log_ctx_t));
    if (log_ctx == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    ngx_memcpy(log, stack->log, sizeof(ngx_log_t));
    log->data   = log_ctx;
    log->action = "creating quic connection";

    hc = ngx_pcalloc(pool, sizeof(ngx_http_connection_t));
    if (hc == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    hc->conf_ctx = cscf->ctx;

    peer_socklen  = id->peer_socklen;
    peer_sockaddr = ngx_pcalloc(pool, peer_socklen);
    if (peer_sockaddr == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    memcpy(peer_sockaddr, id->peer_sockaddr, peer_socklen);
    
    // addr text
    addr_text.len = ngx_sock_ntop(peer_sockaddr, peer_socklen,
                                  buf, NGX_SOCKADDR_STRLEN, 0);
    addr_text.data = ngx_pcalloc(pool, sizeof(u_char) * addr_text.len);
    if (addr_text.data == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }
    ngx_memcpy(addr_text.data, buf, addr_text.len);

    // local sockaddr
    self_socklen  = id->self_socklen;
    self_sockaddr = ngx_pcalloc(pool, self_socklen);
    if (self_sockaddr == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    c = ngx_get_connection(stack->fd, stack->log);
    if (c == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    log_ctx->connection      = c;

    rev = c->read;
    rev->active  = 1;
    rev->ready   = 1;
    rev->eof     = 1;
    rev->handler = ngx_http_quic_close_handler;
    rev->log = log;

    wev = c->write;
    ngx_memcpy(wev, rev, sizeof(ngx_event_t));
    wev->write = 1;
    wev->active = 1;

    c->fd                   = stack->fd;
    c->shared               = 1;
    c->pool                 = pool;
    c->data                 = hc;
    c->sent                 = 0;
    c->log                  = log;
    c->buffered             = 0;
    c->sndlowat             = 1;
    c->destroyed            = 1;
    c->tcp_nodelay          = NGX_TCP_NODELAY_DISABLED;
    c->socklen              = peer_socklen;
    c->sockaddr             = peer_sockaddr;
    c->addr_text            = addr_text;
    c->local_socklen        = self_socklen;
    c->local_sockaddr       = self_sockaddr;

    c->recv                 = ngx_http_quic_recv;
    c->send                 = ngx_http_quic_send;
    c->recv_chain           = ngx_http_quic_recv_chain;
    c->send_chain           = ngx_http_quic_send_chain;

    return c;
}


static void
ngx_http_quic_close_handler(ngx_event_t *ev)
{
}


static ngx_int_t
ngx_http_quic_process_request_line(ngx_http_request_t *r)
{
    ngx_int_t               rc;
    ngx_connection_t       *c;

    rc = ngx_http_parse_request_line(r, r->header_in);
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return rc;
    }
    c = r->connection;

    /* the request line has been parsed successfully */

    r->request_line.len = r->request_end - r->request_start;
    r->request_line.data = r->request_start;
    r->request_length = r->header_in->pos - r->request_start;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http request line: \"%V\"", &r->request_line);

    r->method_name.len = r->method_end - r->request_start + 1;
    r->method_name.data = r->request_line.data;

    if (r->http_protocol.data) {
        r->http_protocol.len = r->request_end - r->http_protocol.data;
    }

    rc = ngx_http_process_request_uri(r);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t));
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return rc;
    }

    c->log->action = "reading client request headers";

    return NGX_OK;
}


static ngx_int_t
ngx_http_quic_process_request_headers(ngx_http_request_t *r)
{
    ngx_int_t                   rc;
    ngx_connection_t           *c;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    c = r->connection;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    for ( ;; ) {

        /* the host header could change the server configuration context */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        rc = ngx_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == NGX_OK) {

            r->request_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                return NGX_ERROR;
            }

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);
            if (hh) {
                if (h->key.len == 4 &&
                    h->lowcase_key[0] == 'h' && h->lowcase_key[1] == 'o' &&
                    h->lowcase_key[2] == 's' && h->lowcase_key[3] == 't') {

                    rc = ngx_http_quic_process_host(r, h); // just use default server

                } else {
                    rc = hh->handler(r, h, hh->offset);
                }
                if (rc != NGX_OK) {
                    return rc;
                }
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                return rc;
            }

            ngx_http_process_request(r);

            break;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line");

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_quic_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NGX_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NGX_DECLINED;

        default:

            if (ngx_path_separator(ch)) {
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    if (alloc) {
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_quic_process_host(ngx_http_request_t *r, ngx_table_elt_t *h)
{
    ngx_int_t                  rc;
    ngx_str_t                  host;
    ngx_http_connection_t     *hc;
    ngx_http_conf_ctx_t       *http_ctx;

    if (r->headers_in.host == NULL) {
        r->headers_in.host = h;
    }

    host     = h->value;
    hc       = r->http_connection;
    http_ctx = hc->conf_ctx;

    rc = ngx_http_quic_validate_host(&host, r->pool, 0);

    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid host header");
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (r->headers_in.server.len) {
        return NGX_OK;
    }

    r->srv_conf = http_ctx->srv_conf;
    r->loc_conf = http_ctx->loc_conf;

    r->headers_in.server = host;

    return NGX_OK;
}


static ssize_t
ngx_http_quic_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int                             rc;
    ngx_http_quic_session_t        *s;
    ngx_http_request_t             *r;
    ngx_quic_stack_t               *stack;

    r = c->data;
    s = (void*)r->parent;
    if (s == NULL) {
        return NGX_ERROR;
    }

    stack = s->stack;
    if (stack == NULL || stack->handler == NULL) {
        return NGX_ERROR;
    }

    rc = quic_stack_read_request_body(
        stack->handler,
        &s->req_id,
        (char*)buf,
        size);

    if (rc == QUIC_STACK_STREAM_CLOSED) {
        return 0;
    }

    if (rc < 0) {
        return NGX_ERROR;
    }

    if (rc == 0) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    c->read->ready = 1;

    return rc;
}

static ssize_t
ngx_http_quic_recv_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "ngx_http_quic_recv_chain unplanned to be called, "
                          "check your callstacks");

    return NGX_AGAIN;
}


static ssize_t
ngx_http_quic_send(ngx_connection_t *c, u_char *buf, size_t size)
{
    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "ngx_http_quic_send unplanned to be called, "
                          "check your callstacks");
    return NGX_AGAIN;
}


static int can_send_quic_fin(ngx_chain_t *in)
{
    int f;
    for (f = 0; !f && in ; in = in->next) {
        if (!ngx_buf_special(in->buf)) {
            break;
        }
        f = in->buf->last_buf;
    }
    return f;
}

static void
ngx_http_quic_close_session(ngx_http_quic_session_t *s)
{
    if (s->send_state == NGX_QUIC_SESSION_SEND_END) { // QUIC stack will callback close
        return;
    }

    s->send_state = NGX_QUIC_SESSION_SEND_END;
    quic_stack_close_stream(
        s->stack->handler,
        &s->req_id);
}


static off_t
ngx_http_quic_get_chunk_size(ngx_buf_t* buf)
{
    off_t size = 0;
    ngx_uint_t found = 0;
    u_char ch, *p = NULL;

    for (p = buf->pos; p < buf->last; p++) {
        ch = *p;
        if (ch == CR) {
            ch = *(p + 1);
            if (ch != LF) {
                size = -1;
            }
            p += 2; // CRLF
            break;
        }

        found = 1;
        if (ch <= '9' && ch >= '0') {
            size = size * 16 + (ch - '0');
            continue;
        } else if (ch >= 'a' && ch <= 'f') {
            size = size * 16 + (ch - 'a' + 10);
            continue;
        } else if (ch >= 'A' && ch <= 'F') {
            size = size * 16 + (ch - 'A' + 10);
            continue;
        }

        size = -1;
        break;
    }

    if (size < 0) {
        return size;
    }
    if (!found) {
        return -1;
    }

    //TODO actually buf chain has trailer header data after chunked 0\r\n
    // We should support this in future.

    buf->pos = p;

    return size;
}


static ngx_buf_t*
ngx_http_quic_process_trailers(ngx_http_request_t *r)
{
    ngx_list_t                      trailers;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *trailer;
    ngx_uint_t                      i;
    ngx_buf_t                      *tb, *tmp;
    size_t                          len;

    len = 1024;
    tb = ngx_create_temp_buf(r->pool, len);
    if (tb == NULL) {
        return NULL;
    }

    trailers = r->headers_out.trailers;
    part = &trailers.part;
    trailer = part->elts;
    for (i = 0; /*void*/; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            trailer = part->elts;
            i = 0;
        }
        if (trailer[i].hash == 0) {
            continue;
        }

        size_t used = tb->last - tb->start;
        while ((len - used) < (trailer[i].key.len + trailer[i].value.len + 3)) {
            len *= 2;
        }

        if (len > (size_t)(tb->end - tb->start)) {
            tmp = ngx_create_temp_buf(r->pool, len);
            if (tmp == NULL) {
                return NULL;
            }

            tmp->last = ngx_copy(tmp->last, tb->start, tb->last - tb->start);
            tb = tmp;
        }

        tb->last = ngx_copy(tb->last, trailer[i].key.data, trailer[i].key.len);
        *tb->last++ = ':'; *tb->last++ = ' ';

        tb->last = ngx_copy(tb->last, trailer[i].value.data, trailer[i].value.len);
        *tb->last++ = '\n';
    }

    return tb;
}


static ngx_chain_t*
ngx_http_quic_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    size_t                          n, tbl;
    off_t                           sent;
    int                             rc, send_fin;
    ngx_quic_core_stack_conf_t     *qscf;
    ngx_http_quic_session_t        *s;
    ngx_http_request_t             *r;
    ngx_buf_t                      *b;
    tQuicOnCanWriteCallback         ngx_wr_cb;
    ngx_buf_t                      *tb;

    r = c->data;
    s = (void*)r->parent;
    if (s == NULL) {
        r->main->write_event_handler = NULL;
        return NGX_CHAIN_ERROR;
    }

    qscf = s->stack->qscf;

    if (s->send_state == NGX_QUIC_SESSION_SEND_END) {
        // drain the no needed chain buffer
        return NULL;
    }

    if (s->send_state == NGX_QUIC_SESSION_SEND_HEADER) {
        if (!r->header_sent) {
            return in;
        }

        b = in->buf;
        n = ngx_buf_size(b);


        if (n != r->header_size) {  // header should be the first chain buffer
            r->main->write_event_handler = NULL;
            ngx_http_quic_close_session(s);
            return NGX_CHAIN_ERROR;
        }

        send_fin = b->last_buf ? b->last_buf : can_send_quic_fin(in->next);
        s->body_send_size = r->headers_out.content_length_n;
        if (!send_fin && !r->chunked && s->body_send_size <= 0) {
            send_fin = 1;
        }


        tb = ngx_http_quic_process_trailers(r);
        if (tb == NULL) {
            r->main->write_event_handler = NULL;
            return NGX_CHAIN_ERROR;
        }

        tbl = ngx_buf_size(tb);
        rc = quic_stack_write_response_header(
            s->stack->handler,
            &s->req_id,
            (const char*)b->pos,
            n,
            (const char*)tb->pos,
            tbl,
            send_fin);
        if (rc != QUIC_STACK_OK) {
            r->main->write_event_handler = NULL;
            ngx_http_quic_close_session(s);
            return NGX_CHAIN_ERROR;
        }

        if (send_fin) {
            s->send_state = NGX_QUIC_SESSION_SEND_END;
        } else {
            s->send_state = r->chunked ? NGX_QUIC_SESSION_CHUNK_BODY_BEGIN : NGX_QUIC_SESSION_SEND_BODY;
        }

        c->sent += n;
        in = ngx_chain_update_sent(in, n);
    }

    sent = 0; // header not included in rate limit
    while (s->send_state != NGX_QUIC_SESSION_SEND_END) {

        if (in == NULL) {
            return in;
        }

        b = in->buf;
        if ((!b->pos || !b->last || b->pos >= b->last) && !b->last_buf) {
            in = in->next;
            continue;
        }

        n = ngx_buf_size(b);

        send_fin = 0;
        if (s->send_state == NGX_QUIC_SESSION_SEND_BODY) {
            send_fin = b->last_buf ? b->last_buf : can_send_quic_fin(in->next);
            if (!send_fin && s->body_send_size <= (off_t)n) {
                send_fin = 1;
            }
        } else {
            if (s->send_state == NGX_QUIC_SESSION_CHUNK_BODY_BEGIN) {
                s->send_state = NGX_QUIC_SESSION_CHUNK_BODY_ING;
                s->body_send_size = ngx_http_quic_get_chunk_size(b);
                if (s->body_send_size < 0) {
                    n = 0;
                    send_fin = 1;
                } else if (s->body_send_size == 0) { // really last one
                    n = ngx_buf_size(b);
                    send_fin = 1;
                } else {
                    n = ngx_buf_size(b);
                    if (n == 0) {
                        in = in->next;
                        continue;
                    }
                }
            } else if (s->send_state == NGX_QUIC_SESSION_CHUNK_BODY_ING) {
                if (s->body_send_size == 0) {
                    if (*(b->pos) != CR || *(b->pos + 1) != LF) {
                        n = 0;
                        send_fin = 1;
                    } else {
                        in = ngx_chain_update_sent(in, 2); // drain CRLF
                        s->send_state = NGX_QUIC_SESSION_CHUNK_BODY_BEGIN;
                        continue;
                    }
                }
            }
        }

        if ((off_t)n > s->body_send_size) {
            n = s->body_send_size;
        }

        // trailers sent after body
        tb = ngx_http_quic_process_trailers(r);
        if (tb == NULL) {
            r->main->write_event_handler = NULL;
            return NGX_CHAIN_ERROR;
        }

        tbl = ngx_buf_size(tb);

        rc = quic_stack_write_response_body(
            s->stack->handler,
            &s->req_id,
            (const char*)b->pos,
            n,
            (const char*)tb->pos,
            tbl,
            qscf->session_buffer_size,
            send_fin);

        if (rc < 0) {
            r->main->write_event_handler = NULL;
            ngx_http_quic_close_session(s);
            return NGX_CHAIN_ERROR;
        }

        if (n > 0 && rc == 0 && !send_fin) { // quic stack session buffer fulled, delay it
            c->write->ready   = 1;

            ngx_wr_cb.OnCanWriteCallback = ngx_http_quic_on_can_write_once;
            ngx_wr_cb.OnCanWriteContext  = c->write;
            quic_stack_add_on_can_write_callback_once(
                s->stack->handler,
                &s->req_id,
                ngx_wr_cb);

            return in;
        }

        if (send_fin) {
            s->send_state = NGX_QUIC_SESSION_SEND_END;
        }

        sent += rc;
        c->sent += rc;
        s->body_send_size -= rc;
        in = ngx_chain_update_sent(in, rc);

        if (limit && sent >= limit) {
            return in;
        }
    }

    if (r->chunked && s->send_state == NGX_QUIC_SESSION_SEND_END) {
        return NULL;
    }

    return in;
}


static void
ngx_http_quic_destroy_connection(ngx_connection_t* c)
{
    ngx_http_close_connection(c);
}


static void
ngx_http_quic_cleanup(void *data)
{
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_http_quic_session_t        *s;

    s = data;
    if (s ==NULL) {
        return;
    }

    r = s->r;
    c = r->connection;

    ngx_http_quic_close_session(s);

    r->parent = NULL;

#if (NGX_HTTP_SSL)
    c->ssl = NULL;
#endif

    // Mark request line as HTTP/3.0
    (r->http_protocol.data)[r->http_protocol.len - 1] = '0';
    (r->http_protocol.data)[r->http_protocol.len - 3] = '3';

    return;
}

static int
ngx_http_quic_create_request(
    const tQuicRequestID *id,
    void **ctx,
    void *server_conf)
{
    ngx_pool_t                     *pool;
    ngx_quic_stack_t               *stack;
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_http_quic_session_t        *s;
    ngx_http_core_srv_conf_t       *cscf;
    ngx_quic_core_stack_conf_t     *qscf;
    ngx_http_cleanup_t             *cln;

    stack = *ctx; // first time, callback ctx is stack context
    if (stack == NULL) {
        return QUIC_STACK_OK;
    }

    qscf = stack->qscf;
    if (qscf == NULL) {
        return QUIC_STACK_SERVER;
    }

    cscf = server_conf;
    if (cscf == NULL) {
        return QUIC_STACK_SERVER;
    }

    c = ngx_http_quic_create_connection(id, stack, cscf);
    if (c == NULL) {
        return QUIC_STACK_MEM;
    }

    pool = c->pool;

    s = ngx_pcalloc(pool, sizeof(ngx_http_quic_session_t));
    if (s == NULL) {
        ngx_http_quic_destroy_connection(c);
        return QUIC_STACK_MEM;
    }

    s->send_state = NGX_QUIC_SESSION_SEND_HEADER;
    s->body_send_size = 0;
    s->stack = stack;

    // connection id
    memcpy(s->req_id.connection_data, id->connection_data, id->connection_len);
    s->req_id.connection_len = id->connection_len;
    s->req_id.stream_id = id->stream_id;

    r = ngx_http_create_request(c);
    if (r == NULL) {
        ngx_http_quic_destroy_connection(c);
        return QUIC_STACK_MEM;
    }

    c->data = r;

#if (NGX_HTTP_SSL)
    c->ssl = NULL; // treat quic request as `https` request
#endif

    r->parent  = (void*)s;

    s->c    = c;
    s->r    = r;

    *ctx = s; // store context

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_free_request(r, 0);
        ngx_http_quic_destroy_connection(c);
        return QUIC_STACK_MEM;
    }
    cln->handler = ngx_http_quic_cleanup;
    cln->data    = s;

    return QUIC_STACK_OK;
}


static int
ngx_http_quic_on_request_header(
    const tQuicRequestID* id,
    const char *data,
    size_t len,
    void **ctx,
    void  *server_conf)
{
    ngx_int_t                       rc;
    ngx_http_request_t             *r;
    ngx_http_quic_session_t        *s;

    rc = ngx_http_quic_create_request(id, ctx, server_conf);
    if (rc != QUIC_STACK_OK) {
        return rc;
    }

    s = *ctx;
    r = s->r;

    ngx_str_set(&r->http_protocol, "HTTP/1.1");

    r->http_version = NGX_HTTP_VERSION_11;
    r->valid_location = 1;
    r->main_filter_need_in_memory = 1;

    r->header_in = ngx_create_temp_buf(r->pool, len);
    if (r->header_in == NULL) {
        ngx_http_free_request(r, 0);
        return QUIC_STACK_MEM;
    }

    rc = ngx_list_init(&r->headers_in.headers, r->pool, 20,
                       sizeof(ngx_table_elt_t));
    if (rc != NGX_OK) {
        ngx_http_free_request(r, 0);
        return QUIC_STACK_MEM;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    memcpy(r->header_in->start, data, len);
    r->header_in->last += len;

    rc = ngx_http_quic_process_request_line(r);
    if (rc != NGX_OK) {
        return QUIC_STACK_SERVER;
    }

    rc = ngx_http_quic_process_request_headers(r);
    if (rc != NGX_OK) {
        return QUIC_STACK_SERVER;
    }

    return QUIC_STACK_OK;
}


static int
ngx_http_quic_on_request_body(
    const tQuicRequestID *id,
    void *ctx,
    void *server_conf)
{
    ngx_event_t                    *rev;
    ngx_connection_t               *c;
    ngx_http_request_t             *r;
    ngx_http_quic_session_t        *s;

    s = ctx;
    r = s->r;
    c = r->connection;
    rev = c->read;

    rev->ready = 1;
    rev->active = 1;
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (r->read_event_handler) {
        r->read_event_handler(r);
    }

    return QUIC_STACK_OK;
}


static int
ngx_http_quic_on_request_close(
    const tQuicRequestID *id,
    void *ctx,
    void *server_conf)
{
    return QUIC_STACK_OK;
}


static void
ngx_http_quic_on_can_write_once(void *ctx)
{
    ngx_event_t *ev = (ngx_event_t *)ctx;
    if (ev && ev->handler) {
        ev->handler(ev);
    }
}


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_int_t
ngx_http_quic_headers_filter(ngx_http_request_t *r)
{
    
    ngx_http_core_srv_conf_t       *cscf;
    ngx_http_quic_conf_t           *qcf;
    ngx_quic_core_stack_conf_t     *qscf;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    qcf = ngx_http_get_module_srv_conf(r, ngx_http_quic_module);
    if (!cscf || !qcf) {
        return ngx_http_next_header_filter(r);
    }

    qscf = qcf->qscf;
    if (!qscf) {
        return ngx_http_next_header_filter(r);
    } 

    if (!qscf->alt_svc_str.data
        || qscf->alt_svc_str.len <= 0) {
        return ngx_http_next_header_filter(r);
    }

    ngx_str_t quic_header_key;
    ngx_str_set(&quic_header_key, "alt-svc");

    ngx_table_elt_t *h;
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    h->key = quic_header_key;
    h->value = qscf->alt_svc_str;
    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_quic_headers_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_quic_headers_filter;
    return NGX_OK;
}
