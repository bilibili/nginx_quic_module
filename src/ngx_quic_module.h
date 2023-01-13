#ifndef _NGX_QUIC_MODULE_H_INCLUDED_
#define _NGX_QUIC_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
#include <ngx_quic_deps.h>
#include <quic_stack_api.h>

#define kMaxV4UdpPacketSize 1472

typedef struct ngx_quic_listen_option_s     ngx_quic_listen_option_t;
typedef struct ngx_quic_stack_s             ngx_quic_stack_t;
typedef struct ngx_quic_log_ctx_s           ngx_quic_log_ctx_t;

typedef struct {
    void        **main_conf;
    void        **stack_conf;
} ngx_quic_conf_ctx_t;


typedef struct {
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);
    ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

    void       *(*create_main_conf)(ngx_conf_t *cf);
    char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

    void       *(*create_stack_conf)(ngx_conf_t *cf);
    char       *(*merge_stack_conf)(ngx_conf_t *cf, void *prev, void *conf);

} ngx_quic_module_t;


#define NGX_QUIC_MODULE           0x43495551   /* "QUIC" */

#define NGX_QUIC_MAIN_CONF        0x02000000
#define NGX_QUIC_STACK_CONF       0x04000000


#define NGX_QUIC_MAIN_CONF_OFFSET    offsetof(ngx_quic_conf_ctx_t, main_conf)
#define NGX_QUIC_STACK_CONF_OFFSET   offsetof(ngx_quic_conf_ctx_t, stack_conf)

#define ngx_quic_conf_get_module_main_conf(cf, module)                        \
    ((ngx_quic_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_quic_conf_get_module_stack_conf(cf, module)                         \
    ((ngx_quic_conf_ctx_t *) cf->ctx)->stack_conf[module.ctx_index]

#define ngx_quic_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_quic_module.index] ?                                 \
        ((ngx_quic_conf_ctx_t *) cycle->conf_ctx[ngx_quic_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)

struct ngx_quic_listen_option_s {
    int                          family;
    in_port_t                    port;
    ngx_sockaddr_t               sockaddr;
    socklen_t                    socklen;
    ngx_str_t                    addr_text;

    in_addr_t                    addr;
#if (NGX_HAVE_INET6)
    struct in6_addr              addr6;
#endif

    ngx_array_t                  servers;
    ngx_uint_t                   initialized;

    unsigned                     bind:1;
    unsigned                     wildcard:1;
#if (NGX_HAVE_INET6)
    unsigned                     ipv6only:1;
#endif
    unsigned                     reuseport:1;
    int                          rcvbuf;
    int                          sndbuf;
    ngx_listening_t             *ls;
};


typedef struct {
    ngx_array_t                stacks;        /* ngx_quic_core_stack_conf_t */
    ngx_log_t                 *log;
    ngx_array_t               *ports;
} ngx_quic_core_main_conf_t;


typedef struct {
    ngx_str_t                       name;     /* quic stack name */

    ngx_quic_conf_ctx_t            *ctx;

    ngx_uint_t                      max_streams_per_connection;
    ngx_uint_t                      initial_idle_timeout_in_sec;
    ngx_uint_t                      default_idle_timeout_in_sec;
    ngx_uint_t                      max_idle_timeout_in_sec;
    ngx_uint_t                      max_time_before_crypto_handshake_in_sec;
    size_t                          session_buffer_size;
    ngx_uint_t                      max_age;
    ngx_str_t                       alt_svc_str;

    ngx_quic_listen_option_t       *ls_opt;

    u_char                         *file;
    ngx_uint_t                      line;

    ngx_log_t                      *error_log;

    ngx_quic_stack_t               *stack;
} ngx_quic_core_stack_conf_t;


struct ngx_quic_stack_s {
    ngx_pool_t                  *pool;
    ngx_log_t                   *log;
    tQuicStackHandler            handler;

    ngx_socket_t                 lsfd;
    struct sockaddr             *self_sockaddr;
    socklen_t                    self_socklen;

    ngx_socket_t                 fd; // dummy for all quic connections

    ngx_event_t                  alarm_ev;
    ngx_event_t                  write_ev;

    ngx_quic_core_stack_conf_t  *qscf;
};

void ngx_quic_read_handler(ngx_event_t *ev);
//void ngx_quic_write_handler(ngx_event_t *ev);

// stack apis
ngx_int_t ngx_quic_init_stack(ngx_conf_t *cf, ngx_quic_core_stack_conf_t *qscf);

void ngx_quic_update_alarm_timer(ngx_quic_stack_t *stack);

extern ngx_module_t  ngx_quic_module;

// exposed to nginx modules which use quic as network transport protocol.
ngx_quic_core_stack_conf_t*
ngx_quic_get_server_by_name(ngx_cycle_t *cycle, ngx_str_t *name);
void
ngx_quic_add_server_name(ngx_quic_core_stack_conf_t *qscf, tQuicServerCtx *server_ctx,
    ngx_str_t *cert, ngx_str_t *key, ngx_str_t *name);

#endif /* _NGX_QUIC_MODULE_H_INCLUDED_ */
