#include <ngx_times.h>
#include <ngx_quic_module.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>

static void
ngx_quic_alarm_event_handler(ngx_event_t *ev);
static void
ngx_quic_write_alarm_event_handler(ngx_event_t *ev);


static int64_t ngx_approximate_time_now_us()
{
    ngx_time_t *time_now;
    time_now = ngx_timeofday();
    return (time_now->sec * 1E6 + time_now->msec * 1E3);
}

static int64_t ngx_time_now_us()
{
    struct timeval   tv;
    ngx_gettimeofday(&tv);

    return (tv.tv_sec * 1E6 + tv.tv_usec);
}

static void
ngx_quic_alarm_event_handler(ngx_event_t *ev)
{
    ngx_quic_stack_t *stack = ev->data;

    if (stack) {
        quic_stack_on_alarm_timeout(stack->handler, ngx_approximate_time_now_us()/1000);
        ngx_quic_update_alarm_timer(stack);
    }
}

void
ngx_quic_update_alarm_timer(ngx_quic_stack_t *stack)
{
    ngx_event_t   *ev;
    ngx_msec_t     deadline_ms, timeout_ms, approximate_time;

    if (stack == NULL) {
        return;
    }

    ev = &stack->alarm_ev;

    deadline_ms = (ngx_msec_t)quic_stack_next_alarm_time(stack->handler);
    if (deadline_ms <= 0) {
        return;
    }

    if (ev->timer_set) {
      ngx_del_timer(ev);
    }

    timeout_ms = 1; // prevent from reregister immediately, which causes infinitely event handler loop.
    approximate_time = ngx_approximate_time_now_us()/1000;
    if (deadline_ms > approximate_time) {
       timeout_ms = deadline_ms - approximate_time;
    }

    ngx_add_timer(ev, timeout_ms);
}

static void
ngx_quic_write_alarm_event_handler(ngx_event_t *ev)
{
    ngx_quic_stack_t *stack = ev->data;

    if (stack) {
        quic_stack_on_can_write(stack->handler);

        if (quic_stack_has_pending_writes(stack->handler)) {
            ngx_post_event(ev, &ngx_posted_events);
        }

        ngx_quic_update_alarm_timer(stack);
    }
}


static int ngx_quic_on_request_header(
    const tQuicRequestID* id,
    const char *data,
    size_t len,
    void **ctx,
    tQuicServerCtx *server_ctx)
{
    ngx_int_t                       rc;
    void                           *conf;

    if (server_ctx == NULL) {
        return QUIC_STACK_SERVER;
    }

    if (server_ctx->module_idx != ngx_http_core_module.index 
        || server_ctx->on_request_header_impl == NULL) {
        return QUIC_STACK_SERVER;
    }

    conf = server_ctx->server_conf;
    rc = (server_ctx->on_request_header_impl)(id, data, len, ctx, conf);
    return rc;
}

static int
ngx_quic_on_request_body(
    const tQuicRequestID *id,
    void *ctx,
    tQuicServerCtx *server_ctx)
{
    ngx_int_t                       rc;
    void                           *conf;

    if (server_ctx == NULL) {
        return QUIC_STACK_SERVER;
    }

    if (server_ctx->module_idx != ngx_http_core_module.index 
        || server_ctx->on_request_body_impl == NULL) {
        return QUIC_STACK_SERVER;
    }

    conf = server_ctx->server_conf;
    rc = (server_ctx->on_request_body_impl)(id, ctx, conf);
    return rc;
}

static int ngx_quic_on_request_close(
    const tQuicRequestID *id,
    void *ctx,
    tQuicServerCtx *server_ctx)
{
    return QUIC_STACK_OK;
}


ngx_int_t ngx_quic_init_stack(ngx_conf_t *cf,
    ngx_quic_core_stack_conf_t *qscf)
{
    ngx_pool_t               *pool;
    tQuicStackConfig          stack_conf;
    ngx_quic_stack_t         *stack;
    const int                 kMaxLen = 128;
    u_char                   *p;
    int                       rc;

    pool = ngx_create_pool(4096, qscf->error_log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    // setup stack config to create stack handler
    ngx_memzero(&stack_conf, sizeof(tQuicStackConfig));

    stack = ngx_pcalloc(pool, sizeof(ngx_quic_stack_t));
    if (stack == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    stack->fd = ngx_socket(AF_INET, SOCK_STREAM, 0); // dummy socket
    if (stack->fd == (ngx_socket_t) -1) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    stack_conf.stack_ctx = stack;

    // setup base components
    stack->pool = pool;
    stack->log  = qscf->error_log;
    // setup alarm event
    stack->alarm_ev.log = stack->log;
    stack->alarm_ev.data = stack;
    stack->alarm_ev.cancelable = 1;
    stack->alarm_ev.handler = ngx_quic_alarm_event_handler;

    stack->write_ev.log = stack->log;
    stack->write_ev.data = stack;
    stack->write_ev.cancelable = 1;
    stack->write_ev.handler = ngx_quic_write_alarm_event_handler;

    stack_conf.max_streams_per_connection = qscf->max_streams_per_connection;
    stack_conf.initial_idle_timeout_in_sec = qscf->initial_idle_timeout_in_sec;
    stack_conf.default_idle_timeout_in_sec = qscf->default_idle_timeout_in_sec;
    stack_conf.max_idle_timeout_in_sec = qscf->max_idle_timeout_in_sec;
    stack_conf.max_time_before_crypto_handshake_in_sec = qscf->max_time_before_crypto_handshake_in_sec;

    // initialize quic stack callbacks
    stack_conf.req_cb.OnRequestHeader = ngx_quic_on_request_header;
    stack_conf.req_cb.OnRequestBody   = ngx_quic_on_request_body;
    stack_conf.req_cb.OnRequestClose  = ngx_quic_on_request_close;

    // initialize time related functions
    stack_conf.clock_gen.ApproximateTimeNowInUsec = ngx_approximate_time_now_us;
    stack_conf.clock_gen.TimeNowInUsec = ngx_time_now_us;

    stack->handler = quic_stack_create(&stack_conf);
    if (stack->handler == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    p = ngx_pcalloc(pool, sizeof(u_char) * kMaxLen);
    if (p == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    qscf->alt_svc_str.data = p;
    p = ngx_sprintf(p, "quic=\":%d\"; ma=%d; v=\"", qscf->ls_opt->port, qscf->max_age);
    rc = quic_stack_supported_versions(stack->handler, (char*)p, kMaxLen - 1);
    if (rc <= QUIC_STACK_OK) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }
    p += rc;
    *(p++) = '\"';
    qscf->alt_svc_str.len = p - qscf->alt_svc_str.data;

    stack->qscf  = qscf;
    qscf->stack = stack;

    ngx_quic_update_alarm_timer(stack);

    return NGX_OK;
}

