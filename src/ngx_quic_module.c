#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_string.h>
#include <ngx_quic_module.h>

static char *ngx_quic_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_quic_core_postconfiguration(ngx_conf_t *cf);
static void *ngx_quic_core_create_main_conf(ngx_conf_t *cf);
static char *ngx_quic_core_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_quic_core_create_stack_conf(ngx_conf_t *cf);
static char *ngx_quic_core_merge_stack_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_quic_merge_stacks(ngx_conf_t *cf, ngx_quic_core_main_conf_t *qmcf,
    ngx_quic_module_t *module, ngx_uint_t ctx_index);

static char *ngx_quic_core_stack(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);

static void ngx_quic_register_write_alarm(void *ctx);

static ngx_int_t ngx_quic_init_addrs(ngx_quic_core_stack_conf_t *qscf);
static ngx_int_t ngx_quic_init_listening(ngx_conf_t *cf);
static ngx_int_t ngx_quic_init_stacks(ngx_conf_t *cf);

static char *ngx_quic_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_quic_enable_ebpf_filter(ngx_socket_t s, ngx_uint_t worker_num);
static ngx_int_t ngx_quic_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_quic_process_init(ngx_cycle_t *cycle);

ngx_uint_t   ngx_quic_max_module;

static ngx_command_t  ngx_quic_commands[] = {

    { ngx_string("quic"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_quic_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_quic_module_ctx = {
    ngx_string("quic"),
    NULL,
    NULL
};


ngx_module_t  ngx_quic_module = {
    NGX_MODULE_V1,
    &ngx_quic_module_ctx,                  /* module context */
    ngx_quic_commands,                     /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t  ngx_quic_core_commands[] = {
    { ngx_string("quic_stack"),
      NGX_QUIC_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_quic_core_stack,
      0,
      0,
      NULL },
    { ngx_string("quic_listen"),
      NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_quic_listen,
      NGX_QUIC_STACK_CONF_OFFSET,
      0,
      NULL },
    { ngx_string("quic_max_streams_per_connection"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, max_streams_per_connection),
      NULL },

    { ngx_string("quic_initial_idle_timeout_in_sec"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, initial_idle_timeout_in_sec),
      NULL },

    { ngx_string("quic_default_idle_timeout_in_sec"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, default_idle_timeout_in_sec),
      NULL },

    { ngx_string("quic_max_idle_timeout_in_sec"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, max_idle_timeout_in_sec),
      NULL },

    { ngx_string("quic_max_time_before_crypto_handshake_in_sec"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, max_time_before_crypto_handshake_in_sec),
      NULL },

    { ngx_string("quic_session_buffer_size"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, session_buffer_size),
      NULL },

    { ngx_string("quic_max_age"),
      NGX_QUIC_MAIN_CONF|NGX_QUIC_STACK_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_QUIC_STACK_CONF_OFFSET,
      offsetof(ngx_quic_core_stack_conf_t, max_age),
      NULL },

      ngx_null_command
};


static ngx_quic_module_t  ngx_quic_core_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_quic_core_postconfiguration,       /* postconfiguration */

    ngx_quic_core_create_main_conf,        /* create main configuration */
    ngx_quic_core_init_main_conf,          /* init main configuration */

    ngx_quic_core_create_stack_conf,       /* create stack configuration */
    ngx_quic_core_merge_stack_conf,        /* merge stack configuration */
};


ngx_module_t  ngx_quic_core_module = {
    NGX_MODULE_V1,
    &ngx_quic_core_module_ctx,            /* module context */
    ngx_quic_core_commands,               /* module directives */
    NGX_QUIC_MODULE,                      /* module type */
    NULL,                                 /* init master */
    ngx_quic_module_init,                 /* init module */
    ngx_quic_process_init,                /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_quic_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_quic_conf_ctx_t         *ctx;
    ngx_uint_t                   mi, m;
    ngx_conf_t                   pcf;
    ngx_quic_module_t           *module;
    ngx_quic_core_main_conf_t   *qmcf;

    if (*(ngx_quic_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main quic context */
    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_quic_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_quic_conf_ctx_t **) conf = ctx;

    /* count the number of the quic modules and set up their indices */
    ngx_quic_max_module = ngx_count_modules(cf->cycle, NGX_QUIC_MODULE);


    /* the quic main_conf context, it is the same in the all quic contexts */
    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_quic_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the quic null stack_conf context, it is used to merge
     * the quic_stack{}s' stack_conf's
     */
    ctx->stack_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_quic_max_module);
    if (ctx->stack_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /* create the main_conf's, the null stack_conf's of the all quic modules */
    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_QUIC_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_stack_conf) {
            ctx->stack_conf[mi] = module->create_stack_conf(cf);
            if (ctx->stack_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_QUIC_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* parse inside the quic{} block */
    cf->module_type = NGX_QUIC_MODULE;
    cf->cmd_type = NGX_QUIC_MAIN_CONF;

    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        goto failed;
    }

    /* init quic{} main_conf's, merge the quic_stack{}s' stack_conf's */
    qmcf = ctx->main_conf[ngx_quic_core_module.ctx_index];

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_QUIC_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init quic{} main_conf's */

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }

        rv = ngx_quic_merge_stacks(cf, qmcf, module, mi);
        if (rv != NGX_CONF_OK) {
            goto failed;
        }
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_QUIC_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
        }
    }

failed:

    *cf = pcf;

    return rv;
}


static void *
ngx_quic_core_create_main_conf(ngx_conf_t *cf)
{
    ngx_quic_core_main_conf_t  *qmcf;

    qmcf = ngx_pcalloc(cf->pool, sizeof(ngx_quic_core_main_conf_t));
    if (qmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&qmcf->stacks, cf->pool, 4,
                       sizeof(ngx_quic_core_stack_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    qmcf->log = cf->log;

    return qmcf;
}


static char *
ngx_quic_core_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


static void *
ngx_quic_core_create_stack_conf(ngx_conf_t *cf)
{
    ngx_quic_core_stack_conf_t  *qscf;

    qscf = ngx_pcalloc(cf->pool, sizeof(ngx_quic_core_stack_conf_t));
    if (qscf == NULL) {
        return NULL;
    }

    qscf->max_streams_per_connection  = NGX_CONF_UNSET_UINT;
    qscf->initial_idle_timeout_in_sec  = NGX_CONF_UNSET_UINT;
    qscf->default_idle_timeout_in_sec  = NGX_CONF_UNSET_UINT;
    qscf->max_idle_timeout_in_sec  = NGX_CONF_UNSET_UINT;
    qscf->max_time_before_crypto_handshake_in_sec  = NGX_CONF_UNSET_UINT;
    qscf->session_buffer_size  = NGX_CONF_UNSET_SIZE;
    qscf->max_age = NGX_CONF_UNSET_UINT;

    qscf->file = cf->conf_file->file.name.data;
    qscf->line = cf->conf_file->line;

    return qscf;
}


static char *
ngx_quic_core_merge_stack_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_quic_core_stack_conf_t *prev = parent;
    ngx_quic_core_stack_conf_t *conf = child;

    /* TODO: it does not merge, it inits only */
    ngx_conf_merge_size_value(conf->max_streams_per_connection,
                              prev->max_streams_per_connection, 100);
    ngx_conf_merge_size_value(conf->initial_idle_timeout_in_sec,
                              prev->initial_idle_timeout_in_sec, 10);
    ngx_conf_merge_size_value(conf->default_idle_timeout_in_sec,
                              prev->default_idle_timeout_in_sec, 60);
    ngx_conf_merge_size_value(conf->max_idle_timeout_in_sec,
                              prev->max_idle_timeout_in_sec, 60 * 10);
    ngx_conf_merge_size_value(conf->max_time_before_crypto_handshake_in_sec,
                              prev->max_time_before_crypto_handshake_in_sec, 15);
    ngx_conf_merge_size_value(conf->session_buffer_size,
                              prev->session_buffer_size, 1024 * 1024);
    ngx_conf_merge_size_value(conf->max_age,
                              prev->max_age, 2592000);

    return NGX_CONF_OK;
}


static char *
ngx_quic_merge_stacks(ngx_conf_t *cf, ngx_quic_core_main_conf_t *qmcf,
    ngx_quic_module_t *module, ngx_uint_t ctx_index)
{
    char                        *rv;
    ngx_uint_t                   s;
    ngx_quic_conf_ctx_t         *ctx, saved;
    ngx_quic_core_stack_conf_t **qscfp;

    qscfp = qmcf->stacks.elts;
    ctx = (ngx_quic_conf_ctx_t *) cf->ctx;
    saved = *ctx;
    rv = NGX_CONF_OK;

    for (s = 0; s < qmcf->stacks.nelts; s++) {

        if (module->merge_stack_conf) {
            /* merge the quic_stack{}s' stack_conf's */
            ctx->stack_conf = qscfp[s]->ctx->stack_conf;

            rv = module->merge_stack_conf(cf, saved.stack_conf[ctx_index],
                                        qscfp[s]->ctx->stack_conf[ctx_index]);
            if (rv != NGX_CONF_OK) {
                goto failed;
            }
        }
    }

failed:

    *ctx = saved;

    return rv;
}


static char *
ngx_quic_core_stack(ngx_conf_t *cf, ngx_command_t *cmd,
    void *dummy)
{
    char                        *rv;
    void                        *mconf;
    ngx_str_t                   *value;
    ngx_uint_t                   i;
    ngx_conf_t                   pcf;
    ngx_quic_module_t           *module;
    ngx_quic_conf_ctx_t         *ctx, *quic_ctx;
    ngx_quic_core_stack_conf_t  *qscf, **qscfp;
    ngx_quic_core_main_conf_t   *qmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_quic_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    quic_ctx = cf->ctx;
    ctx->main_conf = quic_ctx->main_conf;

    /* the quic_stack{}'s stack_conf */
    ctx->stack_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_quic_max_module);
    if (ctx->stack_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != NGX_QUIC_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_stack_conf) {
            mconf = module->create_stack_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->stack_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */
    qscf = ctx->stack_conf[ngx_quic_core_module.ctx_index];
    qscf->ctx = ctx;

    value = cf->args->elts;
    qscf->name = value[1];

    qmcf = ctx->main_conf[ngx_quic_core_module.ctx_index];

    qscfp = ngx_array_push(&qmcf->stacks);
    if (qscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *qscfp = qscf;

    /* parse inside quic_stack{} */
    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_QUIC_STACK_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static ngx_int_t
ngx_quic_core_postconfiguration(ngx_conf_t *cf)
{
    ngx_int_t                    rc;
    ngx_uint_t                   i;
    ngx_quic_core_main_conf_t   *qmcf;
    ngx_quic_core_stack_conf_t **qscfp;

    qmcf = ngx_quic_conf_get_module_main_conf(cf, ngx_quic_core_module);
    if (qmcf == NULL) {
        return NGX_ERROR;
    }

    qscfp = qmcf->stacks.elts;

    for (i = 0; i < qmcf->stacks.nelts; ++i) {
        if (qscfp[i]->name.data == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "no stack name is defined for quic stack in %s:%ui",
                qscfp[i]->file, qscfp[i]->line);

            return NGX_ERROR;
        }

        if (qscfp[i]->ls_opt == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                "no \"quic_listen\" is defined for quic stack in %s:%ui",
                qscfp[i]->file, qscfp[i]->line);

            return NGX_ERROR;
        }

        if (qscfp[i]->max_streams_per_connection == NGX_CONF_UNSET_UINT) {
            qscfp[i]->max_streams_per_connection = 100;
        }

        if (qscfp[i]->initial_idle_timeout_in_sec == NGX_CONF_UNSET_UINT) {
            qscfp[i]->initial_idle_timeout_in_sec = 10;
        }

        if (qscfp[i]->default_idle_timeout_in_sec == NGX_CONF_UNSET_UINT) {
            qscfp[i]->default_idle_timeout_in_sec = 60;
        }

        if (qscfp[i]->max_idle_timeout_in_sec == NGX_CONF_UNSET_UINT) {
            qscfp[i]->max_idle_timeout_in_sec = 60 * 10;
        }

        if (qscfp[i]->max_time_before_crypto_handshake_in_sec == NGX_CONF_UNSET_UINT) {
            qscfp[i]->max_time_before_crypto_handshake_in_sec = 15;
        }

        if (qscfp[i]->session_buffer_size == NGX_CONF_UNSET_SIZE) {
            qscfp[i]->session_buffer_size = 1024 * 1024;
        }

        if (qscfp[i]->max_age == NGX_CONF_UNSET_UINT) {
            qscfp[i]->max_age = 2592000;
        }

    }

    rc = ngx_quic_init_listening(cf);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_quic_init_stacks(cf);

    return rc;
}


static ngx_int_t
ngx_quic_init_stacks(ngx_conf_t *cf)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_quic_listen_option_t   *qls;
    ngx_quic_core_main_conf_t  *qmcf;
    ngx_quic_core_stack_conf_t *qscf, **qscfp;

    qmcf = ngx_quic_conf_get_module_main_conf(cf, ngx_quic_core_module);
    if (qmcf == NULL) {
        return NGX_ERROR;
    }

    qscfp = qmcf->stacks.elts;

    for (i = 0; i < qmcf->stacks.nelts; ++i) {
        qscf = qscfp[i];
        qls  = qscf->ls_opt;
        if (!qls) {
            continue;
        }

        rc = ngx_quic_init_stack(cf, qscf);
        if (rc != NGX_OK) {
            return rc;
        }
    }
    return NGX_OK;
}


static char *ngx_quic_listen(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_quic_core_stack_conf_t *qscf = conf;

    u_char                     *p;
    size_t                      len;
    u_char                      buf[NGX_SOCKADDR_STRLEN];
    ngx_url_t                   u;
    ngx_uint_t                  i;
    ngx_quic_listen_option_t   *ls;
    ngx_str_t                  *value, size;

    if (qscf->ls_opt) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate \"quic_listen\" directive");
        return NGX_CONF_ERROR;
    }

    ls = ngx_pcalloc(cf->pool, sizeof(ngx_quic_listen_option_t));
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_quic_listen_option_t));

    ngx_memcpy(&ls->sockaddr.sockaddr, &u.sockaddr, u.socklen);
    ls->socklen = u.socklen;

    len = ngx_sock_ntop(&ls->sockaddr.sockaddr, ls->socklen,
                        buf, NGX_SOCKADDR_STRLEN, 1);

    p = ngx_pnalloc(cf->pool, len);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(p, buf, len);
    ls->addr_text.len  = len;
    ls->addr_text.data = p;

    //ls->server  = qscf;
    ls->initialized = 0;

    ls->bind      = 1;
    ls->reuseport = 1;
    ls->rcvbuf    = -1;
    ls->sndbuf    = -1;
#if (NGX_HAVE_INET6)
    ls->ipv6only  = 1;
#endif
    ls->wildcard  = u.wildcard;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->rcvbuf = ngx_parse_size(&size);

            if (ls->rcvbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->sndbuf = ngx_parse_size(&size);

            if (ls->sndbuf == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                ls->ipv6only = 1;

            } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                ls->ipv6only = 0;

            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[i].data[9]);
                return NGX_CONF_ERROR;
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return NGX_CONF_ERROR;
#endif
        }
    }
    ls->ipv6only = 0;
    qscf->ls_opt = ls;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_quic_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i, j;
    ngx_core_conf_t             *ccf;
    ngx_listening_t             *ls;
    ngx_quic_core_main_conf_t   *qmcf;
    ngx_quic_core_stack_conf_t  *qscf, **qscfp;

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (ccf == NULL) {
        return NGX_ERROR;
    }

    qmcf = ngx_quic_cycle_get_module_main_conf(cycle, ngx_quic_core_module);
    if (qmcf == NULL) {
        return NGX_OK;
    }

    qscfp = qmcf->stacks.elts;
    ls  = cycle->listening.elts;

    for (i = 0; i < qmcf->stacks.nelts; i++) {
        qscf  = qscfp[i];
        for (j = 0; j < cycle->listening.nelts; j++) {
            if (qscf != ls[j].servers || ls[j].worker != 0) {
                continue;
            }

            if (!ngx_test_config &&
                ngx_quic_enable_ebpf_filter(ls[j].fd, ccf->worker_processes) != NGX_OK) {
                // TODO add error log output.
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static void
ngx_quic_register_write_alarm(void *ctx)
{
  ngx_msec_t      timeout_ms;
  ngx_event_t    *ev;

  ev = (ngx_event_t *)ctx;
  if (ev) {
    if (ev->timer_set) {
      ngx_del_timer(ev);
    }

    timeout_ms = 10;
    ngx_add_timer(ev, timeout_ms);
  }
}


static ngx_int_t
ngx_quic_enable_ebpf_filter(
    ngx_socket_t s, ngx_uint_t worker_num)
{
#if 0
    static char bpf_log_buf[65536];
    static const char bpf_license[] = "GPL";

    /* eBPF programs for QUIC & IETF packet dispatch(REUSEPORT)
     * r0 = skb->data[0]; // first udp packet byte
     * r0 &= 0x80; // check significant bit
     * r7 = r0; // save ro result
     * if (r7 == 0) {
     *   r0 = skb->data[1...4];
     * } else {
     *   r0 = skb->data[6...10];
     * }
     * r0 %= worker_num
     */

    const struct bpf_insn prog[] = {
        { BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0 },
        // Load short CID
        { BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 1 },
        { BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_8, BPF_REG_0, 0, 0 },
        // Load large CID
        { BPF_LD | BPF_ABS | BPF_W, 0, 0, 0, 6 },
        { BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_9, BPF_REG_0, 0, 0 },
        // Load first byte
        { BPF_LD | BPF_ABS | BPF_B, 0, 0, 0, 0 },
        { BPF_ALU64 | BPF_AND | BPF_K, BPF_REG_0, 0, 0, 0x80 },
        { BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_7, BPF_REG_0, 0, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_8, 0, 0 },
        { BPF_JMP | BPF_JEQ | BPF_K, BPF_REG_7, 0, 1, 0 },
        { BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_0, BPF_REG_9, 0, 0 },
        { BPF_ALU64 | BPF_MOD | BPF_K, BPF_REG_0, 0, 0, worker_num },
        { BPF_JMP | BPF_EXIT, 0, 0, 0, 0 }
    };
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.prog_type    = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt     = (sizeof(prog) / sizeof((prog)[0]));
    attr.insns        = (unsigned long) &prog;
    attr.license      = (unsigned long) &bpf_license;
    attr.log_buf      = (unsigned long) &bpf_log_buf;
    attr.log_size     = sizeof(bpf_log_buf);
    attr.log_level    = 1;
    attr.kern_version = 0;

    int bpf_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (bpf_fd < 0) {
        return NGX_ERROR;
    }

    if (setsockopt(s, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &bpf_fd, sizeof(bpf_fd))) {
        return NGX_ERROR;
    }

    close(bpf_fd);
#endif
    return NGX_OK;
}


static ngx_int_t
ngx_quic_init_listening(ngx_conf_t *cf)
{
    ngx_int_t                   rc;
    ngx_uint_t                  i;
    ngx_listening_t            *ls;
    ngx_quic_listen_option_t   *qls;
    ngx_quic_core_main_conf_t  *qmcf;
    ngx_quic_core_stack_conf_t *qscf, **qscfp;

    qmcf = ngx_quic_conf_get_module_main_conf(cf, ngx_quic_core_module);
    if (qmcf == NULL) {
        return NGX_ERROR;
    }

    qscfp = qmcf->stacks.elts;
    for (i = 0; i < qmcf->stacks.nelts; ++i) {
        qscf = qscfp[i];
        qls  = qscf->ls_opt;
        if (qls == NULL) {
            continue;
        }

        qscf->error_log = &cf->cycle->new_log;
        if (qscf->error_log == NULL) {
            return NGX_ERROR;
        }
        if (qls->initialized) {
            continue;
        }
        ls = ngx_create_listening(cf, &qls->sockaddr.sockaddr, qls->socklen);
        if (ls == NULL) {
            return NGX_ERROR;
        }

        ls->addr_ntop   = 1;
        ls->handler     = NULL;
        ls->pool_size   = 256;
        ls->type        = SOCK_DGRAM;

        ls->logp        = qscf->error_log;
        ls->log.data    = &ls->addr_text;
        ls->log.handler = ngx_accept_log_error;

        ls->backlog     = 0;
        ls->rcvbuf      = qls->rcvbuf;
        ls->sndbuf      = qls->sndbuf;

        ls->wildcard     = qls->wildcard;

#if (NGX_HAVE_INET6)
        ls->ipv6only     = qls->ipv6only;
#endif
        ls->reuseport    = qls->reuseport;

        ls->servers      = qscf;

        rc = ngx_quic_init_addrs(qscf);
        if (rc != NGX_OK) {
            return rc;
        }

#if (nginx_version < 1015002)

        rc = ngx_clone_listening(cf, ls);
       if (rc != NGX_OK) {
            return rc;
       }
#endif

       qls->initialized = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_init_addrs(ngx_quic_core_stack_conf_t *qscf)
{
    struct sockaddr           *sa;
    ngx_quic_listen_option_t  *qls;

    qls = qscf->ls_opt;

    sa = &qls->sockaddr.sockaddr;
    qls->family = sa->sa_family;
    qls->port = ngx_inet_get_port(sa);


#if (NGX_HAVE_INET6)
    if (qls->family == AF_INET6) {
        struct sockaddr_in6  *sin6;
        sin6 = (struct sockaddr_in6 *) &qls->sockaddr.sockaddr_in6;
        qls->addr6 = sin6->sin6_addr;
        return NGX_OK;
    }
#endif

    struct sockaddr_in  *sin;
    sin = (struct sockaddr_in *) &qls->sockaddr.sockaddr;
    qls->addr = sin->sin_addr.s_addr;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t                   i, j;
    ngx_connection_t            *c;
    ngx_listening_t             *ls;
    ngx_quic_core_main_conf_t   *qmcf;
    ngx_quic_core_stack_conf_t  *qscf, **qscfp;
    ngx_quic_stack_t            *stack;
    tQuicOnCanWriteCallback      write_blocked_cb;

    qmcf = ngx_quic_cycle_get_module_main_conf(cycle, ngx_quic_core_module);
    if (qmcf == NULL) {
        return NGX_OK;
    }

    qscfp = qmcf->stacks.elts;
    ls  = cycle->listening.elts;

    for (i = 0; i < qmcf->stacks.nelts; i++) {
        qscf  = qscfp[i];
        stack = qscf->stack;
        for (j = 0; j < cycle->listening.nelts; j++) {
            if (qscf->ls_opt == NULL || ls[j].worker != ngx_worker) {
                continue;
            }
				
	    if (qscf == ls[j].servers) {
                stack->lsfd = ls[j].fd;
                stack->self_sockaddr = ls[j].sockaddr;
                stack->self_socklen = ls[j].socklen;
                write_blocked_cb.OnCanWriteCallback = ngx_quic_register_write_alarm;
                write_blocked_cb.OnCanWriteContext = &stack->write_ev;
                quic_stack_init_writer(stack->handler, ls[j].fd, write_blocked_cb);
                ngx_quic_update_alarm_timer(stack);
                c = ls[j].connection;
                c->data = (void*)stack;
                c->read->log = stack->log;
                c->read->handler = ngx_quic_read_handler;
            }
        }
    }

    return NGX_OK;
}


ngx_quic_core_stack_conf_t*
ngx_quic_get_server_by_name(ngx_cycle_t *cycle, ngx_str_t *name)
{
    ngx_uint_t                   i;
    ngx_quic_core_main_conf_t   *qmcf;
    ngx_quic_core_stack_conf_t  *qscf, **qscfp;

    qmcf = ngx_quic_cycle_get_module_main_conf(cycle, ngx_quic_core_module);
    if (qmcf == NULL) {
        return NULL;
    }

    qscfp = qmcf->stacks.elts;

    for (i = 0; i < qmcf->stacks.nelts; i++) {
        qscf = qscfp[i];
        if (ngx_strcmp(qscf->name.data, name->data) == 0) {
            return qscf;
        }
    }
    return NULL;
}


void ngx_quic_add_server_name(ngx_quic_core_stack_conf_t *qscf, tQuicServerCtx *server_ctx,
    ngx_str_t *cert, ngx_str_t *key, ngx_str_t *name)
{
    tQuicStackCertificate     cert_conf;
    ngx_quic_stack_t         *stack;

    if (qscf == NULL || cert == NULL || key == NULL || name == NULL)
        return;

    stack = qscf->stack;

    cert_conf.certificate           = (char*)cert->data;
    cert_conf.certificate_len       = cert->len;
    cert_conf.certificate_key       = (char*)key->data;
    cert_conf.certificate_key_len   = key->len;
    cert_conf.hostname              = (char*)name->data;
    cert_conf.hostname_len          = name->len;
    cert_conf.server_ctx            = server_ctx;
    quic_stack_add_certificate(stack->handler, &cert_conf);
}
