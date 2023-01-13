#ifndef _NGX_HTTP_QUIC_DEPS_H_INCLUDED_
#define _NGX_HTTP_QUIC_DEPS_H_INCLUDED_

#if (NGX_WIN32)
#error "nginx-http-quic-module not support windows platform"
#endif

#if !(NGX_HAVE_REUSEPORT)
#error "nginx-http-quic-module should have NGX_HAVE_REUSEPORT"
#endif

#endif /* _NGX_HTTP_QUIC_DEPS_H_INCLUDED_ */