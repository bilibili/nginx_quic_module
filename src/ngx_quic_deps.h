#ifndef _NGX_QUIC_MODULE_DEPS_H_INCLUDED_
#define _NGX_QUIC_MODULE_DEPS_H_INCLUDED_

#if (NGX_WIN32)
#error "nginx-quic-module not support windows platform"
#endif

#if !(NGX_HAVE_REUSEPORT)
#error "nginx-quic-module should have NGX_HAVE_REUSEPORT"
#endif

#endif /* _NGX_QUIC_MODULE_DEPS_H_INCLUDED_ */