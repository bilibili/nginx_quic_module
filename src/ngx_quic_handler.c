#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_quic_module.h>

static int
ngx_quic_recvmsg(
    ngx_quic_stack_t        *s,
    char                    *buf,
    size_t                   buflen,
    struct sockaddr         **peer_sockaddr,
    socklen_t               *peer_socklen,
    struct sockaddr         **local_sockaddr,
    socklen_t               *local_socklen)
{
    int                n;
    ngx_err_t          err;
    struct iovec       iov[1];
    struct msghdr      msg;
    ngx_sockaddr_t     sa;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

#if (NGX_HAVE_IP_RECVDSTADDR)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_addr))];
#elif (NGX_HAVE_IP_PKTINFO)
    u_char             msg_control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    u_char             msg_control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif

#endif

    ngx_memzero(&msg, sizeof(struct msghdr));

    iov[0].iov_base = (void *) buf;
    iov[0].iov_len = buflen;

    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(ngx_sockaddr_t);
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)

#if (NGX_HAVE_IP_RECVDSTADDR || NGX_HAVE_IP_PKTINFO)
    if (s->self_sockaddr->sa_family == AF_INET) {
	msg.msg_control = &msg_control;
	msg.msg_controllen = sizeof(msg_control);
    }
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    if (s->self_sockaddr->sa_family == AF_INET6) {
	msg.msg_control = &msg_control6;
	msg.msg_controllen = sizeof(msg_control6);
    }
#endif

#endif

    n = recvmsg(s->lsfd, &msg, 0);
    if (n == -1) {
        err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            ngx_log_debug0(NGX_LOG_DEBUG, s->log, err,
                            "recvmsg() not ready");
            return -1;
        }
        ngx_log_error(NGX_LOG_ALERT, s->log, err, "recvmsg() failed");
        return -1;
    }

#if (NGX_HAVE_MSGHDR_MSG_CONTROL)
    if (msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) {
	    ngx_log_error(NGX_LOG_ALERT, s->log, 0,
			    "recvmsg() truncated data");
	    return -1;
    }
#endif

    *peer_sockaddr = msg.msg_name;
    *peer_socklen = msg.msg_namelen;

    *local_sockaddr = s->self_sockaddr;
    *local_socklen = s->self_socklen;
    
#if (NGX_HAVE_MSGHDR_MSG_CONTROL) 
    struct cmsghdr	*cmsg;

    //ngx_memcpy(&lsa, *local_sockaddr, *local_socklen);
    //*local_sockaddr = &lsa.sockaddr;

    for (cmsg = CMSG_FIRSTHDR(&msg);
		    cmsg != NULL;
		    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#if (NGX_HAVE_IP_RECVDSTADDR)
	if (cmsg->cmsg_level == IPPROTO_IP
			&& cmsg->cmsg_type == IP_RECVDSTADDR
			&& s->self_sockaddr->sa_family == AF_INET) {
	    struct in_addr      *addr;
	    struct sockaddr_in  *sin;

	    addr = (struct in_addr *) CMSG_DATA(cmsg);
	    sin = (struct sockaddr_in *) (*local_sockaddr);
	    sin->sin_addr = *addr;
	    break;
	}
#elif (NGX_HAVE_IP_PKTINFO)
	if (cmsg->cmsg_level == IPPROTO_IP
			&& cmsg->cmsg_type == IP_PKTINFO
			&& s->self_sockaddr->sa_family == AF_INET) {
	    struct in_pktinfo	*pkt;
	    struct sockaddr_in	*sin;
	
            pkt = (struct in_pktinfo *) CMSG_DATA(cmsg);
	    sin = (struct sockaddr_in *) (*local_sockaddr);
	    sin->sin_addr = pkt->ipi_addr;
	    break;
	}
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
	if (cmsg->cmsg_level == IPPROTO_IPV6
			&& cmsg->cmsg_type == IPV6_PKTINFO
			&& s->self_sockaddr->sa_family == AF_INET6) {
	    struct in6_pktinfo   *pkt6;
	    struct sockaddr_in6  *sin6;

	    pkt6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
	    sin6 = (struct sockaddr_in6 *) (*local_sockaddr);
	    sin6->sin6_addr = pkt6->ipi6_addr;
	    break;
	}
#endif
    }
#endif
    return n;
}

static ngx_int_t
ngx_quic_read_and_process(ngx_quic_stack_t *s)
{
    int                 n;
    char                buf[kMaxV4UdpPacketSize];
    struct sockaddr     *peer_sockaddr;
    socklen_t           peer_socklen;
    struct sockaddr     *local_sockaddr;
    socklen_t           local_socklen;

    n = ngx_quic_recvmsg(s, buf, sizeof(buf), &peer_sockaddr, &peer_socklen, &local_sockaddr, &local_socklen);
    if (n < 0) {
        return 0;
    }
    
    // process packet in quic stack
    quic_stack_process_packet(
        s->handler,
        local_sockaddr, local_socklen,
        peer_sockaddr, peer_socklen,
        buf, n);

    return 1;
}


void ngx_quic_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_quic_stack_t      *s;

    c = ev->data;
    s = c->data;

    // TODO config 16: max_connection to create.
    quic_stack_process_chlos(s->handler, 16);

    int more_to_read = 1;
    while (more_to_read) {
        more_to_read = ngx_quic_read_and_process(s);
    }

    if (quic_stack_has_chlos_buffered(s->handler)) {
        ngx_post_event(ev, &ngx_posted_events);
    }

    ngx_quic_update_alarm_timer(s);
}


#if 0
void ngx_quic_write_handler(ngx_event_t *ev)
{
    ngx_connection_t            *c;
    ngx_quic_stack_t            *stack;

    c = ev->data;
    stack = c->data;

    if (ev->ready) {
        quic_stack_on_can_write(stack->handler);

        if (quic_stack_has_pending_writes(stack->handler)) {
            ngx_post_event(ev, &ngx_posted_events);
        }

        ngx_quic_update_alarm_timer(stack);
    }
}
#endif
