# nginx-quic-module

QUIC is a new transport protocol which reduces latency compared to that of TCP. On the surface, QUIC is very similar to TCP+TLS+HTTP/2 implemented on UDP. Currently, most servers are borned to build on the top of TCP, rarely support QUIC/UDP.

This repository is a NGINX-based module implemented by BVC (Bilibili Video Cloud team), which enables NGINX application modules such as HTTP module run service over QUIC as network protocol. Its sources are under NGINX module development framework, so it's not able to work by itself but needing NGINX sources and a QUIC protocol stack. QUIC protocol stack locates in another repository which called `ngx_quic_stack`, it will generate libngxquicstack.so library for ` nginx-quic-module `. `nginx-quic-module` follows NGINX formatted configuration. It is easy to configure and be used in other NGINX modules, simply by adding `enbale_quic` directive.

Key features of `nginx-quic-module` include
  * All QUIC protocol features, e.g. 0RTT connection establishment, improved congestion control
  * Easy way to configure QUIC server
  * High performance

## Build
Before you build this module, suppose you have already built `ngx_quic_stack`, and installed libngxquicstack.so to your system library path.
```bash
To use this in dynamic way, cd to NGINX source directory & run:
./configure --add-dynamic-module=/path/to/nginx-quic-module
make
make install
```
Or to statically compile this with nginx binary, run this instead:
./configure –-add-module=/path/to/nginx-quic-module
Remember to adjust quic modules order in ngx_modules.c to place them after event modules before compiling.

## Platform limitations
To use some systems’ features & APIs, there are some limitations of the platforms
* Only Linux & kernel version 4.8+ supported
* Only tested on tengine-2.3.2+

## Example nginx.conf
```bash
# if dynamic module
load_module "modules/ngx_quic_module.so";

quic {
    quic_stack stack1 {
        quic_listen 443;
        quic_max_streams_per_connection 88;
        quic_initial_idle_timeout_in_sec 10;
        quic_default_idle_timeout_in_sec 60;
        quic_max_idle_timeout_in_sec 600;
        quic_max_time_before_crypto_handshake_in_sec 20;
        quic_session_buffer_size 1M;
        quic_max_age 600;
    }
}

http {
    server {
        listen       80;
        server_name  test.domain.com;

        root /root;

        location / {
            index  index.html index.htm;
            try_files $uri $uri/ =404;
        }
    }

    server {
        listen 443 ssl;
        ssl_certificate /path/to/server.crt;
        ssl_certificate_key /path/to/server.key;
        server_name test.domain.com;

        # QUIC config ---
        enable_quic stack1;
        # ---

        root /root;
        # cache location for TCP&QUIC
        location /cache {
            index  index.html index.htm;
            try_files $uri $uri/ =404;
        }

        # proxy_pass location for TCP&QUIC upstream to tcp:80
        location /proxy { 
            proxy_pass http://127.0.0.1;
        }
    }
}
```
