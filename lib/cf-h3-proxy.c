/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && \
    defined(USE_NGHTTP3) && !defined(CURL_DISABLE_PROXY) && \
    (defined(USE_OPENSSL_QUIC) || defined(USE_NGTCP2))

#ifdef USE_OPENSSL_QUIC
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#endif /* USE_OPENSSL_QUIC */

#ifdef USE_NGTCP2
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#ifdef USE_OPENSSL
#include <openssl/err.h>
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#elif defined(OPENSSL_QUIC_API2)
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif
#include "vtls/openssl.h"
#endif /* USE_OPENSSL */
#endif /* USE_NGTCP2 */

#include <nghttp3/nghttp3.h>

#include "urldata.h"
#include "hash.h"
#include "sendf.h"
#include "multiif.h"
#include "cfilters.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "strerror.h"
#include "curlx/dynbuf.h"
#include "dynhds.h"
#include "http_proxy.h"
#include "select.h"
#include "uint-hash.h"
#include "vquic/vquic.h"
#include "vquic/vquic_int.h"
#include "vquic/vquic-tls.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "curl_trc.h"
#include "cf-h3-proxy.h"
#include "url.h"
#include "curlx/strerr.h"
#include "capsule.h"
#include "rand.h"

/* The last 2 #include files should be in this order */
#include "curl_memory.h"
#include "memdebug.h"

/* A stream window is the maximum amount we need to buffer for
 * each active transfer. We use HTTP/3 flow control and only ACK
 * when we take things out of the buffer.
 * Chunk size is large enough to take a full DATA frame */
#define PROXY_H3_STREAM_WINDOW_SIZE (128 * 1024)
#define PROXY_H3_STREAM_CHUNK_SIZE (16 * 1024)

/* The pool keeps spares around and half of a full stream window
 * seems good. More does not seem to improve performance.
 * The benefit of the pool is that stream buffer to not keep
 * spares. Memory consumption goes down when streams run empty,
 * have a large upload done, etc. */
#define PROXY_H3_STREAM_POOL_SPARES \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE) / 2

#define PROXY_H3_STREAM_RECV_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)
#define PROXY_H3_STREAM_SEND_CHUNKS 1

#define H3_TUNNEL_RECV_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)
#define H3_TUNNEL_SEND_CHUNKS \
  (PROXY_H3_STREAM_WINDOW_SIZE / PROXY_H3_STREAM_CHUNK_SIZE)

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

#ifdef USE_NGTCP2
#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_HANDSHAKE_TIMEOUT (10*NGTCP2_SECONDS)
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
typedef uint32_t sslerr_t;
#else
typedef unsigned long sslerr_t;
#endif

static const char *osslq_SSL_ERROR_to_str(int err)
{
  switch(err) {
  case SSL_ERROR_NONE:
    return "SSL_ERROR_NONE";
  case SSL_ERROR_SSL:
    return "SSL_ERROR_SSL";
  case SSL_ERROR_WANT_READ:
    return "SSL_ERROR_WANT_READ";
  case SSL_ERROR_WANT_WRITE:
    return "SSL_ERROR_WANT_WRITE";
  case SSL_ERROR_WANT_X509_LOOKUP:
    return "SSL_ERROR_WANT_X509_LOOKUP";
  case SSL_ERROR_SYSCALL:
    return "SSL_ERROR_SYSCALL";
  case SSL_ERROR_ZERO_RETURN:
    return "SSL_ERROR_ZERO_RETURN";
  case SSL_ERROR_WANT_CONNECT:
    return "SSL_ERROR_WANT_CONNECT";
  case SSL_ERROR_WANT_ACCEPT:
    return "SSL_ERROR_WANT_ACCEPT";
#ifdef SSL_ERROR_WANT_ASYNC
  case SSL_ERROR_WANT_ASYNC:
    return "SSL_ERROR_WANT_ASYNC";
#endif
#ifdef SSL_ERROR_WANT_ASYNC_JOB
  case SSL_ERROR_WANT_ASYNC_JOB:
    return "SSL_ERROR_WANT_ASYNC_JOB";
#endif
#ifdef SSL_ERROR_WANT_EARLY
  case SSL_ERROR_WANT_EARLY:
    return "SSL_ERROR_WANT_EARLY";
#endif
  default:
    return "SSL_ERROR unknown";
  }
}

/* Return error string for last OpenSSL error */
static char *osslq_strerror(unsigned long error, char *buf, size_t size)
{
  DEBUGASSERT(size);
  *buf = '\0';

#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
  ERR_error_string_n((uint32_t)error, buf, size);
#else
  ERR_error_string_n(error, buf, size);
#endif

  if(!*buf) {
    const char *msg = error ? "Unknown error" : "No error";
    if(strlen(msg) < size)
      strcpy(buf, msg);
  }
  return buf;
}

static CURLcode make_bio_addr(BIO_ADDR **pbio_addr,
                              const struct Curl_sockaddr_ex *addr)
{
  BIO_ADDR *ba;
  CURLcode result = CURLE_FAILED_INIT;

  ba = BIO_ADDR_new();
  if(!ba) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  switch(addr->family) {
  case AF_INET:
  {
    const struct sockaddr_in *const sin =
        (const struct sockaddr_in *)&addr->curl_sa_addr;
    if(!BIO_ADDR_rawmake(ba, AF_INET, &sin->sin_addr,
                          sizeof(sin->sin_addr), sin->sin_port)) {
      goto out;
    }
    result = CURLE_OK;
    break;
  }
#ifdef USE_IPV6
  case AF_INET6:
  {
    const struct sockaddr_in6 *const sin =
        (const struct sockaddr_in6 *)&addr->curl_sa_addr;
    if(!BIO_ADDR_rawmake(ba, AF_INET6, &sin->sin6_addr,
                          sizeof(sin->sin6_addr), sin->sin6_port)) {
      goto out;
    }
    result = CURLE_OK;
    break;
  }
#endif /* USE_IPV6 */
  default:
    /* sunsupported */
    DEBUGASSERT(0);
    break;
  }

out:
  if(result && ba) {
    BIO_ADDR_free(ba);
    ba = NULL;
  }
  *pbio_addr = ba;
  return result;
}
#endif /* USE_OPENSSL_QUIC */

typedef enum
{
  H3_TUNNEL_INIT,     /* init/default/no tunnel state */
  H3_TUNNEL_CONNECT,  /* CONNECT request is being sent */
  H3_TUNNEL_RESPONSE, /* CONNECT response received completely */
  H3_TUNNEL_ESTABLISHED,
  H3_TUNNEL_FAILED
} h3_tunnel_state;

struct tunnel_stream
{
  struct http_resp *resp;
  char *authority;
  curl_int64_t stream_id;
  h3_tunnel_state state;
  BIT(has_final_response);
  BIT(closed);
};

static CURLcode tunnel_stream_init(struct Curl_cfilter *cf,
                                   struct tunnel_stream *ts)
{
  const char *hostname;
  int port;
  bool ipv6_ip;
  CURLcode result;

  ts->state = H3_TUNNEL_INIT;
  ts->stream_id = -1;
  ts->has_final_response = FALSE;

  result = Curl_http_proxy_get_destination(cf, &hostname, &port, &ipv6_ip);
  if(result)
    return result;

  ts->authority = /* host:port with IPv6 support */
      curl_maprintf("%s%s%s:%d", ipv6_ip ? "[" : "", hostname,
                                    ipv6_ip ? "]" : "", port);
  if(!ts->authority)
    return CURLE_OUT_OF_MEMORY;

  return CURLE_OK;
}

static void tunnel_stream_clear(struct tunnel_stream *ts)
{
  Curl_http_resp_free(ts->resp);
  Curl_safefree(ts->authority);
  memset(ts, 0, sizeof(*ts));
  ts->state = H3_TUNNEL_INIT;
}

static void h3_tunnel_go_state(struct Curl_cfilter *cf,
                               struct tunnel_stream *ts,
                               h3_tunnel_state new_state,
                               struct Curl_easy *data)
{
  (void)cf;

  if(ts->state == new_state)
    return;
  /* leaving this one */
  switch(ts->state) {
  case H3_TUNNEL_CONNECT:
    data->req.ignorebody = FALSE;
    break;
  default:
    break;
  }
  /* entering this one */
  switch(new_state) {
  case H3_TUNNEL_INIT:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'init'",
                ts->stream_id);
    tunnel_stream_clear(ts);
    break;

  case H3_TUNNEL_CONNECT:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'connect'",
                ts->stream_id);
    ts->state = H3_TUNNEL_CONNECT;
    break;

  case H3_TUNNEL_RESPONSE:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'response'",
                ts->stream_id);
    ts->state = H3_TUNNEL_RESPONSE;
    break;

  case H3_TUNNEL_ESTABLISHED:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'established'",
                ts->stream_id);
    if(cf->conn->bits.udp_tunnel_proxy) {
      infof(data, "CONNECT-UDP phase completed for HTTP/3 proxy");
    }
    else {
      infof(data, "CONNECT phase completed for HTTP/3 proxy");
    }
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    FALLTHROUGH();
  case H3_TUNNEL_FAILED:
    if(new_state == H3_TUNNEL_FAILED)
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] new tunnel state 'failed'",
                  ts->stream_id);
    ts->state = new_state;
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it is not accidentally used for the document request
       after we have connected. So let's free and clear it here. */
    Curl_safefree(data->state.aptr.proxyuserpwd);
    break;
  }
}

#ifdef USE_OPENSSL_QUIC
/* QUIC stream (not necessarily H3) for OpenSSL */
struct cf_osslq_stream {
  curl_int64_t id;
  SSL *ssl;
  struct bufq recvbuf; /* QUIC war data recv buffer */
  BIT(recvd_eos);
  BIT(closed);
  BIT(reset);
  BIT(send_blocked);
  BIT(tunnel_stream);
};

static CURLcode cf_osslq_stream_open(struct cf_osslq_stream *s,
                                     SSL *conn,
                                     uint64_t flags,
                                     struct bufc_pool *bufcp,
                                     void *user_data)
{
  DEBUGASSERT(!s->ssl);
  Curl_bufq_initp(&s->recvbuf, bufcp, 1, BUFQ_OPT_NONE);
  s->ssl = SSL_new_stream(conn, flags);
  if(!s->ssl) {
    return CURLE_FAILED_INIT;
  }
  s->id = (curl_int64_t)SSL_get_stream_id(s->ssl);
  SSL_set_app_data(s->ssl, user_data);
  return CURLE_OK;
}

static void cf_osslq_stream_cleanup(struct cf_osslq_stream *s)
{
  if(s->ssl) {
    SSL_set_app_data(s->ssl, NULL);
    SSL_free(s->ssl);
  }
  Curl_bufq_free(&s->recvbuf);
  memset(s, 0, sizeof(*s));
}

static void cf_osslq_stream_close(struct cf_osslq_stream *s)
{
  if(s->ssl) {
    SSL_free(s->ssl);
    s->ssl = NULL;
  }
}

struct cf_osslq_h3conn {
  nghttp3_conn *conn;
  nghttp3_settings settings;
  struct cf_osslq_stream s_ctrl;
  struct cf_osslq_stream s_qpack_enc;
  struct cf_osslq_stream s_qpack_dec;
  struct cf_osslq_stream remote_ctrl[3]; /* uni streams opened by the peer */
  size_t remote_ctrl_n; /* number of peer streams opened */
};

static void cf_osslq_h3conn_cleanup(struct cf_osslq_h3conn *h3)
{
  size_t i;

  if(h3->conn)
    nghttp3_conn_del(h3->conn);
  cf_osslq_stream_cleanup(&h3->s_ctrl);
  cf_osslq_stream_cleanup(&h3->s_qpack_enc);
  cf_osslq_stream_cleanup(&h3->s_qpack_dec);
  for(i = 0; i < h3->remote_ctrl_n; ++i) {
    cf_osslq_stream_cleanup(&h3->remote_ctrl[i]);
  }
}

struct cf_osslq_ctx
{
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
  struct cf_call_data call_data;
  struct cf_osslq_h3conn h3;
  struct curltime started_at;    /* time the current attempt started */
  struct curltime handshake_at;  /* time connect handshake finished */
  struct curltime first_byte_at; /* when first byte was recvd */
  struct bufc_pool stream_bufcp; /* chunk pool for streams */
  struct uint_hash streams;
                           /* hash `data->mid` to `h3_proxy_stream_ctx` */
  size_t max_stream_window;      /* max flow window for one stream */
  uint64_t max_idle_ms;          /* max idle time for QUIC connection */
  SSL_POLL_ITEM *poll_items;     /* Array for polling on writable state */
  struct Curl_easy **curl_items; /* Array of easy objs */
  size_t items_max;              /* max elements in poll/curl_items */
  struct Curl_addrinfo *addr;    /* remote addr */
  BIT(initialized);
  BIT(got_first_byte);    /* if first byte was received */
  BIT(x509_store_setup);  /* if x509 store has been set up */
  BIT(protocol_shutdown); /* QUIC connection is shut down */
  BIT(need_recv);         /* QUIC connection needs to receive */
  BIT(need_send);         /* QUIC connection needs to send */
};
#endif /* USE_OPENSSL_QUIC */

#ifdef USE_NGTCP2
struct cf_ngtcp2_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
#ifdef OPENSSL_QUIC_API2
  ngtcp2_crypto_ossl_ctx *ossl_ctx;
#endif
  ngtcp2_path connected_path;
  ngtcp2_conn *qconn;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  uint32_t version;
  ngtcp2_settings settings;
  ngtcp2_transport_params transport_params;
  ngtcp2_ccerr last_error;
  ngtcp2_crypto_conn_ref conn_ref;
  struct cf_call_data call_data;
  nghttp3_conn *h3conn;
  nghttp3_settings h3settings;
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct bufc_pool stream_bufcp;     /* chunk pool for streams */
  struct dynbuf scratch;             /* temp buffer for header construction */
  struct uint_hash streams;
                            /* hash `data->mid` to `h3_proxy_stream_ctx` */
  size_t max_stream_window;          /* max flow window for one stream */
  uint64_t used_bidi_streams;        /* bidi streams we have opened */
  uint64_t max_bidi_streams;         /* max bidi streams we can open */
  size_t earlydata_max;              /* max amount of early data supported by
                                        server on session reuse */
  size_t earlydata_skip;             /* sending bytes to skip when earlydata
                                        is accepted by peer */
  CURLcode tls_vrfy_result;          /* result of TLS peer verification */
  int qlogfd;
  struct Curl_addrinfo *addr;        /* remote addr */
  BIT(initialized);
  BIT(tls_handshake_complete);       /* TLS handshake is done */
  BIT(use_earlydata);                /* Using 0RTT data */
  BIT(earlydata_accepted);           /* 0RTT was accepted by server */
  BIT(shutdown_started);             /* queued shutdown packets */
};
#endif /* USE_NGTCP2 */

struct cf_h3_proxy_ctx
{
#ifdef USE_OPENSSL_QUIC
  struct cf_osslq_ctx *osslq_ctx;
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  struct cf_ngtcp2_ctx *ngtcp2_ctx;
#endif /* USE_NGTCP2 */
  struct bufq inbufq;          /* network receive buffer */
  struct tunnel_stream tunnel; /* our tunnel CONNECT stream */
  int32_t goaway_error;
  BIT(partial_read);
  BIT(connected);
};

static void h3_stream_hash_free(unsigned int id, void *stream);

#ifdef USE_OPENSSL_QUIC
static void cf_osslq_ctx_init(struct cf_osslq_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  Curl_bufcp_init(&ctx->stream_bufcp, PROXY_H3_STREAM_CHUNK_SIZE,
                  PROXY_H3_STREAM_POOL_SPARES);
  Curl_uint_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->poll_items = NULL;
  ctx->curl_items = NULL;
  ctx->items_max = 0;
  ctx->initialized = TRUE;
}

static void cf_osslq_ctx_free(struct cf_osslq_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_bufcp_free(&ctx->stream_bufcp);
    Curl_uint_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
    free(ctx->poll_items);
    free(ctx->curl_items);
  }
  free(ctx);
}

static void cf_osslq_ctx_close(struct cf_osslq_ctx *ctx)
{
  cf_osslq_h3conn_cleanup(&ctx->h3);
  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
}
#endif /* USE_OPENSSL_QUIC */

#ifdef USE_NGTCP2
static void cf_ngtcp2_ctx_init(struct cf_ngtcp2_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  ctx->qlogfd = -1;
  ctx->version = NGTCP2_PROTO_VER_MAX;
  ctx->max_stream_window = PROXY_H3_STREAM_WINDOW_SIZE;
  Curl_bufcp_init(&ctx->stream_bufcp, PROXY_H3_STREAM_CHUNK_SIZE,
                  PROXY_H3_STREAM_POOL_SPARES);
  curlx_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  Curl_uint_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->initialized = TRUE;
}

static void cf_ngtcp2_ctx_free(struct cf_ngtcp2_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_vquic_tls_cleanup(&ctx->tls);
    vquic_ctx_free(&ctx->q);
    Curl_bufcp_free(&ctx->stream_bufcp);
    curlx_dyn_free(&ctx->scratch);
    Curl_uint_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
  }
  free(ctx);
}

static void cf_ngtcp2_ctx_close(struct cf_ngtcp2_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(!ctx->initialized)
    return;
  if(ctx->qlogfd != -1) {
    close(ctx->qlogfd);
  }
  ctx->qlogfd = -1;
  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
  if(ctx->h3conn) {
    nghttp3_conn_del(ctx->h3conn);
    ctx->h3conn = NULL;
  }
  if(ctx->qconn) {
    ngtcp2_conn_del(ctx->qconn);
    ctx->qconn = NULL;
  }
#ifdef OPENSSL_QUIC_API2
  if(ctx->ossl_ctx) {
    ngtcp2_crypto_ossl_ctx_del(ctx->ossl_ctx);
    ctx->ossl_ctx = NULL;
  }
#endif
  ctx->call_data = save;
}

static void cf_ngtcp2_setup_keep_alive(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  const ngtcp2_transport_params *rp;
  /* Peer should have sent us its transport parameters. If it
  * announces a positive `max_idle_timeout` it will close the
  * connection when it does not hear from us for that time.
  *
  * Some servers use this as a keep-alive timer at a rather low
  * value. We are doing HTTP/3 here and waiting for the response
  * to a request may take a considerable amount of time. We need
  * to prevent the peer's QUIC stack from closing in this case.
  */
  if(!ctx->qconn)
    return;

  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(!rp || !rp->max_idle_timeout) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no peer idle timeout, unset keep-alive");
  }
  else if(!Curl_uint_hash_count(&ctx->streams)) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no active streams, unset keep-alive");
  }
  else {
    ngtcp2_duration keep_ns;
    keep_ns = (rp->max_idle_timeout > 1) ? (rp->max_idle_timeout / 2) : 1;
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, keep_ns);
    CURL_TRC_CF(data, cf, "peer idle timeout is %" FMT_PRIu64 "ms, "
                "set keep-alive to %" FMT_PRIu64 " ms.",
                (curl_uint64_t)(rp->max_idle_timeout / NGTCP2_MILLISECONDS),
                (curl_uint64_t)(keep_ns / NGTCP2_MILLISECONDS));
  }
}

/* ngtcp2 helper structures and functions for proxy */
struct pkt_io_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  ngtcp2_tstamp ts;
  ngtcp2_path_storage ps;
};

static void pktx_update_time(struct pkt_io_ctx *pktx,
                             struct Curl_cfilter *cf)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;

  vquic_ctx_update_time(&ctx->q);
  pktx->ts = (ngtcp2_tstamp)ctx->q.last_op.tv_sec * NGTCP2_SECONDS +
             (ngtcp2_tstamp)ctx->q.last_op.tv_usec * NGTCP2_MICROSECONDS;
}

static void pktx_init(struct pkt_io_ctx *pktx,
                      struct Curl_cfilter *cf,
                      struct Curl_easy *data)
{
  pktx->cf = cf;
  pktx->data = data;
  ngtcp2_path_storage_zero(&pktx->ps);
  pktx_update_time(pktx, cf);
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  struct Curl_cfilter *cf = conn_ref->user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  return ctx->qconn;
}

#ifdef DEBUG_NGTCP2
static void quic_printf(void *user_data, const char *fmt, ...)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  (void)ctx;  /* need an easy handle to infof() message */
  va_list ap;
  va_start(ap, fmt);
  curl_mvfprintf(stderr, fmt, ap);
  va_end(ap);
  curl_mfprintf(stderr, "\n");
}
#endif /* DEBUG_NGTCP2 */

static void qlog_callback(void *user_data, uint32_t flags,
                          const void *data, size_t datalen)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  (void)flags;
  if(ctx->qlogfd != -1) {
    ssize_t rc = write(ctx->qlogfd, data, datalen);
    if(rc == -1) {
      /* on write error, stop further write attempts */
      close(ctx->qlogfd);
      ctx->qlogfd = -1;
    }
  }
}

static void quic_settings_proxy(struct cf_ngtcp2_ctx *ctx,
                                struct Curl_easy *data,
                                struct pkt_io_ctx *pktx)
{
  ngtcp2_settings *s = &ctx->settings;
  ngtcp2_transport_params *t = &ctx->transport_params;

  ngtcp2_settings_default(s);
  ngtcp2_transport_params_default(t);
#ifdef DEBUG_NGTCP2
  s->log_printf = quic_printf;
#else
  s->log_printf = NULL;
#endif /* DEBUG_NGTCP2 */

  s->initial_ts = pktx->ts;
  s->handshake_timeout = (data->set.connecttimeout > 0) ?
    data->set.connecttimeout * NGTCP2_MILLISECONDS : QUIC_HANDSHAKE_TIMEOUT;
  s->max_window = 100 * ctx->max_stream_window;
  s->max_stream_window = 10 * ctx->max_stream_window;
  s->no_pmtud = FALSE;
#ifdef NGTCP2_SETTINGS_V3
  /* try ten times the ngtcp2 defaults here for problems with Caddy */
  s->glitch_ratelim_burst = 1000 * 10;
  s->glitch_ratelim_rate = 33 * 10;
#endif /* NGTCP2_SETTINGS_V3 */
  t->initial_max_data = 10 * ctx->max_stream_window;
  t->initial_max_stream_data_bidi_local = ctx->max_stream_window;
  t->initial_max_stream_data_bidi_remote = ctx->max_stream_window;
  t->initial_max_stream_data_uni = ctx->max_stream_window;
  t->initial_max_streams_bidi = QUIC_MAX_STREAMS;
  t->initial_max_streams_uni = QUIC_MAX_STREAMS;
  t->max_idle_timeout = 0; /* no idle timeout from our side */
  if(ctx->qlogfd != -1) {
    s->qlog_write = qlog_callback;
  }
}

static void cf_ngtcp2_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

static bool cf_ngtcp2_err_is_fatal(int code)
{
  return (NGTCP2_ERR_FATAL >= code) ||
         (NGTCP2_ERR_DROP_CONN == code) ||
         (NGTCP2_ERR_IDLE_CLOSE == code);
}

static void cf_ngtcp2_err_set(struct Curl_cfilter *cf,
                              struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    if(NGTCP2_ERR_CRYPTO == code) {
      ngtcp2_ccerr_set_tls_alert(&ctx->last_error,
                                 ngtcp2_conn_get_tls_alert(ctx->qconn),
                                 NULL, 0);
    }
    else {
      ngtcp2_ccerr_set_liberr(&ctx->last_error, code, NULL, 0);
    }
  }
  if(cf_ngtcp2_err_is_fatal(code))
    cf_ngtcp2_conn_close(cf, data);
}

static bool cf_ngtcp2_h3_err_is_fatal(int code)
{
  return (NGHTTP3_ERR_FATAL >= code) ||
         (NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM == code);
}

static void cf_ngtcp2_h3_err_set(struct Curl_cfilter *cf,
                                 struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    ngtcp2_ccerr_set_application_error(&ctx->last_error,
      nghttp3_err_infer_quic_app_error_code(code), NULL, 0);
  }
  if(cf_ngtcp2_h3_err_is_fatal(code))
    cf_ngtcp2_conn_close(cf, data);
}
#endif /* USE_NGTCP2 */

/* How to access `call_data` from a cf_h3_proxy filter */
#undef CF_CTX_CALL_DATA
#ifdef USE_OPENSSL_QUIC
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_h3_proxy_ctx *)(cf)->ctx)->osslq_ctx->call_data
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_h3_proxy_ctx *)(cf)->ctx)->ngtcp2_ctx->call_data
#endif /* USE_NGTCP2 */

static void cf_h3_proxy_ctx_clear(struct cf_h3_proxy_ctx *ctx)
{
  Curl_bufq_free(&ctx->inbufq);
  tunnel_stream_clear(&ctx->tunnel);
  memset(ctx, 0, sizeof(*ctx));
}

static void cf_h3_proxy_ctx_free(struct cf_h3_proxy_ctx *ctx)
{
  if(ctx) {
    cf_h3_proxy_ctx_clear(ctx);
    free(ctx);
  }
}

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_osslq_h3conn_add_stream(struct cf_osslq_h3conn *h3,
                                           SSL *stream_ssl,
                                           struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  curl_int64_t stream_id = (curl_int64_t)SSL_get_stream_id(stream_ssl);

  if(h3->remote_ctrl_n >= ARRAYSIZE(h3->remote_ctrl)) {
    /* rejected, we are full */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] rejecting remote stream",
                stream_id);
    SSL_free(stream_ssl);
    return CURLE_FAILED_INIT;
  }
  switch(SSL_get_stream_type(stream_ssl)) {
  case SSL_STREAM_TYPE_READ:{
    struct cf_osslq_stream *nstream = &h3->remote_ctrl[h3->remote_ctrl_n++];
    nstream->id = stream_id;
    nstream->ssl = stream_ssl;
    Curl_bufq_initp(&nstream->recvbuf, &ctx->stream_bufcp, 1, BUFQ_OPT_NONE);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] accepted remote uni stream",
                stream_id);
    break;
  }
  default:
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reject remote non-uni-read"
                          " stream",
                stream_id);
    SSL_free(stream_ssl);
    return CURLE_FAILED_INIT;
  }
  return CURLE_OK;
}

static CURLcode cf_osslq_ssl_err(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 int detail, CURLcode def_result)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = def_result;
  sslerr_t errdetail;
  char ebuf[256] = "unknown";
  const char *err_descr = ebuf;
  long lerr;
  int lib;
  int reason;
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

  errdetail = ERR_get_error();
  lib = ERR_GET_LIB(errdetail);
  reason = ERR_GET_REASON(errdetail);

  if((lib == ERR_LIB_SSL) &&
     ((reason == SSL_R_CERTIFICATE_VERIFY_FAILED) ||
      (reason == SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED))) {
    result = CURLE_PEER_FAILED_VERIFICATION;

    lerr = SSL_get_verify_result(ctx->tls.ossl.ssl);
    if(lerr != X509_V_OK) {
      ssl_config->certverifyresult = lerr;
      curl_msnprintf(ebuf, sizeof(ebuf),
                     "SSL certificate problem: %s",
                     X509_verify_cert_error_string(lerr));
    }
    else
      err_descr = "SSL certificate verification failed";
  }
#ifdef SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED
  /* SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED is only available on
     OpenSSL version above v1.1.1, not LibreSSL, BoringSSL, or AWS-LC */
  else if((lib == ERR_LIB_SSL) &&
           (reason == SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED)) {
    /* If client certificate is required, communicate the
       error to client */
    result = CURLE_SSL_CLIENTCERT;
    osslq_strerror(errdetail, ebuf, sizeof(ebuf));
  }
#endif
  else if((lib == ERR_LIB_SSL) && (reason == SSL_R_PROTOCOL_IS_SHUTDOWN)) {
    ctx->protocol_shutdown = TRUE;
    err_descr = "QUIC connection has been shut down";
    result = def_result;
  }
  else {
    result = def_result;
    osslq_strerror(errdetail, ebuf, sizeof(ebuf));
  }

  /* detail is already set to the SSL error above */

  /* If we e.g. use SSLv2 request-method and the server does not like us
   * (RST connection, etc.), OpenSSL gives no explanation whatsoever and
   * the SO_ERROR is also lost.
   */
  if(CURLE_SSL_CONNECT_ERROR == result && errdetail == 0) {
    char extramsg[80]="";
    int sockerr = SOCKERRNO;
    struct ip_quadruple ip;

    if(sockerr && detail == SSL_ERROR_SYSCALL)
      curlx_strerror(sockerr, extramsg, sizeof(extramsg));
    if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
      failf(data, "QUIC connect: %s in connection to %s:%d (%s)",
            extramsg[0] ? extramsg : osslq_SSL_ERROR_to_str(detail),
            ctx->peer.dispname, ip.remote_port, ip.remote_ip);
  }
  else {
    /* Could be a CERT problem */
    failf(data, "%s", err_descr);
  }
  return result;
}

static CURLcode cf_osslq_verify_peer(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;

  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */

  return Curl_vquic_tls_verify_peer(&ctx->tls, cf, data, &ctx->peer);
}
#endif /* USE_OPENSSL_QUIC */

/**
 * All about the H3 internals of a stream
 */
struct h3_proxy_stream_ctx
{
#ifdef USE_OPENSSL_QUIC
  struct cf_osslq_stream s;
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  curl_int64_t id;              /* HTTP/3 stream identifier */
#endif /* USE_NGTCP2 */
  struct bufq sendbuf;          /* h3 request body */
  struct bufq recvbuf;          /* h3 response body */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  curl_uint64_t error3;         /* HTTP/3 stream error code */
  curl_off_t upload_left;       /* number of request bytes left to upload */
  curl_off_t tun_data_recvd;    /* number of bytes received over tunnel */
  int status_code;              /* HTTP status code */
#ifdef USE_NGTCP2
  CURLcode xfer_result;         /* result from xfer_resp_write(_hd) */
#endif /* USE_NGTCP2 */
  BIT(resp_hds_complete);       /* we have a complete, final response */
  BIT(closed);                  /* TRUE on stream close */
  BIT(reset);                   /* TRUE on stream reset */
  BIT(send_closed);             /* stream is local closed */
  BIT(quic_flow_blocked);       /* stream is blocked by QUIC flow control */
};

#define H3_PROXY_STREAM_CTX(ctx, data)                                     \
  (data ? Curl_uint_hash_get(&(ctx)->streams, (data)->mid) : NULL)

/* Helper macro to get stream ID regardless of QUIC stack */
#ifdef USE_OPENSSL_QUIC
#define H3_STREAM_ID(stream) ((stream)->s.id)
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
#define H3_STREAM_ID(stream) ((stream)->id)
#endif /* USE_NGTCP2 */

static void h3_stream_ctx_free(struct h3_proxy_stream_ctx *stream)
{
#ifdef USE_OPENSSL_QUIC
  cf_osslq_stream_cleanup(&stream->s);
#endif /* USE_OPENSSL_QUIC */
  Curl_bufq_free(&stream->sendbuf);
  Curl_bufq_free(&stream->recvbuf);
  free(stream);
}

static void h3_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct h3_proxy_stream_ctx *)stream);
}

static CURLcode h3_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct h3_proxy_stream_ctx *stream = NULL;

  if(!data)
    return CURLE_FAILED_INIT;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(stream)
      return CURLE_OK;

    stream = calloc(1, sizeof(*stream));
    if(!stream)
      return CURLE_OUT_OF_MEMORY;

    stream->s.id = -1;
    Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                    PROXY_H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
    stream->sendbuf_len_in_flight = 0;
    Curl_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                    PROXY_H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);

    if(!Curl_uint_hash_set(&ctx->streams, data->mid, stream)) {
      h3_stream_ctx_free(stream);
      return CURLE_OUT_OF_MEMORY;
    }
    return CURLE_OK;
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(stream)
      return CURLE_OK;

    stream = calloc(1, sizeof(*stream));
    if(!stream)
      return CURLE_OUT_OF_MEMORY;

    stream->id = -1;
    /* on send, we control how much we put into the buffer */
    Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                    PROXY_H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
    stream->sendbuf_len_in_flight = 0;
    Curl_bufq_initp(&stream->recvbuf, &ctx->stream_bufcp,
                    PROXY_H3_STREAM_RECV_CHUNKS, BUFQ_OPT_SOFT_LIMIT);

    if(!Curl_uint_hash_set(&ctx->streams, data->mid, stream)) {
      h3_stream_ctx_free(stream);
      return CURLE_OUT_OF_MEMORY;
    }

    if(Curl_uint_hash_count(&ctx->streams) == 1)
      cf_ngtcp2_setup_keep_alive(cf, data);

    return CURLE_OK;
  }
#endif /* USE_NGTCP2 */

  return CURLE_FAILED_INIT;
}

#ifdef USE_OPENSSL_QUIC
struct cf_ossq_find_ctx {
  curl_int64_t stream_id;
  struct h3_proxy_stream_ctx *stream;
};

static bool cf_osslq_find_stream(unsigned int mid, void *val, void *user_data)
{
  struct h3_proxy_stream_ctx *stream = val;
  struct cf_ossq_find_ctx *fctx = user_data;

  (void)mid;
  if(stream && stream->s.id == fctx->stream_id) {
    fctx->stream = stream;
    return FALSE; /* stop iterating */
  }
  return TRUE;
}

static struct cf_osslq_stream *cf_osslq_get_qstream(struct Curl_cfilter *cf,
                                                    struct Curl_easy *data,
                                                    int64_t stream_id)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

  if(stream && stream->s.id == stream_id) {
    return &stream->s;
  }
  else if(ctx->h3.s_ctrl.id == stream_id) {
    return &ctx->h3.s_ctrl;
  }
  else if(ctx->h3.s_qpack_enc.id == stream_id) {
    return &ctx->h3.s_qpack_enc;
  }
  else if(ctx->h3.s_qpack_dec.id == stream_id) {
    return &ctx->h3.s_qpack_dec;
  }
  else {
    struct cf_ossq_find_ctx fctx;
    fctx.stream_id = stream_id;
    fctx.stream = NULL;
    Curl_uint_hash_visit(&ctx->streams, cf_osslq_find_stream, &fctx);
    if(fctx.stream)
      return &fctx.stream->s;
  }
  return NULL;
}
#endif /* USE_OPENSSL_QUIC */

/* nghttp3 callbacks - these work with both QUIC stacks */
static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *user_data,
                                void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  size_t skiplen;
  (void)cf;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  if(!stream)
    return 0;
  /* The server acknowledged `datalen` of bytes from our request body.
   * This is a delta. We have kept this data in `sendbuf` for
   * re-transmissions and can free it now. */
  if(datalen >= (uint64_t)stream->sendbuf_len_in_flight)
    skiplen = stream->sendbuf_len_in_flight;
  else
    skiplen = (size_t)datalen;
  Curl_bufq_skip(&stream->sendbuf, skiplen);
  stream->sendbuf_len_in_flight -= skiplen;

  /* Resume upload processing if we have more data to send */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    int rv = nghttp3_conn_resume_stream(conn, stream_id);
    if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  (void)conn;
  (void)stream_id;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  /* we might be called by nghttp3 after we already cleaned up */
  if(!stream)
    return 0;

  stream->closed = TRUE;
  stream->error3 = app_error_code;
  if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] RESET: error %" FMT_PRIu64,
                H3_STREAM_ID(stream), stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] CLOSED", H3_STREAM_ID(stream));
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

#define TMP_BUF_SIZE (size_t) 32768
static size_t head = 0;
static size_t tail = 0;
static char tmp_buf[TMP_BUF_SIZE] = {0};

static int handle_buffered_data(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct h3_proxy_stream_ctx *stream = NULL;
  size_t nwritten;
  size_t data_len;
  CURLcode result = CURLE_OK;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  data_len = tail - head;

  result = Curl_bufq_write(&proxy_ctx->inbufq,
                           (const unsigned char *)(tmp_buf + head),
                           data_len, &nwritten);
  if(result)
    return 0;

  if(nwritten < data_len) {
    head += nwritten;
    data_len = tail - head + 1;
  }
  else {
    proxy_ctx->partial_read = FALSE;
    head = 0;
    tail = 0;
    memset(tmp_buf, 0, TMP_BUF_SIZE);
  }
  return 0;
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t buflen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  size_t nwritten;
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)stream3_id;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  if(!stream) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  stream->tun_data_recvd += (curl_off_t)buflen;
  CURL_TRC_CF(data, cf, "[cb_h3_recv_data] "
              "[%" FMT_PRId64 "] DATA len=%zu, total=%zd",
              H3_STREAM_ID(stream), buflen, stream->tun_data_recvd);

  if(proxy_ctx->partial_read) {
    memcpy(tmp_buf + tail, buf, buflen);
    tail += buflen;
    return 0;
  }

  result = Curl_bufq_write(&proxy_ctx->inbufq, buf, buflen, &nwritten);
  if(result) {
    proxy_ctx->partial_read = TRUE;
    memcpy(tmp_buf + tail, buf, buflen);
    tail += buflen;
    return 0;
  }
  if(nwritten < buflen) {
    proxy_ctx->partial_read = TRUE;
    memcpy(tmp_buf + tail, buf + nwritten, (buflen - nwritten));
    tail += (buflen - nwritten);
    return 0;
  }

#ifdef USE_NGTCP2
  if(result && proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream->id, buflen);
    ngtcp2_conn_extend_max_offset(ctx->qconn, buflen);
  }
#endif

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  (void)conn;
  (void)stream_user_data;

#ifdef USE_OPENSSL_QUIC
  (void)stream_id;
  if(proxy_ctx->osslq_ctx) {
    struct Curl_easy *data = stream_user_data;
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);

    if(stream)
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] deferred consume %zu bytes",
                  H3_STREAM_ID(stream), consumed);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;

    /* nghttp3 has consumed bytes on the QUIC stream and we need to
    * tell the QUIC connection to increase its flow control */
    ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream_id, consumed);
    ngtcp2_conn_extend_max_offset(ctx->qconn, consumed);
  }
#endif /* USE_NGTCP2 */

  return 0;
}

static int cb_h3_recv_header(nghttp3_conn *conn, int64_t sid,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  curl_int64_t stream_id = sid;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  CURLcode result = CURLE_OK;
  int http_status;
  struct http_resp *resp;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)cf;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  /* we might have cleaned up this transfer already */
  if(!stream)
    return 0;

  if(proxy_ctx->tunnel.has_final_response) {
    /* we do not do anything with trailers for tunnel streams */
    return 0;
  }

  if(token == NGHTTP3_QPACK_TOKEN__STATUS) {
    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)h3val.base, h3val.len);
    if(result)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    http_status = stream->status_code;
    result = Curl_http_resp_make(&resp, http_status, NULL);
    if(result)
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    resp->prev = proxy_ctx->tunnel.resp;
    proxy_ctx->tunnel.resp = resp;
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] header: %.*s: %.*s",
                stream_id, (int)h3name.len, h3name.base,
                (int)h3val.len, h3val.base);
    result = Curl_dynhds_add(&proxy_ctx->tunnel.resp->headers,
      (const char *)h3name.base, h3name.len,
      (const char *)h3val.base, h3val.len);
    if(result) {
      return -1;
    }
  }
  return 0;
}

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t sid,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  struct h3_proxy_stream_ctx *stream = NULL;
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)cf;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  if(!stream)
    return 0;

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] end_headers, status=%d",
              stream_id, stream->status_code);

  if(!proxy_ctx->tunnel.has_final_response) {
    if(stream->status_code / 100 != 1) {
      proxy_ctx->tunnel.has_final_response = TRUE;
    }
  }

  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }

  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  (void)conn;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    struct Curl_easy *data = stream_user_data;
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    curl_int64_t stream_id = sid;
    (void)app_error_code;

    if(!stream || !stream->s.ssl)
      return 0;

    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] stop_sending", stream_id);
    cf_osslq_stream_close(&stream->s);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  (void)stream_user_data;

  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;

    int rv = ngtcp2_conn_shutdown_stream_read(ctx->qconn, 0, sid,
                                             app_error_code);

    if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
#endif /* USE_NGTCP2 */

  return 0;
}

static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = sid;
  int rv;
  (void)conn;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(stream && stream->s.ssl) {
      SSL_STREAM_RESET_ARGS args = {0};
      args.quic_error_code = app_error_code;
      rv = !SSL_stream_reset(stream->s.ssl, &args, sizeof(args));
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
      if(!rv) {
        return NGHTTP3_ERR_CALLBACK_FAILURE;
      }
    }
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  (void)data;

  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    rv = ngtcp2_conn_shutdown_stream_write(ctx->qconn, 0, stream_id,
                                           app_error_code);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
    if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
#endif /* USE_NGTCP2 */

  return 0;
}

static nghttp3_ssize
cb_h3_read_data_for_tunnel_stream(nghttp3_conn *conn, int64_t stream_id,
                                  nghttp3_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  size_t nwritten = 0;
  size_t nvecs = 0;
  const unsigned char *buf_base;
  (void)cf;
  (void)conn;
  (void)stream_id;
  (void)user_data;
  (void)veccnt;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  /* nghttp3 keeps references to the sendbuf data until it is ACKed
   * by the server (see `cb_h3_acked_req_body()` for updates).
   * `sendbuf_len_in_flight` is the amount of bytes in `sendbuf`
   * that we have already passed to nghttp3, but which have not been
   * ACKed yet.
   * Any amount beyond `sendbuf_len_in_flight` we need still to pass
   * to nghttp3. Do that now, if we can. */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    nvecs = 0;
    while(nvecs < veccnt) {
      if(!Curl_bufq_peek_at(&stream->sendbuf,
                           stream->sendbuf_len_in_flight,
                           &buf_base,
                           &vec[nvecs].len))
        break;
      vec[nvecs].base = (uint8_t *)(uintptr_t)buf_base;
      stream->sendbuf_len_in_flight += vec[nvecs].len;
      nwritten += vec[nvecs].len;
      ++nvecs;
    }
    DEBUGASSERT(nvecs > 0); /* we SHOULD have been be able to peek */
  }

  if(nwritten > 0 && stream->upload_left != -1)
    stream->upload_left -= nwritten;

  /* When we stopped sending and everything in `sendbuf` is "in flight",
   * we are at the end of the request body. */
  /* We should NOT set send_closed = TRUE for tunnel stream */
#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx && stream->upload_left == 0 &&
     !stream->s.tunnel_stream) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx && stream->upload_left == 0) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }
#endif /* USE_NGTCP2 */

  else if(!nwritten) {
    /* Not EOF, and nothing to give, we signal WOULDBLOCK. */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> AGAIN",
                H3_STREAM_ID(stream));
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> "
              "%d vecs%s with %zu (buffered=%zu, left=%" FMT_OFF_T ")",
              H3_STREAM_ID(stream), (int)nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf),
              stream->upload_left);
  return (nghttp3_ssize)nvecs;
}

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  NULL, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  NULL, /* begin_trailers */
  cb_h3_recv_header,
  NULL, /* end_trailers */
  cb_h3_stop_sending,
  NULL, /* end_stream */
  cb_h3_reset_stream,
  NULL, /* shutdown */
  NULL, /* recv_settings */
#ifdef NGHTTP3_CALLBACKS_V2
  NULL, /* recv_origin */
  NULL, /* end_origin */
  NULL, /* rand */
#endif
};

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_osslq_h3conn_init(struct cf_osslq_ctx *ctx, SSL *conn,
                                     void *user_data)
{
  struct cf_osslq_h3conn *h3 = &ctx->h3;
  CURLcode result;
  int rc;

  nghttp3_settings_default(&h3->settings);
  h3->settings.enable_connect_protocol = 1;
  h3->settings.qpack_max_dtable_capacity = 4096;
  h3->settings.qpack_blocked_streams = 100;
  rc = nghttp3_conn_client_new(&h3->conn,
                               &ngh3_callbacks,
                               &h3->settings,
                               Curl_nghttp3_mem(),
                               user_data);
  if(rc) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  result = cf_osslq_stream_open(&h3->s_ctrl, conn,
                                SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  result = cf_osslq_stream_open(&h3->s_qpack_enc, conn,
                                SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  result = cf_osslq_stream_open(&h3->s_qpack_dec, conn,
                                SSL_STREAM_FLAG_ADVANCE | SSL_STREAM_FLAG_UNI,
                                &ctx->stream_bufcp, NULL);
  if(result) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  rc = nghttp3_conn_bind_control_stream(h3->conn, h3->s_ctrl.id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  rc = nghttp3_conn_bind_qpack_streams(h3->conn, h3->s_qpack_enc.id,
                                       h3->s_qpack_dec.id);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  result = CURLE_OK;
out:
  return result;
}

struct h3_quic_recv_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  struct cf_osslq_stream *s;
};

static CURLcode h3_quic_recv(void *reader_ctx,
                            unsigned char *buf, size_t len,
                            size_t *pnread)
{
  struct h3_quic_recv_ctx *x = reader_ctx;
  int rv;

  rv = SSL_read_ex(x->s->ssl, buf, len, pnread);
  if(rv <= 0) {
    int detail = SSL_get_error(x->s->ssl, rv);
    if(detail == SSL_ERROR_WANT_READ || detail == SSL_ERROR_WANT_WRITE) {
      return CURLE_AGAIN;
    }
    else if(detail == SSL_ERROR_ZERO_RETURN) {
      CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] h3_quic_recv -> EOS",
                  x->s->id);
      x->s->recvd_eos = TRUE;
      return CURLE_OK;
    }
    else if(SSL_get_stream_read_state(x->s->ssl) ==
            SSL_STREAM_STATE_RESET_REMOTE) {
      uint64_t app_error_code = NGHTTP3_H3_NO_ERROR;
      SSL_get_stream_read_error_code(x->s->ssl, &app_error_code);
      CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] h3_quic_recv -> RESET, "
                  "rv=%d, app_err=%" FMT_PRIu64,
                  x->s->id, rv, (curl_uint64_t)app_error_code);
      if(app_error_code != NGHTTP3_H3_NO_ERROR) {
        x->s->reset = TRUE;
      }
      x->s->recvd_eos = TRUE;
      return CURLE_OK;
    }
    else {
      return cf_osslq_ssl_err(x->cf, x->data, detail, CURLE_RECV_ERROR);
    }
  }
  return CURLE_OK;
}

static CURLcode cf_osslq_stream_recv(struct cf_osslq_stream *s,
                                     struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;
  size_t n;
  ssize_t nread;
  struct h3_quic_recv_ctx x;
  bool eagain = FALSE;
  size_t total_recv_len = 0;

  DEBUGASSERT(s);
  if(s->closed)
    return CURLE_OK;

  x.cf = cf;
  x.data = data;
  x.s = s;
  while(s->ssl && !s->closed && !eagain &&
         (total_recv_len < PROXY_H3_STREAM_CHUNK_SIZE)) {

    if(proxy_ctx->partial_read && s->id == proxy_ctx->tunnel.stream_id) {
      handle_buffered_data(cf, data);
      break;
    }

    if(Curl_bufq_is_empty(&s->recvbuf) && !s->recvd_eos) {
      while(!eagain && !s->recvd_eos && !Curl_bufq_is_full(&s->recvbuf)) {
        result = Curl_bufq_sipn(&s->recvbuf, 0, h3_quic_recv, &x, &n);
        if(result) {
          if(result != CURLE_AGAIN) {
            goto out;
          }
          result = CURLE_OK;
          eagain = TRUE;
        }
      }
    }

    /* At this point we can have 2 scenarios:
      (1) The proxytunnel is NOT yet UP and we are still negotiating the
          CONNECT request and the different unidirectional streams with
          the proxy. In this case, all the data must be forwarded to
          nghttp3 library for processing.
          Flow:
          cf_h3_proxy_quic_connect() --> proxy_h3_submit() -->
          proxy_h3_progress_egress() --> proxy_h3_progress_ingress() -->
          cf_osslq_h3conn_add_stream() --> cf_osslq_stream_recv() -->
          inspect_response() --> tunnel is UP (with bidi stream id = 0)
      (2) The proxytunnel is UP
          At this point, we have 7 streams - 1 bidi (the tunnel stream) and
          6 unidirectional streams (3 from curl and 3 from the proxy)
          Every "DATA" from the underlying HTTP/1.1 connection must be
          forwarded end-to-end through this HTTP/3 proxytunnel
          (i) Stream 0:
          <HTTP/1.1 data> === proxytunnel === <HTTP/3 headers>
                                              <HTTP/3 data> = <HTTP/1.1 data>
          (ii) Unidirectional Streams:
          can be terminated here, HTTP/1.1 layer is unaware of this
          Functions of Interest:
          (1) nghttp3_conn_read_stream --> this received HTTP/3 specific info
          (2) cb_h3_recv_data --> this received the actual end-to-end flow
                                      data from the server via the proxy
          nghttp3_conn_read_stream() internally invokes cb_h3_recv_data()
          In cb_h3_recv_data(), we are storing the "data" received w.r.t. to
          the HTTP/1.1 flow in cf_h3_proxy_ctx->inbufq
          Now, we need to propagate this up to the recv() call from the
          HTTP/1.1 SSL layer
          This is how the filter chain looks like:
          Curl_cft_http_connect --> Curl_cft_ssl --> ... --> Curl_cft_h3_proxy
    */

    /* Forward what we have to nghttp3 */
    if(!Curl_bufq_is_empty(&s->recvbuf)) {
      const unsigned char *buf;
      size_t blen;

      while(Curl_bufq_peek(&s->recvbuf, &buf, &blen)) {
        nread = nghttp3_conn_read_stream(ctx->h3.conn, s->id,
                                         buf, blen, 0);
        if(nread < 0) {
          failf(data, "nghttp3_conn_read_stream(len=%zu) error: %s",
                blen, nghttp3_strerror((int)nread));
          result = CURLE_OK;
          goto out;
        }

        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] stream %ld, received %zd "
                      "bytes, DATA bytes = %zu, forwarded to nghttp3 = %zd",
                      s->id, s->id, blen, (blen - nread), nread);

        Curl_bufq_skip(&s->recvbuf, blen);
        total_recv_len += blen;

        if(Curl_bufq_is_empty(&s->recvbuf) || proxy_ctx->partial_read)
          break;
      }
    }

    /* When we forwarded everything, handle RESET/EOS */
    if(Curl_bufq_is_empty(&s->recvbuf) && !s->closed) {
      int rv;
      result = CURLE_OK;
      if(s->reset) {
        uint64_t app_error;
        if(!SSL_get_stream_read_error_code(s->ssl, &app_error)) {
          failf(data, "SSL_get_stream_read_error_code returned error");
          result = CURLE_RECV_ERROR;
          goto out;
        }
        rv = nghttp3_conn_close_stream(ctx->h3.conn, s->id, app_error);
        s->closed = TRUE;
        if(rv < 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
          failf(data, "nghttp3_conn_close_stream returned error: %s",
                nghttp3_strerror(rv));
          result = CURLE_RECV_ERROR;
          goto out;
        }
      }
      else if(s->recvd_eos) {
        rv = nghttp3_conn_close_stream(ctx->h3.conn, s->id,
                                       NGHTTP3_H3_NO_ERROR);
        s->closed = TRUE;
        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] close nghttp3 stream -> %d",
                    s->id, rv);
        if(rv < 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
          failf(data, "nghttp3_conn_close_stream returned error: %s",
                nghttp3_strerror(rv));
          result = CURLE_RECV_ERROR;
          goto out;
        }
      }
    }
  }
out:
  return result;
}

struct cf_ossq_recv_ctx {
  struct Curl_cfilter *cf;
  struct Curl_multi *multi;
  CURLcode result;
};

static bool cf_osslq_iter_recv(unsigned int mid, void *val, void *user_data)
{
  struct h3_proxy_stream_ctx *stream = val;
  struct cf_ossq_recv_ctx *rctx = user_data;

  (void)mid;
  if(stream && !stream->closed && !Curl_bufq_is_full(&stream->recvbuf)) {
    struct Curl_easy *sdata = Curl_multi_get_easy(rctx->multi, mid);
    if(sdata) {
      rctx->result = cf_osslq_stream_recv(&stream->s, rctx->cf, sdata);
      if(rctx->result)
        return FALSE; /* abort iteration */
    }
  }
  return TRUE;
}
#endif /* USE_OPENSSL_QUIC */

#ifdef USE_NGTCP2
#if NGTCP2_VERSION_NUM < 0x011100
struct cf_ngtcp2_sfind_ctx {
  curl_int64_t stream_id;
  struct h3_proxy_stream_ctx *stream;
  unsigned int mid;
};

static bool cf_ngtcp2_sfind(unsigned int mid, void *value, void *user_data)
{
  struct cf_ngtcp2_sfind_ctx *fctx = user_data;
  struct h3_proxy_stream_ctx *stream = value;

  if(fctx->stream_id == H3_STREAM_ID(stream)) {
    fctx->mid = mid;
    fctx->stream = stream;
    return FALSE;
  }
  return TRUE; /* continue */
}

static struct h3_proxy_stream_ctx *
cf_ngtcp2_get_stream(struct cf_ngtcp2_ctx *ctx, curl_int64_t stream_id)
{
  struct cf_ngtcp2_sfind_ctx fctx;
  fctx.stream_id = stream_id;
  fctx.stream = NULL;
  Curl_uint_hash_visit(&ctx->streams, cf_ngtcp2_sfind, &fctx);
  return fctx.stream;
}
#else
static struct h3_proxy_stream_ctx *
cf_ngtcp2_get_stream(struct cf_ngtcp2_ctx *ctx, curl_int64_t stream_id)
{
  struct Curl_easy *data =
    ngtcp2_conn_get_stream_user_data(ctx->qconn, stream_id);

  if(!data) {
    return NULL;
  }
  return H3_PROXY_STREAM_CTX(ctx, data);
}
#endif /* NGTCP2_VERSION_NUM < 0x011100 */

static CURLcode cf_ngtcp2_h3conn_init(struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
  int rc;

  if(ngtcp2_conn_get_streams_uni_left(ctx->qconn) < 3) {
    failf(data, "QUIC connection lacks 3 uni streams to run HTTP/3");
    return CURLE_QUIC_CONNECT_ERROR;
  }

  nghttp3_settings_default(&ctx->h3settings);

  rc = nghttp3_conn_client_new(&ctx->h3conn,
                               &ngh3_callbacks,
                               &ctx->h3settings,
                               Curl_nghttp3_mem(),
                               cf);
  if(rc) {
    failf(data, "error creating nghttp3 connection instance");
    return CURLE_OUT_OF_MEMORY;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &ctrl_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 control stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = nghttp3_conn_bind_control_stream(ctx->h3conn, ctrl_stream_id);
  if(rc) {
    failf(data, "error binding HTTP/3 control stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_enc_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 qpack encoding stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_dec_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 qpack decoding stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  rc = nghttp3_conn_bind_qpack_streams(ctx->h3conn, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if(rc) {
    failf(data, "error binding HTTP/3 qpack streams: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }
  return CURLE_OK;
}

/* ngtcp2 callbacks for proxy QUIC connection */
static int cb_ngtcp2_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data;

  (void)tconn;
  DEBUGASSERT(ctx);
  data = CF_DATA_CURRENT(cf);
  DEBUGASSERT(data);
  if(!ctx || !data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  ctx->handshake_at = curlx_now();
  ctx->tls_handshake_complete = TRUE;
  Curl_vquic_report_handshake(&ctx->tls, cf, data);

  ctx->tls_vrfy_result = Curl_vquic_tls_verify_peer(&ctx->tls, cf,
                                                    data, &ctx->peer);
#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(Curl_trc_is_verbose(data)) {
    const ngtcp2_transport_params *rp;
    rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
    CURL_TRC_CF(data, cf, "handshake complete after %dms, remote transport["
                "max_udp_payload=%" FMT_PRIu64
                ", initial_max_data=%" FMT_PRIu64
                "]",
               (int)curlx_timediff(ctx->handshake_at, ctx->started_at),
               (curl_uint64_t)rp->max_udp_payload_size,
               (curl_uint64_t)rp->initial_max_data);
  }
#endif

  /* In case of earlydata, where we simulate being connected, update
   * the handshake time when we really did connect */
  if(ctx->use_earlydata)
    Curl_pgrsTimeWas(data, TIMER_APPCONNECT, ctx->handshake_at);
  if(ctx->use_earlydata) {
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA)
    ctx->earlydata_accepted =
      (SSL_get_early_data_status(ctx->tls.ossl.ssl) !=
       SSL_EARLY_DATA_REJECTED);
#endif
#ifdef USE_GNUTLS
    int flags = gnutls_session_get_flags(ctx->tls.gtls.session);
    ctx->earlydata_accepted = !!(flags & GNUTLS_SFLAGS_EARLY_DATA);
#endif
#ifdef USE_WOLFSSL
#ifdef WOLFSSL_EARLY_DATA
    ctx->earlydata_accepted =
      (wolfSSL_get_early_data_status(ctx->tls.wssl.ssl) !=
       WOLFSSL_EARLY_DATA_REJECTED);
#else
    DEBUGASSERT(0); /* should not come here if ED is disabled. */
    ctx->earlydata_accepted = FALSE;
#endif /* WOLFSSL_EARLY_DATA */
#endif
    CURL_TRC_CF(data, cf, "server did%s accept %zu bytes of early data",
                ctx->earlydata_accepted ? "" : " not", ctx->earlydata_skip);
    Curl_pgrsEarlyData(data, ctx->earlydata_accepted ?
                              (curl_off_t)ctx->earlydata_skip :
                             -(curl_off_t)ctx->earlydata_skip);
  }
  return 0;
}

static int cb_ngtcp2_recv_stream_data(ngtcp2_conn *tconn, uint32_t flags,
                                      int64_t sid, uint64_t offset,
                                      const uint8_t *buf, size_t buflen,
                                      void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  nghttp3_ssize nconsumed;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  struct Curl_easy *data = stream_user_data;
  (void)offset;
  (void)data;

  nconsumed =
    nghttp3_conn_read_stream(ctx->h3conn, stream_id, buf, buflen, fin);
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(data)
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read_stream(len=%zu) -> %zd",
                stream_id, buflen, nconsumed);
  if(nconsumed < 0) {
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(data && stream) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] error on known stream, "
                  "reset=%d, closed=%d",
                  stream_id, stream->reset, stream->closed);
    }
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* number of bytes inside buflen which consists of framing overhead
   * including QPACK HEADERS. In other words, it does not consume payload of
   * DATA frame. */
  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, (uint64_t)nconsumed);
  ngtcp2_conn_extend_max_offset(tconn, (uint64_t)nconsumed);

  return 0;
}

static int cb_ngtcp2_acked_stream_data_offset(ngtcp2_conn *tconn,
                                              int64_t stream_id,
                                              uint64_t offset,
                                              uint64_t datalen,
                                              void *user_data,
                                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  int rv;
  (void)stream_id;
  (void)tconn;
  (void)offset;
  (void)datalen;
  (void)stream_user_data;

  rv = nghttp3_conn_add_ack_offset(ctx->h3conn, stream_id, datalen);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_ngtcp2_stream_close(ngtcp2_conn *tconn, uint32_t flags,
                                  int64_t sid, uint64_t app_error_code,
                                  void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
  int rv;

  (void)tconn;
  /* stream is closed... */
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(!data)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if(!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  rv = nghttp3_conn_close_stream(ctx->h3conn, stream_id, app_error_code);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] quic close(app_error=%"
              FMT_PRIu64 ") -> %d", stream_id, (curl_uint64_t)app_error_code,
              rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    cf_ngtcp2_h3_err_set(cf, data, rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_ngtcp2_extend_max_local_streams_bidi(ngtcp2_conn *tconn,
                                                   uint64_t max_streams,
                                                   void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)tconn;
  ctx->max_bidi_streams = max_streams;
  if(data)
    CURL_TRC_CF(data, cf, "max bidi streams now %" FMT_PRIu64
                ", used %" FMT_PRIu64, (curl_uint64_t)ctx->max_bidi_streams,
                (curl_uint64_t)ctx->used_bidi_streams);
  return 0;
}

static void cb_ngtcp2_rand(uint8_t *dest, size_t destlen,
                           const ngtcp2_rand_ctx *rand_ctx)
{
  CURLcode result;
  (void)rand_ctx;

  result = Curl_rand(NULL, dest, destlen);
  if(result) {
    /* cb_rand is only used for non-cryptographic context. If Curl_rand
       failed, just fill 0 and call it *random*. */
    memset(dest, 0, destlen);
  }
}

static int cb_ngtcp2_get_new_connection_id(ngtcp2_conn *tconn, ngtcp2_cid *cid,
                                           uint8_t *token, size_t cidlen,
                                           void *user_data)
{
  CURLcode result;
  (void)tconn;
  (void)user_data;

  result = Curl_rand(NULL, cid->data, cidlen);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;

  result = Curl_rand(NULL, token, NGTCP2_STATELESS_RESET_TOKENLEN);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

static int cb_ngtcp2_stream_reset(ngtcp2_conn *tconn, int64_t sid,
                                  uint64_t final_size, uint64_t app_error_code,
                                  void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;
  (void)data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_ngtcp2_extend_max_stream_data(ngtcp2_conn *tconn,
                                            int64_t stream_id,
                                            uint64_t max_data, void *user_data,
                                            void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *s_data = stream_user_data;
  struct h3_proxy_stream_ctx *stream = NULL;
  int rv;
  (void)tconn;
  (void)max_data;

  rv = nghttp3_conn_unblock_stream(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  stream = H3_PROXY_STREAM_CTX(ctx, s_data);
  if(stream && stream->quic_flow_blocked) {
    CURL_TRC_CF(s_data, cf, "[%" FMT_PRId64 "] unblock quic flow",
                (curl_int64_t)stream_id);
    stream->quic_flow_blocked = FALSE;
    Curl_multi_mark_dirty(s_data);
  }
  return 0;
}

static int cb_ngtcp2_stream_stop_sending(ngtcp2_conn *tconn, int64_t stream_id,
                                         uint64_t app_error_code,
                                         void *user_data,
                                         void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  int rv;
  (void)tconn;
  (void)app_error_code;
  (void)stream_user_data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int cb_ngtcp2_recv_rx_key(ngtcp2_conn *tconn,
                                 ngtcp2_encryption_level level,
                                 void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  (void)tconn;

  if(level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
    return 0;

  DEBUGASSERT(ctx);
  DEBUGASSERT(data);
  if(ctx && data && !ctx->h3conn) {
    if(cf_ngtcp2_h3conn_init(cf, data))
      return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static ngtcp2_callbacks ngtcp2_proxy_callbacks = {
  ngtcp2_crypto_client_initial_cb,
  NULL, /* recv_client_initial */
  ngtcp2_crypto_recv_crypto_data_cb,
  cb_ngtcp2_handshake_completed,
  NULL, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_ngtcp2_recv_stream_data,
  cb_ngtcp2_acked_stream_data_offset,
  NULL, /* stream_open */
  cb_ngtcp2_stream_close,
  NULL, /* recv_stateless_reset */
  ngtcp2_crypto_recv_retry_cb,
  cb_ngtcp2_extend_max_local_streams_bidi,
  NULL, /* extend_max_local_streams_uni */
  cb_ngtcp2_rand,
  cb_ngtcp2_get_new_connection_id,
  NULL, /* remove_connection_id */
  ngtcp2_crypto_update_key_cb,
  NULL, /* path_validation */
  NULL, /* select_preferred_addr */
  cb_ngtcp2_stream_reset,
  NULL, /* extend_max_remote_streams_bidi */
  NULL, /* extend_max_remote_streams_uni */
  cb_ngtcp2_extend_max_stream_data,
  NULL, /* dcid_status */
  NULL, /* handshake_confirmed */
  NULL, /* recv_new_token */
  ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  NULL, /* recv_datagram */
  NULL, /* ack_datagram */
  NULL, /* lost_datagram */
  ngtcp2_crypto_get_path_challenge_data_cb,
  cb_ngtcp2_stream_stop_sending,
  NULL, /* version_negotiation */
  cb_ngtcp2_recv_rx_key, /* recv_rx_key */
  NULL, /* recv_tx_key */
  NULL, /* early_data_rejected */
#ifdef NGTCP2_CALLBACKS_V2
  NULL, /* begin_path_validation */
#endif
};

static CURLcode cf_ngtcp2_recv_pkts_proxy(const unsigned char *buf,
                                          size_t buflen, size_t gso_size,
                                          struct sockaddr_storage *remote_addr,
                                          socklen_t remote_addrlen, int ecn,
                                          void *userp)
{
  struct pkt_io_ctx *pktx = userp;
  struct cf_h3_proxy_ctx *proxy_ctx = pktx->cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  ngtcp2_pkt_info pi;
  ngtcp2_path path;
  size_t offset, pktlen;
  int rv;

  if(ecn)
    CURL_TRC_CF(pktx->data, pktx->cf, "vquic_recv(len=%zu, gso=%zu, ecn=%x)",
                buflen, gso_size, ecn);
  ngtcp2_addr_init(&path.local, (struct sockaddr *)&ctx->q.local_addr,
                   (socklen_t)ctx->q.local_addrlen);
  ngtcp2_addr_init(&path.remote, (struct sockaddr *)remote_addr,
                   remote_addrlen);
  pi.ecn = (uint8_t)ecn;

  for(offset = 0; offset < buflen; offset += gso_size) {
    pktlen = ((offset + gso_size) <= buflen) ? gso_size : (buflen - offset);
    rv = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi,
                              buf + offset, pktlen, pktx->ts);
    if(rv) {
      CURL_TRC_CF(pktx->data, pktx->cf, "ingress, read_pkt -> %s (%d)",
                  ngtcp2_strerror(rv), rv);
      cf_ngtcp2_err_set(pktx->cf, pktx->data, rv);

      if(rv == NGTCP2_ERR_CRYPTO)
        /* this is a "TLS problem", but a failed certificate verification
           is a common reason for this */
        return CURLE_PEER_FAILED_VERIFICATION;
      return CURLE_RECV_ERROR;
    }
  }
  return CURLE_OK;
}

static CURLcode proxy_h3_progress_ingress_ngtcp2(struct Curl_cfilter *cf,
                                                 struct Curl_easy *data,
                                                 struct pkt_io_ctx *pktx)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct pkt_io_ctx local_pktx;
  CURLcode result = CURLE_OK;

  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;

    if(!pktx) {
      pktx_init(&local_pktx, cf, data);
      pktx = &local_pktx;
    }
    else {
      pktx_update_time(pktx, cf);
      ngtcp2_path_storage_zero(&pktx->ps);
    }

    result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
    if(result)
      return result;

    return vquic_recv_packets(cf, data, &ctx->q, 1000,
                              cf_ngtcp2_recv_pkts_proxy, pktx);
  }
  return result;
}
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
static CURLcode proxy_h3_progress_ingress_ossl(struct Curl_cfilter *cf,
                                               struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;

    if(!ctx->tls.ossl.ssl)
      goto out;

    ERR_clear_error();

    /* Check for new incoming streams, once the proxy tunnel stream
      and the 3 unidirectional streams (CONTROL, QPACK DEC & ENC)
      are setup, we do not expect to accept any more stream */
    if(!proxy_ctx->connected && ctx->h3.remote_ctrl_n < 3) {
      while(1) {
        SSL *snew = SSL_accept_stream(ctx->tls.ossl.ssl,
                                      SSL_ACCEPT_STREAM_NO_BLOCK);
        if(!snew)
          break;

        (void)cf_osslq_h3conn_add_stream(&ctx->h3, snew, cf, data);
      }
    }

    if(!SSL_handle_events(ctx->tls.ossl.ssl)) {
      int detail = SSL_get_error(ctx->tls.ossl.ssl, 0);
      result = cf_osslq_ssl_err(cf, data, detail, CURLE_RECV_ERROR);
    }

    if(ctx->h3.conn) {
      size_t i;
      for(i = 0; i < ctx->h3.remote_ctrl_n; ++i) {
        result = cf_osslq_stream_recv(&ctx->h3.remote_ctrl[i], cf, data);
        if(result)
          goto out;
      }
    }

    if(ctx->h3.conn) {
      struct cf_ossq_recv_ctx rctx;

      DEBUGASSERT(data->multi);
      rctx.cf = cf;
      rctx.multi = data->multi;
      rctx.result = CURLE_OK;
      Curl_uint_hash_visit(&ctx->streams, cf_osslq_iter_recv, &rctx);
      result = rctx.result;
    }
  }

out:
    CURL_TRC_CF(data, cf, "progress_ingress -> %d", result);
    return result;
}

struct cf_ossq_fill_ctx {
  struct cf_osslq_ctx *ctx;
  struct Curl_multi *multi;
  size_t n;
};

static bool cf_osslq_collect_block_send(unsigned int mid, void *val,
                                        void *user_data)
{
  struct h3_proxy_stream_ctx *stream = val;
  struct cf_ossq_fill_ctx *fctx = user_data;
  struct cf_osslq_ctx *ctx = fctx->ctx;

  if(fctx->n >= ctx->items_max)  /* should not happen, prevent mayhem */
    return FALSE;

  if(stream && stream->s.ssl && stream->s.send_blocked) {
    struct Curl_easy *sdata = Curl_multi_get_easy(fctx->multi, mid);
    if(sdata) {
      ctx->poll_items[fctx->n].desc = SSL_as_poll_descriptor(stream->s.ssl);
      ctx->poll_items[fctx->n].events = SSL_POLL_EVENT_W;
      ctx->curl_items[fctx->n] = sdata;
      fctx->n++;
    }
  }
  return TRUE;
}

/* Iterate over all streams and check if blocked can be unblocked */
static CURLcode cf_osslq_check_and_unblock(struct Curl_cfilter *cf,
                                           struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = NULL;
    size_t poll_count;
  size_t result_count = 0;
  size_t idx_count = 0;
  CURLcode res = CURLE_OK;
  struct timeval timeout;
  void *tmpptr;

  if(ctx->h3.conn) {
    struct cf_ossq_fill_ctx fill_ctx;

    if(ctx->items_max < Curl_uint_hash_count(&ctx->streams)) {
      size_t nmax = Curl_uint_hash_count(&ctx->streams);
      ctx->items_max = 0;
      tmpptr = realloc(ctx->poll_items, nmax * sizeof(SSL_POLL_ITEM));
      if(!tmpptr) {
        free(ctx->poll_items);
        ctx->poll_items = NULL;
        res = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      ctx->poll_items = tmpptr;

      tmpptr = realloc(ctx->curl_items, nmax * sizeof(struct Curl_easy *));
      if(!tmpptr) {
        free(ctx->curl_items);
        ctx->curl_items = NULL;
        res = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      ctx->curl_items = tmpptr;
      ctx->items_max = nmax;
    }

    fill_ctx.ctx = ctx;
    fill_ctx.multi = data->multi;
    fill_ctx.n = 0;
    Curl_uint_hash_visit(&ctx->streams, cf_osslq_collect_block_send,
                          &fill_ctx);
    poll_count = fill_ctx.n;
    if(poll_count) {
      CURL_TRC_CF(data, cf, "polling %zu blocked streams", poll_count);

      memset(&timeout, 0, sizeof(struct timeval));
      res = CURLE_UNRECOVERABLE_POLL;
      if(!SSL_poll(ctx->poll_items, poll_count, sizeof(SSL_POLL_ITEM),
                    &timeout, 0, &result_count))
        goto out;

      res = CURLE_OK;

      for(idx_count = 0; idx_count < poll_count && result_count > 0;
            idx_count++) {
        if(ctx->poll_items[idx_count].revents & SSL_POLL_EVENT_W) {
          stream = H3_PROXY_STREAM_CTX(ctx, ctx->curl_items[idx_count]);
          DEBUGASSERT(stream); /* should still exist */
          if(stream) {
            nghttp3_conn_unblock_stream(ctx->h3.conn, stream->s.id);
            stream->s.send_blocked = FALSE;
            Curl_multi_mark_dirty(ctx->curl_items[idx_count]);
            CURL_TRC_CF(ctx->curl_items[idx_count], cf, "unblocked");
          }
          result_count--;
        }
      }
    }
  }

out:
  return res;
}

static CURLcode h3_send_streams(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  CURLcode result = CURLE_OK;

  if(!ctx->tls.ossl.ssl || !ctx->h3.conn)
    goto out;

  for(;;) {
    struct cf_osslq_stream *s = NULL;
    nghttp3_vec vec[16];
    nghttp3_ssize n, i;
    int64_t stream_id;
    size_t written;
    int eos, ok, rv;
    size_t total_len, acked_len = 0;
    bool blocked = FALSE, eos_written = FALSE;

    n = nghttp3_conn_writev_stream(ctx->h3.conn, &stream_id, &eos,
                                   vec, ARRAYSIZE(vec));
    if(n < 0) {
      failf(data, "nghttp3_conn_writev_stream returned error: %s",
            nghttp3_strerror((int)n));
      result = CURLE_SEND_ERROR;
      goto out;
    }
    if(stream_id < 0) {
      result = CURLE_OK;
      goto out;
    }

    /* Get the stream for this data */
    s = cf_osslq_get_qstream(cf, data, stream_id);
    if(!s) {
      failf(data, "nghttp3_conn_writev_stream gave unknown stream %"
                  FMT_PRId64, (curl_int64_t)stream_id);
      result = CURLE_SEND_ERROR;
      goto out;
    }
    /* Now write the data to the stream's SSL*, it may not all fit! */
    DEBUGASSERT(s->id == stream_id);
    for(i = 0, total_len = 0; i < n; ++i)
      total_len += vec[i].len;

    for(i = 0; (i < n) && !blocked; ++i) {
      /* Without stream->s.ssl, we closed that already, so
       * pretend the write did succeed. */
      uint64_t flags = (eos && ((i + 1) == n)) ? SSL_WRITE_FLAG_CONCLUDE : 0;
      if(stream_id == proxy_ctx->tunnel.stream_id)
        eos = 0;

      written = vec[i].len;
      ok = !s->ssl || SSL_write_ex2(s->ssl, vec[i].base, vec[i].len, flags,
                                    &written);
      if(ok) {
        /* As OpenSSL buffers the data, we count this as acknowledged
         * from nghttp3's point of view */
        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send %zu bytes to QUIC ok",
                    s->id, vec[i].len);
        acked_len += vec[i].len;
      }
      else {
        int detail = SSL_get_error(s->ssl, 0);
        switch(detail) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          /* QUIC blocked us from writing more */
          CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send %zu bytes to "
                                "QUIC blocked",
                      s->id, vec[i].len);
          written = 0;
          nghttp3_conn_block_stream(ctx->h3.conn, s->id);
          s->send_blocked = blocked = TRUE;
          break;
        default:
          failf(data, "[%" FMT_PRId64 "] send %zu bytes to QUIC, SSL error %d",
                s->id, vec[i].len, detail);
          result = cf_osslq_ssl_err(cf, data, detail, CURLE_HTTP3);
          goto out;
        }
      }
    }

    if(acked_len > 0 || (eos && !s->send_blocked)) {
      /* Since QUIC buffers the data written internally, we can tell
       * nghttp3 that it can move forward on it */
      ctx->q.last_io = curlx_now();
      rv = nghttp3_conn_add_write_offset(ctx->h3.conn, s->id, acked_len);
      if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
        failf(data, "nghttp3_conn_add_write_offset returned error: %s",
              nghttp3_strerror(rv));
        result = CURLE_SEND_ERROR;
        goto out;
      }
      rv = nghttp3_conn_add_ack_offset(ctx->h3.conn, s->id, acked_len);
      if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
        failf(data, "nghttp3_conn_add_ack_offset returned error: %s",
              nghttp3_strerror(rv));
        result = CURLE_SEND_ERROR;
        goto out;
      }
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] forwarded %zu/%zu h3 bytes "
                            "to QUIC, eos=%d",
                  s->id, acked_len, total_len, eos);
    }

    if(eos && !s->send_blocked && !eos_written) {
      /* wrote everything and H3 indicates end of stream */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] closing QUIC stream", s->id);
      SSL_stream_conclude(s->ssl, 0);
    }
  }

out:
  CURL_TRC_CF(data, cf, "h3_send_streams -> %d", result);
  return result;
}

static CURLcode proxy_h3_progress_egress_ossl(struct Curl_cfilter *cf,
                                              struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;

    if(!ctx->tls.ossl.ssl)
      goto out;

    ERR_clear_error();
    result = h3_send_streams(cf, data);
    if(result)
      goto out;

    if(!SSL_handle_events(ctx->tls.ossl.ssl)) {
      int detail = SSL_get_error(ctx->tls.ossl.ssl, 0);
      result = cf_osslq_ssl_err(cf, data, detail, CURLE_SEND_ERROR);
    }

    result = cf_osslq_check_and_unblock(cf, data);
  }

out:
  CURL_TRC_CF(data, cf, "progress_egress -> %d", result);
  return result;
}
#endif /* USE_OPENSSL_QUIC */

#ifdef USE_NGTCP2
/**
 * Read a network packet to send from ngtcp2 into `buf`.
 * Return number of bytes written or -1 with *err set.
 */
static CURLcode read_pkt_to_send(void *userp,
                                 unsigned char *buf, size_t buflen,
                                 size_t *pnread)
{
  struct pkt_io_ctx *x = userp;
  struct cf_h3_proxy_ctx *proxy_ctx = x->cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  nghttp3_vec vec[16];
  nghttp3_ssize veccnt;
  ngtcp2_ssize ndatalen;
  uint32_t flags;
  int64_t stream_id;
  int fin;
  ssize_t n;

  *pnread = 0;
  veccnt = 0;
  stream_id = -1;
  fin = 0;

  /* ngtcp2 may want to put several frames from different streams into
   * this packet. `NGTCP2_WRITE_STREAM_FLAG_MORE` tells it to do so.
   * When `NGTCP2_ERR_WRITE_MORE` is returned, we *need* to make
   * another iteration.
   * When ngtcp2 is happy (because it has no other frame that would fit
   * or it has nothing more to send), it returns the total length
   * of the assembled packet. This may be 0 if there was nothing to send. */
  for(;;) {

    if(ctx->h3conn && ngtcp2_conn_get_max_data_left(ctx->qconn)) {
      veccnt = nghttp3_conn_writev_stream(ctx->h3conn, &stream_id, &fin, vec,
                                          CURL_ARRAYSIZE(vec));
      if(veccnt < 0) {
        failf(x->data, "nghttp3_conn_writev_stream returned error: %s",
              nghttp3_strerror((int)veccnt));
        cf_ngtcp2_h3_err_set(x->cf, x->data, (int)veccnt);
        return CURLE_SEND_ERROR;
      }
    }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE |
            (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    n = ngtcp2_conn_writev_stream(ctx->qconn, &x->ps.path,
                                  NULL, buf, buflen,
                                  &ndatalen, flags, stream_id,
                                  (const ngtcp2_vec *)vec, veccnt, x->ts);
    if(n == 0) {
      /* nothing to send */
      return CURLE_AGAIN;
    }
    else if(n < 0) {
      switch(n) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
        struct h3_proxy_stream_ctx *stream = NULL;
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_block_stream(ctx->h3conn, stream_id);
        CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] block quic flow",
                    (curl_int64_t)stream_id);
        stream = cf_ngtcp2_get_stream(ctx, stream_id);
        if(stream) /* it might be not one of our h3 streams? */
          stream->quic_flow_blocked = TRUE;
        n = 0;
        break;
      }
      case NGTCP2_ERR_STREAM_SHUT_WR:
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_shutdown_stream_write(ctx->h3conn, stream_id);
        n = 0;
        break;
      case NGTCP2_ERR_WRITE_MORE:
        /* ngtcp2 wants to send more. update the flow of the stream whose data
         * is in the buffer and continue */
        DEBUGASSERT(ndatalen >= 0);
        n = 0;
        break;
      default:
        DEBUGASSERT(ndatalen == -1);
        failf(x->data, "ngtcp2_conn_writev_stream returned error: %s",
              ngtcp2_strerror((int)n));
        cf_ngtcp2_err_set(x->cf, x->data, (int)n);
        return CURLE_SEND_ERROR;
      }
    }

    if(ndatalen >= 0) {
      /* we add the amount of data bytes to the flow windows */
      int rv = nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, ndatalen);
      if(rv) {
        failf(x->data, "nghttp3_conn_add_write_offset returned error: %s",
              nghttp3_strerror(rv));
        return CURLE_SEND_ERROR;
      }
    }

    if(n > 0) {
      /* packet assembled, leave */
      *pnread = (size_t)n;
      return CURLE_OK;
    }
  }
}

static CURLcode proxy_h3_progress_egress_ngtcp2(struct Curl_cfilter *cf,
                                                struct Curl_easy *data,
                                                struct pkt_io_ctx *pktx)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  size_t nread;
  size_t max_payload_size, path_max_payload_size;
  size_t pktcnt = 0;
  size_t gsolen = 0;  /* this disables gso until we have a clue */
  size_t send_quantum;
  CURLcode curlcode;
  struct pkt_io_ctx local_pktx;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    pktx_update_time(pktx, cf);
    ngtcp2_path_storage_zero(&pktx->ps);
  }

  curlcode = vquic_flush(cf, data, &ctx->q);
  if(curlcode) {
    if(curlcode == CURLE_AGAIN) {
      Curl_expire(data, 1, EXPIRE_QUIC);
      return CURLE_OK;
    }
    return curlcode;
  }

  /* In UDP, there is a maximum theoretical packet payload length and
   * a minimum payload length that is "guaranteed" to work.
   * To detect if this minimum payload can be increased, ngtcp2 sends
   * now and then a packet payload larger than the minimum. It that
   * is ACKed by the peer, both parties know that it works and
   * the subsequent packets can use a larger one.
   * This is called PMTUD (Path Maximum Transmission Unit Discovery).
   * Since a PMTUD might be rejected right on send, we do not want it
   * be followed by other packets of lesser size. Because those would
   * also fail then. So, if we detect a PMTUD while buffering, we flush.
   */
  max_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(ctx->qconn);
  path_max_payload_size =
      ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
  send_quantum = ngtcp2_conn_get_send_quantum(ctx->qconn);
  CURL_TRC_CF(data, cf, "egress, collect and send packets, quantum=%zu",
              send_quantum);
  for(;;) {
    /* add the next packet to send, if any, to our buffer */
    curlcode = Curl_bufq_sipn(&ctx->q.sendbuf, max_payload_size,
                              read_pkt_to_send, pktx, &nread);
    if(curlcode == CURLE_AGAIN)
      break;
    else if(curlcode)
      return curlcode;
    else {
      size_t buflen = Curl_bufq_len(&ctx->q.sendbuf);
      if((buflen >= send_quantum) ||
         ((buflen + gsolen) >= ctx->q.sendbuf.chunk_size))
         break;
      DEBUGASSERT(nread > 0);
      ++pktcnt;
      if(pktcnt == 1) {
        /* first packet in buffer. This is either of a known, "good"
         * payload size or it is a PMTUD. We will see. */
        gsolen = nread;
      }
      else if(nread > gsolen ||
              (gsolen > path_max_payload_size && nread != gsolen)) {
        /* The just added packet is a PMTUD *or* the one(s) before the
         * just added were PMTUD and the last one is smaller.
         * Flush the buffer before the last add. */
        curlcode = vquic_send_tail_split(cf, data, &ctx->q,
                                         gsolen, nread, nread);
        if(curlcode) {
          if(curlcode == CURLE_AGAIN) {
            Curl_expire(data, 1, EXPIRE_QUIC);
            return CURLE_OK;
          }
          return curlcode;
        }
        pktcnt = 0;
      }
      else if(nread < gsolen) {
        /* Reached MAX_PKT_BURST *or*
         * the capacity of our buffer *or*
         * last add was shorter than the previous ones, flush */
        break;
      }
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* time to send */
    CURL_TRC_CF(data, cf, "egress, send collected %zu packets in %zu bytes",
                pktcnt, Curl_bufq_len(&ctx->q.sendbuf));
    curlcode = vquic_send(cf, data, &ctx->q, gsolen);
    if(curlcode) {
      if(curlcode == CURLE_AGAIN) {
        Curl_expire(data, 1, EXPIRE_QUIC);
        return CURLE_OK;
      }
      return curlcode;
    }
    pktx_update_time(pktx, cf);
    ngtcp2_conn_update_pkt_tx_time(ctx->qconn, pktx->ts);
  }
  return CURLE_OK;
}
#endif /* USE_NGTCP2 */

#ifdef USE_NGTCP2
static CURLcode cf_ngtcp2_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data, bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;
  pktx_init(&pktx, cf, data);

  if(!ctx->shutdown_started) {
    char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    ngtcp2_ssize nwritten;

    if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
      result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
      if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
        CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
        result = CURLE_OK;
        goto out;
      }
      else if(result) {
        CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
        *done = TRUE;
        goto out;
      }
    }

    DEBUGASSERT(Curl_bufq_is_empty(&ctx->q.sendbuf));
    ctx->shutdown_started = TRUE;
    nwritten = ngtcp2_conn_write_connection_close(
      ctx->qconn, NULL, /* path */
      NULL, /* pkt_info */
      (uint8_t *)buffer, sizeof(buffer),
      &ctx->last_error, pktx.ts);
    CURL_TRC_CF(data, cf, "start shutdown(err_type=%d, err_code=%"
                FMT_PRIu64 ") -> %d", ctx->last_error.type,
                (curl_uint64_t)ctx->last_error.error_code, (int)nwritten);
    /* there are cases listed in ngtcp2 documentation where this call
     * may fail. Since we are doing a connection shutdown as graceful
     * as we can, such an error is ignored here. */
    if(nwritten > 0) {
      /* Ignore amount written. sendbuf was empty and has always room for
       * NGTCP2_MAX_UDP_PAYLOAD_SIZE. It can only completely fail, in which
       * case `result` is set non zero. */
      size_t n;
      result = Curl_bufq_write(&ctx->q.sendbuf, (const unsigned char *)buffer,
                               (size_t)nwritten, &n);
      if(result) {
        CURL_TRC_CF(data, cf, "error %d adding shutdown packets to sendbuf, "
                    "aborting shutdown", result);
        goto out;
      }

      ctx->q.no_gso = TRUE;
      ctx->q.gsolen = (size_t)nwritten;
      ctx->q.split_len = 0;
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    CURL_TRC_CF(data, cf, "shutdown, flushing egress");
    result = vquic_flush(cf, data, &ctx->q);
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
      result = CURLE_OK;
      goto out;
    }
    else if(result) {
      CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
      *done = TRUE;
      goto out;
    }
  }

  if(Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* Sent everything off. ngtcp2 seems to have no support for graceful
     * shutdowns. So, we are done. */
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
    result = CURLE_OK;
  }
out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_ngtcp2_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  bool done;
  cf_ngtcp2_shutdown(cf, data, &done);
}

static void cf_ngtcp2_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  if(ctx && ctx->qconn) {
    cf_ngtcp2_conn_close(cf, data);
    cf_ngtcp2_ctx_close(ctx);
    CURL_TRC_CF(data, cf, "close");
  }
  cf->connected = FALSE;
  CF_DATA_RESTORE(cf, save);
}

static void cf_ngtcp2_stream_close(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_proxy_stream_ctx  *stream)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  DEBUGASSERT(data);
  DEBUGASSERT(stream);
  if(!stream->closed && ctx->qconn && ctx->h3conn) {
    CURLcode result;

    nghttp3_conn_set_stream_user_data(ctx->h3conn, stream->id, NULL);
    ngtcp2_conn_set_stream_user_data(ctx->qconn, stream->id, NULL);
    stream->closed = TRUE;
    (void)ngtcp2_conn_shutdown_stream(ctx->qconn, 0, stream->id,
                                      NGHTTP3_H3_REQUEST_CANCELLED);
    result = proxy_h3_progress_egress_ngtcp2(cf, data, NULL);
    if(result)
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cancel stream -> %d",
                  stream->id, result);
  }
}
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
static CURLcode check_and_set_expiry_ossl(struct Curl_cfilter *cf,
                                          struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  timediff_t timeoutms;

  struct timeval tv;
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    int is_infinite = 1;

    if(ctx->tls.ossl.ssl &&
        SSL_get_event_timeout(ctx->tls.ossl.ssl, &tv, &is_infinite) &&
        !is_infinite) {
      timeoutms = curlx_tvtoms(&tv);
      /* QUIC want to be called again latest at the returned timeout */
      if(timeoutms <= 0) {
        result = proxy_h3_progress_ingress_ossl(cf, data);
        if(result)
          goto out;
        result = proxy_h3_progress_egress_ossl(cf, data);
        if(result)
          goto out;
        if(SSL_get_event_timeout(ctx->tls.ossl.ssl, &tv, &is_infinite)) {
          timeoutms = curlx_tvtoms(&tv);
        }
      }
      if(!is_infinite) {
        Curl_expire(data, timeoutms, EXPIRE_QUIC);
        CURL_TRC_CF(data, cf, "QUIC expiry in %ldms", (long)timeoutms);
      }
    }
  }

out:
  return result;
}
#endif /* USE_OPENSSL_QUIC */

#ifdef USE_NGTCP2
/**
 * Connection maintenance like timeouts on packet ACKs etc. are done by us, not
 * the OS like for TCP. POLL events on the socket therefore are not
 * sufficient.
 * ngtcp2 tells us when it wants to be invoked again. We handle that via
 * the `Curl_expire()` mechanisms.
 */
static CURLcode check_and_set_expiry_ngtcp2(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            struct pkt_io_ctx *pktx)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;

  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    struct pkt_io_ctx local_pktx;
    ngtcp2_tstamp expiry;

    if(!pktx) {
      pktx_init(&local_pktx, cf, data);
      pktx = &local_pktx;
    }
    else {
      pktx_update_time(pktx, cf);
    }

    expiry = ngtcp2_conn_get_expiry(ctx->qconn);
    if(expiry != UINT64_MAX) {
      if(expiry <= pktx->ts) {
        CURLcode result;
        int rv = ngtcp2_conn_handle_expiry(ctx->qconn, pktx->ts);
        if(rv) {
          failf(data, "ngtcp2_conn_handle_expiry returned error: %s",
                ngtcp2_strerror(rv));
          cf_ngtcp2_err_set(cf, data, rv);
          return CURLE_SEND_ERROR;
        }
        result = proxy_h3_progress_ingress_ngtcp2(cf, data, pktx);
        if(result)
          return result;
        result = proxy_h3_progress_egress_ngtcp2(cf, data, pktx);
        if(result)
          return result;
        /* ask again, things might have changed */
        expiry = ngtcp2_conn_get_expiry(ctx->qconn);
      }

      if(expiry > pktx->ts) {
        ngtcp2_duration timeout = expiry - pktx->ts;
        if(timeout % NGTCP2_MILLISECONDS) {
          timeout += NGTCP2_MILLISECONDS;
        }
        Curl_expire(data, (timediff_t)(timeout / NGTCP2_MILLISECONDS),
                    EXPIRE_QUIC);
      }
    }
    return CURLE_OK;
  }
}
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
static CURLcode recv_closed_stream(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h3_proxy_stream_ctx *stream,
                                   size_t *pnread)
{
  (void)cf;
  *pnread = 0;
  if(stream->reset) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64 " reset by server",
          H3_STREAM_ID(stream));
    return data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64
          " was closed cleanly, but before getting"
          " all response header fields, treated as error",
          H3_STREAM_ID(stream));
    return CURLE_HTTP3;
  }
  return CURLE_OK;
}
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
static ssize_t recv_closed_stream(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_proxy_stream_ctx *stream,
                                  CURLcode *err)
{
  ssize_t nread = -1;

  (void)cf;
  if(stream->reset) {
    failf(data, "HTTP/3 stream %" FMT_PRId64 " reset by server", stream->id);
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    goto out;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    *err = CURLE_HTTP3;
    goto out;
  }
  *err = CURLE_OK;
  nread = 0;

out:
  return nread;
}
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_h3_proxy_send_ossl(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      const void *buf, size_t len, bool eos,
                                      size_t *pnwritten)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);

  *pnwritten = -1;

  if(proxy_ctx->tunnel.closed)
    return CURLE_SEND_ERROR;

  (void)eos; /* use to end stream */
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->tls.ossl.ssl);
  DEBUGASSERT(ctx->h3.conn);

  if(!stream) {
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] discarding data"
                            "on closed stream with response",
                  H3_STREAM_ID(stream));
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send_body(len=%zu) "
                          "-> stream closed",
                H3_STREAM_ID(stream), len);
    result = CURLE_HTTP3;
    goto out;
  }
  else {
    if(data->conn->bits.udp_tunnel_proxy) {
      struct dynbuf dyn;

      result = Curl_capsule_encap_udp_datagram(&dyn, buf, len);
      if(result)
        goto out;

      result = Curl_bufq_write(&stream->sendbuf,
                                 (const unsigned char *)curlx_dyn_ptr(&dyn),
                                 curlx_dyn_len(&dyn), pnwritten);
      curlx_dyn_free(&dyn);
    }
    else {
      result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_h3_proxy_send, add to "
                          "sendbuf(len=%zu) -> %zd, %d",
                H3_STREAM_ID(stream), len, *pnwritten, result);

    if(result) {
      goto out;
    }
    stream->upload_left += *pnwritten;

    (void)nghttp3_conn_resume_stream(ctx->h3.conn, H3_STREAM_ID(stream));

  }

  result = Curl_1st_err(result, proxy_h3_progress_ingress_ossl(cf, data));

  result = Curl_1st_err(result, proxy_h3_progress_egress_ossl(cf, data));

out:
  result = Curl_1st_err(result, check_and_set_expiry_ossl(cf, data));

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_h3_proxy_send(len=%zu)"
                        " -> %zd, %d",
              stream ? H3_STREAM_ID(stream) : -1, len, *pnwritten, result);

  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
static CURLcode cf_h3_proxy_send_ngtcp2(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        const void *buf, size_t len, bool eos,
                                        size_t *pnwritten)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  pktx_init(&pktx, cf, data);
  *pnwritten = 0;

  if(proxy_ctx->tunnel.closed)
    return CURLE_SEND_ERROR;

  /* handshake verification failed in callback, do not send anything */
  if(ctx->tls_vrfy_result) {
    result = ctx->tls_vrfy_result;
    goto denied;
  }

  (void)eos; /* use for stream EOF and block handling */

  if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] discarding data"
                  "on closed stream with response", stream->id);
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send_body(len=%zu) "
                "-> stream closed", stream->id, len);
    result = CURLE_HTTP3;
    goto out;
  }
  else {
    if(data->conn->bits.udp_tunnel_proxy) {
      struct dynbuf dyn;

      result = Curl_capsule_encap_udp_datagram(&dyn, buf, len);
      if(result)
        goto out;

      result = Curl_bufq_write(&stream->sendbuf,
                                 (const unsigned char *)curlx_dyn_ptr(&dyn),
                                 curlx_dyn_len(&dyn), pnwritten);
      curlx_dyn_free(&dyn);
    }
    else {
      result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send, add to "
                "sendbuf(len=%zu) -> %d, %zu",
                stream->id, len, result, *pnwritten);
    if(result)
      goto out;
    (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
  }

  if(*pnwritten > 0 && !ctx->tls_handshake_complete && ctx->use_earlydata)
    ctx->earlydata_skip += *pnwritten;

  DEBUGASSERT(!result);
  result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);

out:
  result = Curl_1st_err(result, check_and_set_expiry_ngtcp2(cf, data, &pktx));
denied:
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, result, *pnwritten);
  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_NGTCP2 */

static CURLcode cf_h3_proxy_send(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 const void *buf, size_t len, bool eos,
                                 size_t *pnwritten)
{
#ifdef USE_OPENSSL_QUIC
  return cf_h3_proxy_send_ossl(cf, data, buf, len, eos, pnwritten);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf_h3_proxy_send_ngtcp2(cf, data, buf, len, eos, pnwritten);
#endif /* USE_NGTCP2 */
}

static ssize_t process_udp_capsule(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   char *buf, size_t len, CURLcode *err)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;

  return Curl_capsule_process_udp(cf, data, &proxy_ctx->inbufq, buf, len, err);
}

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_h3_proxy_recv_ossl(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      char *buf, size_t len, size_t *pnread)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);

  *pnread = 0;

  if(proxy_ctx->tunnel.closed)
    return CURLE_RECV_ERROR;

  (void)ctx;
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->tls.ossl.ssl);
  DEBUGASSERT(ctx->h3.conn);

  if(!stream) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(!data->conn->bits.udp_tunnel_proxy) {
    if(!Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
      result = Curl_bufq_cread(&proxy_ctx->inbufq,
                              buf, len, pnread);
      if(result)
        goto out;
    }
  }

  result = Curl_1st_err(result, proxy_h3_progress_ingress_ossl(cf, data));
  if(result)
    goto out;

  if(data->conn->bits.udp_tunnel_proxy) {
    if(Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
      /* No data to process */
      result = CURLE_AGAIN;
      goto out;
    }

    if(proxy_ctx->osslq_ctx) {
      *pnread = process_udp_capsule(cf, data, buf, len, &result);
    }
    goto out;
  }

  /* recvbuf had nothing before, maybe after progressing ingress? */
  if(!*pnread && !Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
    result = Curl_bufq_cread(&proxy_ctx->inbufq,
                             buf, len, pnread);
    if(result) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read recvbuf(len=%zu) "
                            "-> %zd, %d",
                  H3_STREAM_ID(stream), len, *pnread, result);
      goto out;
    }
  }

  if(*pnread) {
    Curl_multi_mark_dirty(data);
  }
  else {
    if(stream->closed) {
      result = recv_closed_stream(cf, data, stream, pnread);
      goto out;
    }
    result = CURLE_AGAIN;
  }

out:
  result = Curl_1st_err(result, proxy_h3_progress_egress_ossl(cf, data));
  result = Curl_1st_err(result, check_and_set_expiry_ossl(cf, data));

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_h3_proxy_recv(len=%zu) -> "
                        " %zd, %d",
              stream ? H3_STREAM_ID(stream) : -1,
              len, *pnread, result);
  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
/* incoming data frames on the h3 stream */
static CURLcode cf_h3_proxy_recv_ngtcp2(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        char *buf, size_t len, size_t *pnread)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  (void)ctx;
  (void)buf;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  *pnread = 0;

  /* handshake verification failed in callback, do not recv anything */
  if(ctx->tls_vrfy_result) {
    result = ctx->tls_vrfy_result;
    goto denied;
  }

  pktx_init(&pktx, cf, data);

  if(!stream || ctx->shutdown_started) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(proxy_h3_progress_ingress_ngtcp2(cf, data, &pktx)) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(data->conn->bits.udp_tunnel_proxy) {
    if(Curl_bufq_is_empty(&proxy_ctx->inbufq)) {
      /* No data to process */
      result = CURLE_AGAIN;
      goto out;
    }

    *pnread = process_udp_capsule(cf, data, buf, len, &result);
    goto out;
  }

  if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] xfer write failed", stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    result = stream->xfer_result;
    goto out;
  }
  else if(stream->closed) {
    ssize_t nread = recv_closed_stream(cf, data, stream, &result);
    if(nread > 0)
      *pnread = (size_t)nread;
    goto out;
  }
  result = CURLE_AGAIN;

out:
  result = Curl_1st_err(result,
                        proxy_h3_progress_egress_ngtcp2(cf, data, &pktx));
  result = Curl_1st_err(result, check_and_set_expiry_ngtcp2(cf, data, &pktx));
denied:
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_recv(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, result, *pnread);
  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_NGTCP2 */

static CURLcode cf_h3_proxy_recv(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 char *buf, size_t len, size_t *pnread)
{
#ifdef USE_OPENSSL_QUIC
  return cf_h3_proxy_recv_ossl(cf, data, buf, len, pnread);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf_h3_proxy_recv_ngtcp2(cf, data, buf, len, pnread);
#endif /* USE_NGTCP2 */
}

static void proxy_h3_submit(curl_int64_t *pstream_id,
                            struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct httpreq *req,
                            CURLcode *err)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct h3_proxy_stream_ctx *stream = NULL;

  struct dynhds h2_headers;
  nghttp3_nv *nva = NULL;
  size_t nheader;

  int rc = 0;
  unsigned int i;
  nghttp3_data_reader reader;
  nghttp3_data_reader *preader = NULL;

  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);
  *err = Curl_http_req_to_h2(&h2_headers, req, data);
  if(*err)
    goto out;

  *err = h3_data_setup(cf, data);
  if(*err)
    goto out;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
#endif /* USE_NGTCP2 */

  DEBUGASSERT(stream);
  if(!stream) {
    *err = CURLE_FAILED_INIT;
    goto out;
  }

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(nghttp3_nv) * nheader);
  if(!nva) {
    *err = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < nheader; ++i) {
    struct dynhds_entry *e = Curl_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].namelen = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].valuelen = e->valuelen;
    nva[i].flags = NGHTTP3_NV_FLAG_NONE;
  }

  /* Open a bidirectional stream */
#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    DEBUGASSERT(stream->s.id == -1);
    *err = cf_osslq_stream_open(&stream->s, ctx->tls.ossl.ssl, 0,
                                &ctx->stream_bufcp, data);
    if(*err) {
      failf(data, "cannot get bidi streams");
      *err = CURLE_SEND_ERROR;
      goto out;
    }
    stream->s.tunnel_stream = TRUE;
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    int64_t sid;
    int rv;
    DEBUGASSERT(stream->id == -1);
    rv = ngtcp2_conn_open_bidi_stream(ctx->qconn, &sid, data);
    if(rv) {
      failf(data, "cannot get bidi streams: %s", ngtcp2_strerror(rv));
      *err = CURLE_SEND_ERROR;
      goto out;
    }
    stream->id = (curl_int64_t)sid;
  }
#endif /* USE_NGTCP2 */

  /* this is a CONNECT request, there is no request body */
  stream->upload_left = 0;
  stream->send_closed = 0;
  reader.read_data = cb_h3_read_data_for_tunnel_stream;
  preader = &reader;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    rc = nghttp3_conn_submit_request(ctx->h3.conn, H3_STREAM_ID(stream),
                                     nva, nheader, preader, data);
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    rc = nghttp3_conn_submit_request(ctx->h3conn, H3_STREAM_ID(stream),
                                     nva, nheader, preader, data);
  }
#endif /* USE_NGTCP2 */

  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send, "
                            "connection is closing",
                  H3_STREAM_ID(stream));
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send -> %d (%s)",
                  H3_STREAM_ID(stream), rc, nghttp3_strerror(rc));
      break;
    }
    *err = CURLE_SEND_ERROR;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    CURL_TRC_CF(data, cf, "[H3-PROXY] [%" FMT_PRId64 "] OPENED stream "
                "for %s", H3_STREAM_ID(stream), data->state.url);
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  if(*err == CURLE_OK) {
    *pstream_id = H3_STREAM_ID(stream);
  }
}

static bool cf_h3_proxy_is_alive(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *input_pending)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  bool alive = FALSE;

  *input_pending = FALSE;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    if(!ctx->tls.ossl.ssl)
      goto out;

#ifdef SSL_VALUE_QUIC_IDLE_TIMEOUT
    /* Added in OpenSSL v3.3.x */
    {
      timediff_t idletime;
      uint64_t idle_ms = 0;
      if(!SSL_get_value_uint(ctx->tls.ossl.ssl,
                             SSL_VALUE_CLASS_FEATURE_NEGOTIATED,
                             SSL_VALUE_QUIC_IDLE_TIMEOUT, &idle_ms)) {
        CURL_TRC_CF(data, cf, "error getting negotiated idle timeout, "
                    "assume connection is dead.");
        goto out;
      }
      CURL_TRC_CF(data, cf, "negotiated idle timeout: %" FMT_PRIu64 "ms",
                  (curl_uint64_t)idle_ms);
      idletime = curlx_timediff(curlx_now(), ctx->q.last_io);
      if(idle_ms && idletime > 0 && (uint64_t)idletime > idle_ms)
        goto out;
    }
#endif /* SSL_VALUE_QUIC_IDLE_TIMEOUT */
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    const ngtcp2_transport_params *rp;
    if(!ctx->qconn || ctx->shutdown_started)
      goto out;

    /* We do not announce a max idle timeout, but when the peer does
    * it will close the connection when it expires. */
    rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
    if(rp && rp->max_idle_timeout) {
      timediff_t idletime_ms = curlx_timediff(curlx_now(), ctx->q.last_io);
      if(idletime_ms > 0) {
        uint64_t max_idle_ms =
          (uint64_t)(rp->max_idle_timeout / NGTCP2_MILLISECONDS);
        if((uint64_t)idletime_ms > max_idle_ms)
          goto out;
      }
    }
  }
#endif /* USE_NGTCP2 */

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    goto out;

  alive = TRUE;
  if(*input_pending) {
    CURLcode result;
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
#ifdef USE_OPENSSL_QUIC
    result = proxy_h3_progress_ingress_ossl(cf, data);
#endif
#ifdef USE_NGTCP2
    result = proxy_h3_progress_ingress_ngtcp2(cf, data, NULL);
#endif
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result ? FALSE : TRUE;
  }

out:
  return alive;
}

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_osslq_proxy_query(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   int query, int *pres1, void *pres2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT:
  {
#ifdef SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL
    /* Added in OpenSSL v3.3.x */
    uint64_t v;
    if(ctx->tls.ossl.ssl &&
       !SSL_get_value_uint(ctx->tls.ossl.ssl, SSL_VALUE_CLASS_GENERIC,
                           SSL_VALUE_QUIC_STREAM_BIDI_LOCAL_AVAIL, &v)) {
      CURL_TRC_CF(data, cf, "error getting available local bidi streams");
      return CURLE_HTTP3;
    }
    /* we report avail + in_use */
    v += CONN_INUSE(cf->conn);
    *pres1 = (v > INT_MAX) ? INT_MAX : (int)v;
#else
    *pres1 = 100;
#endif
    CURL_TRC_CF(data, cf, "query max_conncurrent -> %d", *pres1);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->got_first_byte) {
      timediff_t ms = curlx_timediff(ctx->first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT:
  {
    struct curltime *when = pres2;
    if(ctx->got_first_byte)
      *when = ctx->first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT:
  {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HOST_PORT:
    *pres1 = (int)cf->conn->http_proxy.port;
    *((const char **)pres2) = cf->conn->http_proxy.host.name;
    return CURLE_OK;
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = cf->connected ? "h3" : NULL;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 31;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO: {
    struct curl_tlssessioninfo *info = pres2;
    if(Curl_vquic_tls_get_ssl_info(&ctx->tls,
                (query == CF_QUERY_SSL_CTX_INFO), info))
      return CURLE_OK;
    break;
  }
  default:
    break;
  }
  CF_DATA_RESTORE(cf, save);
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static CURLcode cf_osslq_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct easy_pollset *ps)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);

  if(!ctx || !ctx->tls.ossl.ssl) {
    /* NOP */
  }
  else if(!cf->connected) {
    result = Curl_pollset_set(data, ps, ctx->q.sockfd,
                              SSL_net_read_desired(ctx->tls.ossl.ssl),
                              SSL_net_write_desired(ctx->tls.ossl.ssl));
  }
  else {
    bool want_recv, want_send;
    Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
    if(want_recv || want_send) {
      result = Curl_pollset_set(data, ps, ctx->q.sockfd,
                                SSL_net_read_desired(ctx->tls.ossl.ssl),
                                SSL_net_write_desired(ctx->tls.ossl.ssl));
    }
    else if(ctx->need_recv || ctx->need_send) {
      result = Curl_pollset_set(data, ps, ctx->q.sockfd,
                                ctx->need_recv, ctx->need_send);
    }
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
static CURLcode cf_ngtcp2_proxy_query(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      int query, int *pres1, void *pres2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  struct cf_call_data save;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    DEBUGASSERT(pres1);
    CF_DATA_SAVE(save, cf, data);
    /* Set after transport params arrived and continually updated
     * by callback. QUIC counts the number over the lifetime of the
     * connection, ever increasing.
     * We count the *open* transfers plus the budget for new ones. */
    if(!ctx->qconn || ctx->shutdown_started) {
      *pres1 = 0;
    }
    else if(ctx->max_bidi_streams) {
      uint64_t avail_bidi_streams = 0;
      uint64_t max_streams = CONN_ATTACHED(cf->conn);
      if(ctx->max_bidi_streams > ctx->used_bidi_streams)
        avail_bidi_streams = ctx->max_bidi_streams - ctx->used_bidi_streams;
      max_streams += avail_bidi_streams;
      *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    }
    else  /* transport params not arrived yet? take our default. */
      *pres1 = (int)Curl_multi_max_concurrent_streams(data->multi);
    CURL_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%u in use)",
                cf->conn->connection_id, *pres1, CONN_ATTACHED(cf->conn));
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->q.got_first_byte) {
      timediff_t ms = curlx_timediff(ctx->q.first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->q.got_first_byte)
      *when = ctx->q.first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 30;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO: {
    struct curl_tlssessioninfo *info = pres2;
    if(Curl_vquic_tls_get_ssl_info(&ctx->tls,
                                   (query == CF_QUERY_SSL_CTX_INFO), info))
      return CURLE_OK;
    break;
  }
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = cf->connected ? "h3" : NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static CURLcode cf_ngtcp2_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                               struct Curl_easy *data,
                                               struct easy_pollset *ps)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  bool want_recv, want_send;
  CURLcode result = CURLE_OK;

  if(!ctx->qconn)
    return CURLE_OK;

  Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
  if(!want_send && !Curl_bufq_is_empty(&ctx->q.sendbuf))
    want_send = TRUE;

  if(want_recv || want_send) {
    struct h3_proxy_stream_ctx *stream = H3_PROXY_STREAM_CTX(ctx, data);
    struct cf_call_data save;
    bool c_exhaust, s_exhaust;

    CF_DATA_SAVE(save, cf, data);
    c_exhaust = want_send && (!ngtcp2_conn_get_cwnd_left(ctx->qconn) ||
                !ngtcp2_conn_get_max_data_left(ctx->qconn));
    s_exhaust = want_send && stream && H3_STREAM_ID(stream) >= 0 &&
                stream->quic_flow_blocked;
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                 !Curl_bufq_is_empty(&ctx->q.sendbuf);

    result = Curl_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
  return result;
}
#endif /* USE_NGTCP2 */

static CURLcode cf_h3_proxy_query(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   int query, int *pres1, void *pres2)
{
#ifdef USE_OPENSSL_QUIC
  return cf_osslq_proxy_query(cf, data, query, pres1, pres2);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf_ngtcp2_proxy_query(cf, data, query, pres1, pres2);
#endif /* USE_NGTCP2 */
}

static CURLcode cf_h3_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct easy_pollset *ps)
{
#ifdef USE_OPENSSL_QUIC
  return cf_osslq_proxy_adjust_pollset(cf, data, ps);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf_ngtcp2_proxy_adjust_pollset(cf, data, ps);
#endif /* USE_NGTCP2 */
}

static bool cf_h3_proxy_data_pending(struct Curl_cfilter *cf,
                                     const struct Curl_easy *data)
{
#ifdef USE_OPENSSL_QUIC
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  const struct h3_proxy_stream_ctx *stream = NULL;
  (void)cf;

  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
  }
  return stream && !Curl_bufq_is_empty(&stream->recvbuf);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf->next ?
    cf->next->cft->has_data_pending(cf->next, data) : FALSE;
#endif /* USE_NGTCP2 */
}

#ifdef USE_NGTCP2
static CURLcode cf_ngtcp2_proxy_tls_ctx_setup(struct Curl_cfilter *cf,
                                              struct Curl_easy *data,
                                              void *user_data)
{

#ifdef USE_OPENSSL
  struct curl_tls_ctx *ctx = user_data;
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
  if(ngtcp2_crypto_boringssl_configure_client_context(ctx->ossl.ssl_ctx)
     != 0) {
    failf(data, "ngtcp2_crypto_boringssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#elif defined(OPENSSL_QUIC_API2)
  /* nothing to do */
  (void)ctx;
#else
  if(ngtcp2_crypto_quictls_configure_client_context(ctx->ossl.ssl_ctx) != 0) {
    failf(data, "ngtcp2_crypto_quictls_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#endif /* !OPENSSL_IS_BORINGSSL && !OPENSSL_IS_AWSLC */
#else
  #error "ngtcp2 TLS backend not configured"
#endif

  (void)cf;
  (void)data;
  return CURLE_OK;
}

static CURLcode cf_ngtcp2_on_session_reuse(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct alpn_spec *alpns,
                                           struct Curl_ssl_session *scs,
                                           bool *do_early_data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
  CURLcode result = CURLE_OK;

  *do_early_data = FALSE;
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA)
  ctx->earlydata_max = scs->earlydata_max;
#endif
#ifdef USE_GNUTLS
  ctx->earlydata_max =
    gnutls_record_get_max_early_data_size(ctx->tls.gtls.session);
#endif
#ifdef USE_WOLFSSL
#ifdef WOLFSSL_EARLY_DATA
  ctx->earlydata_max = scs->earlydata_max;
#else
  ctx->earlydata_max = 0;
#endif /* WOLFSSL_EARLY_DATA */
#endif
#if defined(USE_GNUTLS) || defined(USE_WOLFSSL) || \
    (defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA))
  if((!ctx->earlydata_max)) {
    CURL_TRC_CF(data, cf, "SSL session does not allow earlydata");
  }
  else if(!Curl_alpn_contains_proto(alpns, scs->alpn)) {
    CURL_TRC_CF(data, cf, "SSL session from different ALPN, no early data");
  }
  else if(!scs->quic_tp || !scs->quic_tp_len) {
    CURL_TRC_CF(data, cf, "no 0RTT transport parameters, no early data, ");
  }
  else {
    int rv;
    rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
      ctx->qconn, (const uint8_t *)scs->quic_tp, scs->quic_tp_len);
    if(rv)
      CURL_TRC_CF(data, cf, "no early data, failed to set 0RTT transport "
                  "parameters: %s", ngtcp2_strerror(rv));
    else {
      infof(data, "SSL session allows %zu bytes of early data, "
            "reusing ALPN '%s'", ctx->earlydata_max, scs->alpn);
      result = cf_ngtcp2_h3conn_init(cf, data);
      if(!result) {
        ctx->use_earlydata = TRUE;
        cf->connected = TRUE;
        *do_early_data = TRUE;
      }
    }
  }
#else /* not supported in the TLS backend */
  (void)data;
  (void)ctx;
  (void)scs;
  (void)alpns;
#endif
  return result;
}

static CURLcode cf_ngtcp2_proxy_ctx_init(struct Curl_cfilter *cf,
                                         struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_ngtcp2_ctx *ctx = NULL;
  int rc;
  int rv;
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int qfd;
  static const struct alpn_spec ALPN_SPEC_H3 = {{ "h3", "h3-29" }, 2};
  struct pkt_io_ctx pktx;

  ctx = calloc(1, sizeof(struct cf_ngtcp2_ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_ngtcp2_ctx_init(ctx);

  memset(&proxy_ctx->tunnel, 0, sizeof(proxy_ctx->tunnel));

  Curl_bufq_init(&proxy_ctx->inbufq, PROXY_H3_STREAM_CHUNK_SIZE,
                 H3_TUNNEL_RECV_CHUNKS);

  if(tunnel_stream_init(cf, &proxy_ctx->tunnel))
    goto out;

  DEBUGASSERT(ctx->initialized);
  ctx->started_at = curlx_now();

  result = CURLE_QUIC_CONNECT_ERROR;
  if(Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL))
    goto out;
  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                   &ctx->q.local_addrlen);
  if(rv == -1)
    goto out;

  ngtcp2_addr_init(&ctx->connected_path.local,
                   (struct sockaddr *)&ctx->q.local_addr,
                   ctx->q.local_addrlen);
  ngtcp2_addr_init(&ctx->connected_path.remote,
                   &sockaddr->curl_sa_addr, (socklen_t)sockaddr->addrlen);

  rc = ngtcp2_conn_client_new(&ctx->qconn, &ctx->dcid, &ctx->scid,
                              &ctx->connected_path,
                              NGTCP2_PROTO_VER_V1, &ngtcp2_proxy_callbacks,
                              &ctx->settings, &ctx->transport_params,
                              Curl_ngtcp2_mem(), cf);
  if(rc) {
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }

  ctx->conn_ref.get_conn = get_conn;
  ctx->conn_ref.user_data = cf;

  ctx->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  ctx->scid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->scid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  (void)Curl_qlogdir(data, ctx->scid.data, NGTCP2_MAX_CIDLEN, &qfd);
  pktx_init(&pktx, cf, data);

  ctx->qlogfd = qfd; /* -1 if failure above */
  quic_settings_proxy(ctx, data, &pktx);

  result = vquic_ctx_init(&ctx->q);
  if(result)
    return result;

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer, &ALPN_SPEC_H3,
                               cf_ngtcp2_proxy_tls_ctx_setup, &ctx->tls,
                               &ctx->conn_ref, NULL);
  if(result)
    goto out;

#if defined(USE_OPENSSL) && defined(OPENSSL_QUIC_API2)
  if(ngtcp2_crypto_ossl_ctx_new(&ctx->ossl_ctx, ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_ctx_new failed");
    result = CURLE_FAILED_INIT;
    goto out;
  }
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->ossl_ctx);
  if(ngtcp2_crypto_ossl_configure_client_session(ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_configure_client_session failed");
    result = CURLE_FAILED_INIT;
    goto out;
  }
#elif defined(USE_OPENSSL)
  SSL_set_quic_use_legacy_codepoint(ctx->tls.ossl.ssl, 0);
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.ossl.ssl);
#else
  #error "ngtcp2 TLS backend not defined"
#endif

  ngtcp2_ccerr_default(&ctx->last_error);

  proxy_ctx->ngtcp2_ctx = ctx;
  proxy_ctx->partial_read = FALSE;
  proxy_ctx->connected = FALSE;

out:
  if(result) {
    if(ctx)
      cf_ngtcp2_ctx_free(ctx);
  }
  CURL_TRC_CF(data, cf, "QUIC tls init -> %d", result);
  CURL_TRC_CF(data, cf, "[0] init ngtcp2 proxy ctx -> %d", result);
  return result;
}
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_osslq_proxy_ctx_init(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_osslq_ctx *ctx;
  int rv;
  CURLcode result = CURLE_OK;
  const struct Curl_sockaddr_ex *peer_addr = NULL;
  BIO *bio = NULL;
  BIO_ADDR *baddr = NULL;
  static const struct alpn_spec ALPN_SPEC_H3 = {
    { "h3" }, 1
  };

  ctx = calloc(1, sizeof(struct cf_osslq_ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_osslq_ctx_init(ctx);

  memset(&proxy_ctx->tunnel, 0, sizeof(proxy_ctx->tunnel));

  Curl_bufq_init(&proxy_ctx->inbufq, PROXY_H3_STREAM_CHUNK_SIZE,
                 H3_TUNNEL_RECV_CHUNKS);

  if(tunnel_stream_init(cf, &proxy_ctx->tunnel))
    goto out;

  DEBUGASSERT(ctx->initialized);

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer,
                               &ALPN_SPEC_H3, NULL, NULL, NULL, NULL);
  if(result)
    goto out;

  result = vquic_ctx_init(&ctx->q);
  if(result)
    goto out;

  result = CURLE_QUIC_CONNECT_ERROR;
  if(Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &peer_addr, NULL) ||
     !peer_addr)
    goto out;

  ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
  rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                  &ctx->q.local_addrlen);
  if(rv == -1)
    goto out;

  result = make_bio_addr(&baddr, peer_addr);
  if(result) {
    failf(data, "error creating BIO_ADDR from sockaddr");
    goto out;
  }
/* Type conversions, see #12861: OpenSSL wants an `int`, but on 64-bit
  * Win32 systems, Microsoft defines SOCKET as `unsigned long long`.
*/
#if defined(_WIN32) && !defined(__LWIP_OPT_H__) && !defined(LWIP_HDR_OPT_H)
  if(ctx->q.sockfd > INT_MAX) {
    failf(data, "Windows socket identifier larger than MAX_INT, "
          "unable to set in OpenSSL dgram API.");
    result = CURLE_QUIC_CONNECT_ERROR;
    goto out;
  }
  bio = BIO_new_dgram((int)ctx->q.sockfd, BIO_NOCLOSE);
#else
  bio = BIO_new_dgram(ctx->q.sockfd, BIO_NOCLOSE);
#endif
  if(!bio) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  if(!SSL_set1_initial_peer_addr(ctx->tls.ossl.ssl, baddr)) {
    failf(data, "failed to set the initial peer address");
    result = CURLE_FAILED_INIT;
    goto out;
  }
  if(!SSL_set_blocking_mode(ctx->tls.ossl.ssl, 0)) {
    failf(data, "failed to turn off blocking mode");
    result = CURLE_FAILED_INIT;
    goto out;
  }

  SSL_set_bio(ctx->tls.ossl.ssl, bio, bio);
  bio = NULL;
  SSL_set_connect_state(ctx->tls.ossl.ssl);
  SSL_set_incoming_stream_policy(ctx->tls.ossl.ssl,
                                  SSL_INCOMING_STREAM_POLICY_ACCEPT, 0);
  /* from our side, there is no idle timeout */
  SSL_set_value_uint(ctx->tls.ossl.ssl,
    SSL_VALUE_CLASS_FEATURE_REQUEST, SSL_VALUE_QUIC_IDLE_TIMEOUT, 0);
  /* setup the H3 things on top of the QUIC connection */
  result = cf_osslq_h3conn_init(ctx, ctx->tls.ossl.ssl, cf);
  proxy_ctx->osslq_ctx = ctx;
  proxy_ctx->partial_read = FALSE;
  proxy_ctx->connected = FALSE;

out:
  if(bio)
    BIO_free(bio);
  if(baddr)
    BIO_ADDR_free(baddr);
  CURL_TRC_CF(data, cf, "QUIC tls init -> %d", result);
  CURL_TRC_CF(data, cf, "[0] init osslq proxy ctx -> %d", result);
  return result;
}
#endif /* USE_OPENSSL_QUIC */

static CURLcode cf_h3_proxy_ctx_init(struct Curl_cfilter *cf,
                                     struct Curl_easy *data)
{
#ifdef USE_OPENSSL_QUIC
  return cf_osslq_proxy_ctx_init(cf, data);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf_ngtcp2_proxy_ctx_init(cf, data);
#endif /* USE_NGTCP2 */
}

static CURLcode submit_CONNECT(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct tunnel_stream *ts)
{
  CURLcode result;
  struct httpreq *req = NULL;

  if(cf->conn->bits.udp_tunnel_proxy) {
    result = Curl_http_proxy_create_CONNECTUDP(&req, cf, data, 3);
  }
  else {
    result = Curl_http_proxy_create_CONNECT(&req, cf, data, 3);
  }
  if(result)
    goto out;
  result = Curl_creader_set_null(data);
  if(result)
    goto out;

  if(cf->conn->bits.udp_tunnel_proxy)
    infof(data, "Establishing HTTP/3 proxy UDP tunnel to %s:%s",
                        data->state.up.hostname, data->state.up.port);
  else
    infof(data, "Establishing HTTP/3 proxy tunnel to %s", req->authority);

  proxy_h3_submit(&ts->stream_id, cf, data, req, &result);

out:
  if(req)
    Curl_http_req_free(req);
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  return result;
}

static CURLcode
inspect_response(struct Curl_cfilter *cf,
                 struct Curl_easy *data,
                 struct tunnel_stream *ts)
{
  CURLcode result = CURLE_OK;
  struct dynhds_entry *auth_reply = NULL;
  struct dynhds_entry *capsule_protocol = NULL;
  size_t i, header_count;
  (void)cf;

  DEBUGASSERT(ts->resp);

  /* Log all response headers */
  if(cf->conn->bits.udp_tunnel_proxy)
    infof(data, "CONNECT-UDP Response Status %d", ts->resp->status);
  else
    infof(data, "CONNECT Response Status %d", ts->resp->status);
  header_count = Curl_dynhds_count(&ts->resp->headers);
  infof(data, "Response Headers (%zu total):", header_count);
  for(i = 0; i < header_count; i++) {
    struct dynhds_entry *entry = Curl_dynhds_getn(&ts->resp->headers, i);
    if(entry)
      infof(data, "  %s: %s", entry->name, entry->value);
  }

  if(cf->conn->bits.udp_tunnel_proxy) {
    if(ts->resp->status == 200) {
      capsule_protocol = Curl_dynhds_cget(&ts->resp->headers,
                                          "capsule-protocol");
      if(capsule_protocol) {
        if(strncmp(capsule_protocol->value, "?1", 2) == 0) {
          CURL_TRC_CF(data, cf, "CONNECT-UDP tunnel established, "
                    "response %d", ts->resp->status);
          h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
          return CURLE_OK;
        }
      }
      else {
        /* NOTE proxies may not set capsule protocol in the headers */
        CURL_TRC_CF(data, cf, "CONNECT-UDP tunnel established, response %d"
                    "but no capsule-protocol header found", ts->resp->status);
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
        return CURLE_OK;
      }
    }
    else {
        CURL_TRC_CF(data, cf, "Failed to establish CONNECT-UDP tunnel, "
                "response %d", ts->resp->status);
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
        return CURLE_RECV_ERROR;
    }
  }
  else {
    if(ts->resp->status / 100 == 2) {
      CURL_TRC_CF(data, cf, "CONNECT tunnel established, response %d",
                  ts->resp->status);
      h3_tunnel_go_state(cf, ts, H3_TUNNEL_ESTABLISHED, data);
      return CURLE_OK;
    }

    if(ts->resp->status == 401) {
      auth_reply = Curl_dynhds_cget(&ts->resp->headers, "WWW-Authenticate");
    }
    else if(ts->resp->status == 407) {
      auth_reply = Curl_dynhds_cget(&ts->resp->headers, "Proxy-Authenticate");
    }

    if(auth_reply) {
      CURL_TRC_CF(data, cf, "[0] CONNECT: fwd auth header '%s'",
                  auth_reply->value);
      result = Curl_http_input_auth(data, ts->resp->status == 407,
                                    auth_reply->value);
      if(result)
        return result;
      if(data->req.newurl) {
        /* Indicator that we should try again */
        Curl_safefree(data->req.newurl);
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_INIT, data);
        return CURLE_OK;
      }
    }
  }

  /* Seems to have failed */
  return CURLE_RECV_ERROR;
}

#ifdef USE_NGTCP2
static CURLcode cf_connect_start(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rc;
  int rv;
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int qfd;
  static const struct alpn_spec ALPN_SPEC_H3 = {{ "h3", "h3-29" }, 2};

  DEBUGASSERT(ctx->initialized);
  ctx->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  ctx->scid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->scid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  (void)Curl_qlogdir(data, ctx->scid.data, NGTCP2_MAX_CIDLEN, &qfd);
  ctx->qlogfd = qfd; /* -1 if failure above */
  quic_settings_proxy(ctx, data, pktx);

  result = vquic_ctx_init(&ctx->q);
  if(result)
    return result;

  if(cf->next->cft == &Curl_cft_udp) {
    if(Curl_cf_socket_peek(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL))
      return CURLE_QUIC_CONNECT_ERROR;
    ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
    rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                    &ctx->q.local_addrlen);
    if(rv == -1)
      return CURLE_QUIC_CONNECT_ERROR;

    ngtcp2_addr_init(&ctx->connected_path.local,
                    (struct sockaddr *)&ctx->q.local_addr,
                    ctx->q.local_addrlen);
    ngtcp2_addr_init(&ctx->connected_path.remote,
                    &sockaddr->curl_sa_addr, (socklen_t)sockaddr->addrlen);

    rc = ngtcp2_conn_client_new(&ctx->qconn, &ctx->dcid, &ctx->scid,
                                &ctx->connected_path,
                                NGTCP2_PROTO_VER_V1, &ngtcp2_proxy_callbacks,
                                &ctx->settings, &ctx->transport_params,
                                Curl_ngtcp2_mem(), cf);
    if(rc)
      return CURLE_QUIC_CONNECT_ERROR;

    ctx->conn_ref.get_conn = get_conn;
    ctx->conn_ref.user_data = cf;
  }
  else {
    struct Curl_sockaddr_ex addr_ex;
    addr_ex.family = AF_INET;
    addr_ex.protocol = IPPROTO_UDP;
    addr_ex.addrlen = ctx->addr->ai_addrlen;
    memcpy(&addr_ex.addr.sa, ctx->addr->ai_addr, ctx->addr->ai_addrlen);
    /* ABASU FIX */
    return CURLE_QUIC_CONNECT_ERROR;
  }

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer, &ALPN_SPEC_H3,
                               cf_ngtcp2_proxy_tls_ctx_setup, &ctx->tls,
                               &ctx->conn_ref,
                               cf_ngtcp2_on_session_reuse);
  if(result)
    return result;

#if defined(USE_OPENSSL) && defined(OPENSSL_QUIC_API2)
  if(ngtcp2_crypto_ossl_ctx_new(&ctx->ossl_ctx, ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_ctx_new failed");
    return CURLE_FAILED_INIT;
  }
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->ossl_ctx);
  if(ngtcp2_crypto_ossl_configure_client_session(ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_configure_client_session failed");
    return CURLE_FAILED_INIT;
  }
#elif defined(USE_OPENSSL)
  SSL_set_quic_use_legacy_codepoint(ctx->tls.ossl.ssl, 0);
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.ossl.ssl);
#elif defined(USE_GNUTLS)
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.gtls.session);
#elif defined(USE_WOLFSSL)
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.wssl.ssl);
#else
  #error "ngtcp2 TLS backend not defined"
#endif

  ngtcp2_ccerr_default(&ctx->last_error);

  return CURLE_OK;
}

static CURLcode cf_ngtcp2_proxy_quic_connect(struct Curl_cfilter *cf,
                                             struct Curl_easy *data,
                                             bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;
  struct curltime now;
  struct pkt_io_ctx pktx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(cf->next->cft == &Curl_cft_udp) {
    /* Connect the UDP filter first */
    if(!cf->next->connected) {
      result = Curl_conn_cf_connect(cf->next, data, done);
      if(result || !*done)
        return result;
    }
  }

  *done = FALSE;
  now = curlx_now();
  pktx_init(&pktx, cf, data);

  if(!proxy_ctx->ngtcp2_ctx) {
    result = cf_h3_proxy_ctx_init(cf, data);
    if(result)
      return result;
  }

  CF_DATA_SAVE(save, cf, data);

  if(!proxy_ctx->ngtcp2_ctx->qconn) {
    proxy_ctx->ngtcp2_ctx->started_at = now;
    result = cf_connect_start(cf, data, &pktx);
    if(result)
      goto out;
    if(cf->connected) {
      *done = TRUE;
      goto out;
    }
    result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = proxy_h3_progress_ingress_ngtcp2(cf, data, &pktx);
  if(result)
    goto out;

  result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
  if(result)
    goto out;

  if(ngtcp2_conn_get_handshake_completed(proxy_ctx->ngtcp2_ctx->qconn)) {
    result = proxy_ctx->ngtcp2_ctx->tls_vrfy_result;
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }

out:
  if(result == CURLE_RECV_ERROR && proxy_ctx->ngtcp2_ctx->qconn &&
     ngtcp2_conn_in_draining_period(proxy_ctx->ngtcp2_ctx->qconn)) {
    const ngtcp2_ccerr *cerr =
      ngtcp2_conn_get_ccerr(proxy_ctx->ngtcp2_ctx->qconn);

    result = CURLE_COULDNT_CONNECT;
    if(cerr) {
      CURL_TRC_CF(data, cf, "connect error, type=%d, code=%"
                  FMT_PRIu64,
                  cerr->type, (curl_uint64_t)cerr->error_code);
      switch(cerr->type) {
      case NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION:
        CURL_TRC_CF(data, cf, "error in version negotiation");
        break;
      default:
        if(cerr->error_code >= NGTCP2_CRYPTO_ERROR) {
          CURL_TRC_CF(data, cf, "crypto error, tls alert=%u",
                      (unsigned int)(cerr->error_code & 0xffu));
        }
        else if(cerr->error_code == NGTCP2_CONNECTION_REFUSED) {
          CURL_TRC_CF(data, cf, "connection refused by server");
          /* When a QUIC server instance is shutting down, it may send us a
           * CONNECTION_CLOSE with this code right away. We want
            * to keep on trying in this case. */
          result = CURLE_WEIRD_SERVER_REPLY;
        }
      }
    }
  }

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result) {
    if(cf->next->cft == &Curl_cft_udp) {
      struct ip_quadruple ip;

      if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
        infof(data, "QUIC connect to %s port %u failed: %s",
              ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
    }
  }
#endif
  if(!result && proxy_ctx->ngtcp2_ctx->qconn) {
    result = check_and_set_expiry_ngtcp2(cf, data, &pktx);
  }
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_NGTCP2 */

#ifdef USE_OPENSSL_QUIC
static CURLcode cf_osslq_proxy_quic_connect(struct Curl_cfilter *cf,
                                            struct Curl_easy *data,
                                            bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;
  struct curltime now;
  int err;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(cf->next->cft == &Curl_cft_udp) {
    /* Connect the UDP filter first */
    if(!cf->next->connected) {
      result = Curl_conn_cf_connect(cf->next, data, done);
      if(result || !*done)
        return result;
    }
  }

  *done = FALSE;
  now = curlx_now();

  if(!proxy_ctx->osslq_ctx) {
    result = cf_h3_proxy_ctx_init(cf, data);
    if(result)
      return result;
  }

  CF_DATA_SAVE(save, cf, data);

  if(!proxy_ctx->osslq_ctx->got_first_byte) {
    int readable = SOCKET_READABLE(proxy_ctx->osslq_ctx->q.sockfd, 0);
    if(readable > 0 && (readable & CURL_CSELECT_IN)) {
      proxy_ctx->osslq_ctx->got_first_byte = TRUE;
      proxy_ctx->osslq_ctx->first_byte_at = curlx_now();
    }
  }

  /* Since OpenSSL does its own send/recv internally, we may miss the
   * moment to populate the x509 store right before the server response.
   * Do it instead before we start the handshake, at the loss of the
   * time to set this up. */
  result = Curl_vquic_tls_before_recv(&proxy_ctx->osslq_ctx->tls, cf, data);
  if(result)
    goto out;

  ERR_clear_error();

  err = SSL_do_handshake(proxy_ctx->osslq_ctx->tls.ossl.ssl);

  if(err == 1) {
    /* connected */
    proxy_ctx->osslq_ctx->handshake_at = now;
    proxy_ctx->osslq_ctx->q.last_io = now;

    CURL_TRC_CF(data, cf, "handshake complete after %dms",
                (int)curlx_timediff(now, proxy_ctx->osslq_ctx->started_at));
    result = cf_osslq_verify_peer(cf, data);
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }
  else {
    int detail = SSL_get_error(proxy_ctx->osslq_ctx->tls.ossl.ssl, err);
    switch(detail) {
    case SSL_ERROR_WANT_READ:
      proxy_ctx->osslq_ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_RECV");
      goto out;
    case SSL_ERROR_WANT_WRITE:
      proxy_ctx->osslq_ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_SEND");
      result = CURLE_OK;
      goto out;
#ifdef SSL_ERROR_WANT_ASYNC
    case SSL_ERROR_WANT_ASYNC:
      proxy_ctx->osslq_ctx->q.last_io = now;
      CURL_TRC_CF(data, cf, "QUIC SSL_connect() -> WANT_ASYNC");
      result = CURLE_OK;
      goto out;
#endif
#ifdef SSL_ERROR_WANT_RETRY_VERIFY
    case SSL_ERROR_WANT_RETRY_VERIFY:
      result = CURLE_OK;
      goto out;
#endif
    default:
      result = cf_osslq_ssl_err(cf, data, detail, CURLE_COULDNT_CONNECT);
      goto out;
    }
  }

out:
  if(result == CURLE_RECV_ERROR && proxy_ctx->osslq_ctx->tls.ossl.ssl &&
      proxy_ctx->osslq_ctx->protocol_shutdown) {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state. The CONNECT may work in the near future again. Indicate
     * that as a "weird" reply. */
    result = CURLE_WEIRD_SERVER_REPLY;
  }

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result) {
    struct ip_quadruple ip;

    if(!Curl_cf_socket_peek(cf->next, data, NULL, NULL, &ip))
      infof(data, "QUIC connect to %s port %u failed: %s",
            ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
  }
#endif

  /* Maybe extreme but avoid seding data before quic handshake is done */
  if(!result && !SSL_in_init(proxy_ctx->osslq_ctx->tls.ossl.ssl))
    result = check_and_set_expiry_ossl(cf, data);
  if(result || *done) {
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  }

  CF_DATA_RESTORE(cf, save);
  return result;
}
#endif /* USE_OPENSSL_QUIC */

static CURLcode cf_h3_proxy_quic_connect(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         bool *done)
{
#ifdef USE_OPENSSL_QUIC
  return cf_osslq_proxy_quic_connect(cf, data, done);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  return cf_ngtcp2_proxy_quic_connect(cf, data, done);
#endif /* USE_NGTCP2 */
}

static CURLcode H3_CONNECT(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct tunnel_stream *ts)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(ts);
  DEBUGASSERT(ts->authority);

  do {
    switch(ts->state) {
    case H3_TUNNEL_INIT:
      CURL_TRC_CF(data, cf, "[0] CONNECT start for %s", ts->authority);
      result = submit_CONNECT(cf, data, ts);
      if(result)
        goto out;
      h3_tunnel_go_state(cf, ts, H3_TUNNEL_CONNECT, data);

#ifdef USE_OPENSSL_QUIC
      result = proxy_h3_progress_egress_ossl(cf, data);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
      result = proxy_h3_progress_egress_ngtcp2(cf, data, NULL);
#endif /* USE_NGTCP2 */
      if(result)
        goto out;
      FALLTHROUGH();

    case H3_TUNNEL_CONNECT:
      while(ts->has_final_response == FALSE) {
#ifdef USE_OPENSSL_QUIC
        result = proxy_h3_progress_ingress_ossl(cf, data);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
        result = proxy_h3_progress_ingress_ngtcp2(cf, data, NULL);
#endif /* USE_NGTCP2 */
        if(result)
          goto out;
#ifdef USE_OPENSSL_QUIC
        result = proxy_h3_progress_egress_ossl(cf, data);
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
        result = proxy_h3_progress_egress_ngtcp2(cf, data, NULL);
#endif /* USE_NGTCP2 */
        if(result && result != CURLE_AGAIN) {
          h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
          goto out;
        }
      }
      if(result && result != CURLE_AGAIN) {
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
        break;
      }

      if(ts->has_final_response)
        h3_tunnel_go_state(cf, ts, H3_TUNNEL_RESPONSE, data);
      else {
        result = CURLE_OK;
        goto out;
      }
      FALLTHROUGH();

    case H3_TUNNEL_RESPONSE:
      DEBUGASSERT(ts->has_final_response);
      result = inspect_response(cf, data, ts);
      if(result)
        goto out;
      ctx->connected = TRUE;
      break;

    case H3_TUNNEL_ESTABLISHED:
      return CURLE_OK;

    case H3_TUNNEL_FAILED:
      return CURLE_RECV_ERROR;

    default:
      break;
    }

  } while(ts->state == H3_TUNNEL_INIT);

out:
  if((result && (result != CURLE_AGAIN)) || ctx->tunnel.closed)
    h3_tunnel_go_state(cf, ts, H3_TUNNEL_FAILED, data);
  return result;
}

static CURLcode
cf_h3_proxy_connect(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;
  timediff_t check;
  struct tunnel_stream *ts = &proxy_ctx->tunnel;
  bool data_saved = FALSE;

  /* Curl_cft_http_proxy --> Curl_cft_h3_proxy --> Curl_cft_udp */
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  *done = FALSE;

  check = Curl_timeleft(data, NULL, TRUE);
  if(check <= 0) {
    failf(data, "Proxy CONNECT aborted due to timeout");
    result = CURLE_OPERATION_TIMEDOUT;
    goto out;
  }

  result = cf_h3_proxy_quic_connect(cf, data, done);
  if(*done != TRUE)
    goto out;

  CF_DATA_SAVE(save, cf, data);
  data_saved = TRUE;

  /* At this point the QUIC is connected, but the proxy isn't connected */
  *done = FALSE;

  result = H3_CONNECT(cf, data, ts);

out:
  *done = (result == CURLE_OK) && (ts->state == H3_TUNNEL_ESTABLISHED);
  if(*done) {
    cf->connected = TRUE;
    /* The real request will follow the CONNECT, reset request partially */
    Curl_req_soft_reset(&data->req, data);
    Curl_client_reset(data);
  }

  if(data_saved)
    CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  (void)cf;
  if(!pause) {
    /* unpaused. make it run again right away */
    Curl_multi_mark_dirty(data);
  }
  return CURLE_OK;
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct h3_proxy_stream_ctx *stream = NULL;

  (void)cf;

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(stream && H3_STREAM_ID(stream) == proxy_ctx->tunnel.stream_id) {
      if(ctx->h3.conn && !stream->closed) {
        nghttp3_conn_shutdown_stream_read(ctx->h3.conn, H3_STREAM_ID(stream));
        nghttp3_conn_close_stream(ctx->h3.conn, H3_STREAM_ID(stream),
                                  NGHTTP3_H3_REQUEST_CANCELLED);
        nghttp3_conn_set_stream_user_data(ctx->h3.conn,
                                          H3_STREAM_ID(stream), NULL);
        proxy_ctx->tunnel.closed = TRUE;
      }
      Curl_uint_hash_remove(&ctx->streams, data->mid);
    }
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    stream = H3_PROXY_STREAM_CTX(ctx, data);
    if(stream && H3_STREAM_ID(stream) == proxy_ctx->tunnel.stream_id) {
      if(ctx->h3conn && !stream->closed) {
        CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] easy handle is done",
                    stream->id);
        cf_ngtcp2_stream_close(cf, data, stream);
        Curl_uint_hash_remove(&ctx->streams, data->mid);
        if(!Curl_uint_hash_count(&ctx->streams))
          cf_ngtcp2_setup_keep_alive(cf, data);
      }
    }
  }
#endif /* USE_NGTCP2 */
}

static CURLcode cf_h3_proxy_cntrl(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  int event, int arg1, void *arg2)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);

  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_proxy_stream_ctx *stream = NULL;
#ifdef USE_OPENSSL_QUIC
    if(proxy_ctx->osslq_ctx) {
      struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
      stream = H3_PROXY_STREAM_CTX(ctx, data);
      if(stream && !stream->send_closed) {
        stream->send_closed = TRUE;
        stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
          stream->sendbuf_len_in_flight;
        (void)nghttp3_conn_resume_stream(ctx->h3.conn, H3_STREAM_ID(stream));
      }
    }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
    if(proxy_ctx->ngtcp2_ctx) {
      struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
      stream = H3_PROXY_STREAM_CTX(ctx, data);
      if(stream && !stream->send_closed) {
        stream->send_closed = TRUE;
        stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
          stream->sendbuf_len_in_flight;
        (void)nghttp3_conn_resume_stream(ctx->h3conn, H3_STREAM_ID(stream));
      }
    }
#endif /* USE_NGTCP2 */
    break;
  }
  case CF_CTRL_CONN_INFO_UPDATE:
    if(!cf->sockindex && cf->connected) {
      cf->conn->httpversion_seen = 31;
      Curl_conn_set_multiplex(cf->conn);
    }
    break;
  default:
    break;
  }

  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_h3_proxy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  (void)data;
  if(ctx) {
#ifdef USE_OPENSSL_QUIC
    /* Clean up the osslq context properly */
    if(ctx->osslq_ctx) {
      CURL_TRC_CF(data, cf, "cf_osslq_ctx_close()");
      if(ctx->osslq_ctx->tls.ossl.ssl)
        cf_osslq_ctx_close(ctx->osslq_ctx);
      cf_osslq_ctx_free(ctx->osslq_ctx);
      ctx->osslq_ctx = NULL;
    }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
    /* Clean up the ngtcp2 context properly */
    if(ctx->ngtcp2_ctx) {
      CURL_TRC_CF(data, cf, "cf_ngtcp2_ctx_close()");
      cf_ngtcp2_close(cf, data);
      cf_ngtcp2_ctx_free(ctx->ngtcp2_ctx);
      ctx->ngtcp2_ctx = NULL;
    }
#endif /* USE_NGTCP2 */
    cf_h3_proxy_ctx_free(ctx);
    cf->ctx = NULL;
  }
}

static void cf_h3_proxy_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_h3_proxy_ctx *ctx = cf->ctx;

  if(ctx) {
    cf_h3_proxy_ctx_clear(ctx);
    cf->connected = FALSE;
  }

  if(cf->next)
    cf->next->cft->do_close(cf->next, data);
}

static CURLcode cf_h3_proxy_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data, bool *done)
{
  struct cf_h3_proxy_ctx *proxy_ctx = cf->ctx;
  struct cf_call_data save;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);

#ifdef USE_OPENSSL_QUIC
  if(proxy_ctx->osslq_ctx) {
    struct cf_osslq_ctx *ctx = proxy_ctx->osslq_ctx;
    int rc;

    if(!cf->connected || !ctx->h3.conn || cf->shutdown ||
                                          ctx->protocol_shutdown) {
      *done = TRUE;
      CF_DATA_RESTORE(cf, save);
      return CURLE_OK;
    }

    *done = FALSE;
    ctx->need_send = FALSE;
    ctx->need_recv = FALSE;

    rc = SSL_shutdown_ex(ctx->tls.ossl.ssl,
                         SSL_SHUTDOWN_FLAG_NO_BLOCK, NULL, 0);
    if(rc == 0) { /* ongoing */
      CURL_TRC_CF(data, cf, "shutdown ongoing");
      ctx->need_recv = TRUE;
      goto out;
    }
    else if(rc == 1) { /* done */
      CURL_TRC_CF(data, cf, "shutdown finished");
      *done = TRUE;
      goto out;
    }
    else {
      long sslerr;
      char err_buffer[256];
      int err = SSL_get_error(ctx->tls.ossl.ssl, rc);

      switch(err) {
      case SSL_ERROR_NONE:
      case SSL_ERROR_ZERO_RETURN:
        CURL_TRC_CF(data, cf, "shutdown not received, but closed");
        *done = TRUE;
        goto out;
      case SSL_ERROR_WANT_READ:
        /* SSL has send its notify and now wants to read the reply
         * from the server. We are not really interested in that. */
        CURL_TRC_CF(data, cf, "shutdown sent, want receive");
        ctx->need_recv = TRUE;
        goto out;
      case SSL_ERROR_WANT_WRITE:
        CURL_TRC_CF(data, cf, "shutdown send blocked");
        ctx->need_send = TRUE;
        goto out;
      default:
        /* We give up on this. */
        sslerr = ERR_get_error();
        CURL_TRC_CF(data, cf, "shutdown, ignore recv error: '%s', errno %d",
                    (sslerr ?
                      osslq_strerror(sslerr, err_buffer, sizeof(err_buffer)) :
                      osslq_SSL_ERROR_to_str(err)),
                    SOCKERRNO);
        *done = TRUE;
        result = CURLE_OK;
        goto out;
      }
    }
  }
#endif /* USE_OPENSSL_QUIC */
#ifdef USE_NGTCP2
  if(proxy_ctx->ngtcp2_ctx) {
    struct cf_ngtcp2_ctx *ctx = proxy_ctx->ngtcp2_ctx;
    struct pkt_io_ctx pktx;

    if(cf->shutdown || !ctx->qconn) {
      *done = TRUE;
      return CURLE_OK;
    }

    CF_DATA_SAVE(save, cf, data);
    *done = FALSE;
    pktx_init(&pktx, cf, data);

    if(!ctx->shutdown_started) {
      char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
      ngtcp2_ssize nwritten;

      if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
        CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
        result = proxy_h3_progress_egress_ngtcp2(cf, data, &pktx);
        if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
          CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
          result = CURLE_OK;
          goto out;
        }
        else if(result) {
          CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
          *done = TRUE;
          goto out;
        }
      }

      DEBUGASSERT(Curl_bufq_is_empty(&ctx->q.sendbuf));
      ctx->shutdown_started = TRUE;
      nwritten = ngtcp2_conn_write_connection_close(
        ctx->qconn, NULL, /* path */
        NULL, /* pkt_info */
        (uint8_t *)buffer, sizeof(buffer),
        &ctx->last_error, pktx.ts);
      CURL_TRC_CF(data, cf, "start shutdown(err_type=%d, err_code=%"
                  FMT_PRIu64 ") -> %d", ctx->last_error.type,
                  (curl_uint64_t)ctx->last_error.error_code, (int)nwritten);
      /* there are cases listed in ngtcp2 documentation where this call
      * may fail. Since we are doing a connection shutdown as graceful
      * as we can, such an error is ignored here. */
      if(nwritten > 0) {
        /* Ignore amount written. sendbuf was empty and has always room for
        * NGTCP2_MAX_UDP_PAYLOAD_SIZE. It can only completely fail, in which
        * case `result` is set non zero. */
        size_t n;
        result = Curl_bufq_write(&ctx->q.sendbuf,
                                 (const unsigned char *)buffer,
                                 (size_t)nwritten, &n);
        if(result) {
          CURL_TRC_CF(data, cf, "error %d adding shutdown packets to sendbuf, "
                      "aborting shutdown", result);
          goto out;
        }

        ctx->q.no_gso = TRUE;
        ctx->q.gsolen = (size_t)nwritten;
        ctx->q.split_len = 0;
      }
    }

    if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      CURL_TRC_CF(data, cf, "shutdown, flushing egress");
      result = vquic_flush(cf, data, &ctx->q);
      if(result == CURLE_AGAIN) {
        CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
        result = CURLE_OK;
        goto out;
      }
      else if(result) {
        CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
        *done = TRUE;
        goto out;
      }
    }

    if(Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      /* Sent everything off. ngtcp2 seems to have no support for graceful
      * shutdowns. So, we are done. */
      CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
      *done = TRUE;
      result = CURLE_OK;
    }
  }
#endif /* USE_NGTCP2 */

out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

struct Curl_cftype Curl_cft_h3_proxy = {
    "H3-PROXY",
    CF_TYPE_IP_CONNECT | CF_TYPE_PROXY,
    CURL_LOG_LVL_NONE,
    cf_h3_proxy_destroy,
    cf_h3_proxy_connect,
    cf_h3_proxy_close,
    cf_h3_proxy_shutdown,
    cf_h3_proxy_adjust_pollset, /* done */
    cf_h3_proxy_data_pending, /* done */
    cf_h3_proxy_send, /* done */
    cf_h3_proxy_recv, /* done */
    cf_h3_proxy_cntrl, /* done */
    cf_h3_proxy_is_alive, /* done */
    Curl_cf_def_conn_keep_alive, /* done */
    cf_h3_proxy_query, /* done */
};

static struct Curl_addrinfo *
addr_first_match(struct Curl_addrinfo *addr, int family)
{
  while(addr) {
    if(addr->ai_family == family)
      return addr;
    addr = addr->ai_next;
  }
  return NULL;
}

static int Curl_get_QUIC_addr_info(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct Curl_addrinfo *ai)
{
  struct connectdata *conn = cf->conn;
  struct Curl_dns_entry *remotehost = data->state.dns[cf->sockindex];
  int ai_family0 = 0, ai_family1 = 0;
  const struct Curl_addrinfo *addr0 = NULL, *addr1 = NULL;

  if(conn->ip_version == CURL_IPRESOLVE_V6) {
#ifdef USE_IPV6
    ai_family0 = AF_INET6;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
#endif
  }
  else if(conn->ip_version == CURL_IPRESOLVE_V4) {
    ai_family0 = AF_INET;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
  }
  else {
    /* no user preference, we try ipv6 always first when available */
#ifdef USE_IPV6
    ai_family0 = AF_INET6;
    addr0 = addr_first_match(remotehost->addr, ai_family0);
#endif
    /* next candidate is ipv4 */
    ai_family1 = AF_INET;
    addr1 = addr_first_match(remotehost->addr, ai_family1);
    /* no ip address families, probably AF_UNIX or something, use the
     * address family given to us */
    if(!addr1  && !addr0 && remotehost->addr) {
      ai_family0 = remotehost->addr->ai_family;
      addr0 = addr_first_match(remotehost->addr, ai_family0);
    }
  }

  if(!addr0 && addr1) {
    /* switch around, so a single baller always uses addr0 */
    addr0 = addr1;
    ai_family0 = ai_family1;
    addr1 = NULL;
  }

  /* Transfer the selected address info into ai */
  if(addr0) {
    memset(ai, 0, sizeof(*ai));
    ai->ai_family = addr0->ai_family;
    ai->ai_socktype = addr0->ai_socktype;
    ai->ai_protocol = addr0->ai_protocol;
    ai->ai_addrlen = addr0->ai_addrlen;
    ai->ai_canonname = addr0->ai_canonname;
    ai->ai_addr = addr0->ai_addr;
    return 1; /* success */
  }
  return 0; /* no address found */
}

CURLcode Curl_cf_h3_proxy_insert_after(struct Curl_cfilter **pcf,
                                       struct Curl_easy *data)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_h3_proxy_ctx *ctx;
  struct connectdata *conn = data->conn;
  struct Curl_addrinfo ai = {0};
  CURLcode result = CURLE_OUT_OF_MEMORY;
  int rv;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx)
    goto out;

  result = Curl_cf_create(&cf, &Curl_cft_h3_proxy, ctx);
  if(result)
    goto out;

  rv = Curl_get_QUIC_addr_info(*pcf, data, &ai);
  if(!rv)
    failf(data, "Failed to get QUIC UDP socket addr info");

  result = Curl_cf_udp_create(&cf->next, data, conn, &ai, TRNSPRT_QUIC);
  if(result)
    goto out;

  Curl_conn_cf_insert_after(*pcf, cf);

out:
  if(result) {
    if(cf)
      Curl_conn_cf_discard_chain(&cf, data);
    else if(ctx)
      cf_h3_proxy_ctx_free(ctx);
  }
  return result;
}

#endif /* !CURL_DISABLE_HTTP && !CURL_DISABLE_PROXY && USE_NGHTTP3 && \
                (USE_OPENSSL_QUIC || USE_NGTCP2) */
