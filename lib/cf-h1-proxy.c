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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP)

#include <openssl/bio.h>
#include <curl/curl.h>
#include "urldata.h"
#include "curlx/dynbuf.h"
#include "sendf.h"
#include "http.h"
#include "http1.h"
#include "http_proxy.h"
#include "url.h"
#include "select.h"
#include "progress.h"
#include "cfilters.h"
#include "cf-h1-proxy.h"
#include "connect.h"
#include "curl_trc.h"
#include "bufq.h"
#include "strcase.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define PROXY_H1_CHUNK_SIZE     (16*1024)
#define H1_TUNNEL_WINDOW_SIZE   (10 * 1024 * 1024)
#define PROXY_H1_NW_RECV_CHUNKS (H1_TUNNEL_WINDOW_SIZE / PROXY_H1_CHUNK_SIZE)

typedef enum {
    H1_TUNNEL_INIT,     /* init/default/no tunnel state */
    H1_TUNNEL_CONNECT,  /* CONNECT request is being send */
    H1_TUNNEL_RECEIVE,  /* CONNECT answer is being received */
    H1_TUNNEL_RESPONSE, /* CONNECT response received completely */
    H1_TUNNEL_ESTABLISHED,
    H1_TUNNEL_FAILED
} h1_tunnel_state;

/* struct for HTTP CONNECT tunneling */
struct h1_tunnel_state {
  struct dynbuf rcvbuf;
  struct dynbuf request_data;
  struct bufq recvbuf;  /* UDP capsule receive buffer */
  size_t nsent;
  size_t headerlines;
  struct Curl_chunker ch;
  enum keeponval {
    KEEPON_DONE,
    KEEPON_CONNECT,
    KEEPON_IGNORE
  } keepon;
  curl_off_t cl; /* size of content to read and ignore */
  h1_tunnel_state tunnel_state;
  BIT(chunked_encoding);
  BIT(close_connection);
};


static bool tunnel_is_established(struct h1_tunnel_state *ts)
{
  return ts && (ts->tunnel_state == H1_TUNNEL_ESTABLISHED);
}

static bool tunnel_is_failed(struct h1_tunnel_state *ts)
{
  return ts && (ts->tunnel_state == H1_TUNNEL_FAILED);
}

static CURLcode tunnel_reinit(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct h1_tunnel_state *ts)
{
  (void)data;
  (void)cf;
  DEBUGASSERT(ts);
  curlx_dyn_reset(&ts->rcvbuf);
  curlx_dyn_reset(&ts->request_data);
  Curl_bufq_reset(&ts->recvbuf);
  ts->tunnel_state = H1_TUNNEL_INIT;
  ts->keepon = KEEPON_CONNECT;
  ts->cl = 0;
  ts->close_connection = FALSE;
  return CURLE_OK;
}

static CURLcode tunnel_init(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            struct h1_tunnel_state **pts)
{
  struct h1_tunnel_state *ts;

  if(cf->conn->handler->flags & PROTOPT_NOTCPPROXY) {
    failf(data, "%s cannot be done over CONNECT", cf->conn->handler->scheme);
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  ts = calloc(1, sizeof(*ts));
  if(!ts)
    return CURLE_OUT_OF_MEMORY;

  infof(data, "allocate connect buffer");

  curlx_dyn_init(&ts->rcvbuf, DYN_PROXY_CONNECT_HEADERS);
  curlx_dyn_init(&ts->request_data, DYN_HTTP_REQUEST);
  Curl_bufq_init2(&ts->recvbuf, PROXY_H1_CHUNK_SIZE, PROXY_H1_NW_RECV_CHUNKS,
                  BUFQ_OPT_SOFT_LIMIT);
  Curl_httpchunk_init(data, &ts->ch, TRUE);

  *pts =  ts;
  connkeep(cf->conn, "HTTP proxy CONNECT");
  return tunnel_reinit(cf, data, ts);
}

static void h1_tunnel_go_state(struct Curl_cfilter *cf,
                               struct h1_tunnel_state *ts,
                               h1_tunnel_state new_state,
                               struct Curl_easy *data)
{
  if(ts->tunnel_state == new_state)
    return;
  /* entering this one */
  switch(new_state) {
  case H1_TUNNEL_INIT:
    CURL_TRC_CF(data, cf, "new tunnel state 'init'");
    tunnel_reinit(cf, data, ts);
    break;

  case H1_TUNNEL_CONNECT:
    CURL_TRC_CF(data, cf, "new tunnel state 'connect'");
    ts->tunnel_state = H1_TUNNEL_CONNECT;
    ts->keepon = KEEPON_CONNECT;
    curlx_dyn_reset(&ts->rcvbuf);
    break;

  case H1_TUNNEL_RECEIVE:
    CURL_TRC_CF(data, cf, "new tunnel state 'receive'");
    ts->tunnel_state = H1_TUNNEL_RECEIVE;
    break;

  case H1_TUNNEL_RESPONSE:
    CURL_TRC_CF(data, cf, "new tunnel state 'response'");
    ts->tunnel_state = H1_TUNNEL_RESPONSE;
    break;

  case H1_TUNNEL_ESTABLISHED:
    CURL_TRC_CF(data, cf, "new tunnel state 'established'");
    if(cf->conn->bits.udp_tunnel_proxy)
      infof(data, "CONNECT-UDP phase completed for HTTP proxy");
    else
      infof(data, "CONNECT phase completed for HTTP proxy");

    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    FALLTHROUGH();
  case H1_TUNNEL_FAILED:
    if(new_state == H1_TUNNEL_FAILED)
      CURL_TRC_CF(data, cf, "new tunnel state 'failed'");
    ts->tunnel_state = new_state;
    curlx_dyn_reset(&ts->rcvbuf);
    curlx_dyn_reset(&ts->request_data);
    /* restore the protocol pointer */
    data->info.httpcode = 0; /* clear it as it might've been used for the
                                proxy */
    /* If a proxy-authorization header was used for the proxy, then we should
       make sure that it is not accidentally used for the document request
       after we have connected. So let's free and clear it here. */
    Curl_safefree(data->state.aptr.proxyuserpwd);
    break;
  }
}

static void tunnel_free(struct Curl_cfilter *cf,
                        struct Curl_easy *data)
{
  if(cf) {
    struct h1_tunnel_state *ts = cf->ctx;
    if(ts) {
      h1_tunnel_go_state(cf, ts, H1_TUNNEL_FAILED, data);
      curlx_dyn_free(&ts->rcvbuf);
      curlx_dyn_free(&ts->request_data);
      Curl_bufq_free(&ts->recvbuf);
      Curl_httpchunk_free(data, &ts->ch);
      free(ts);
      cf->ctx = NULL;
    }
  }
}

static bool tunnel_want_send(struct h1_tunnel_state *ts)
{
  return ts->tunnel_state == H1_TUNNEL_CONNECT;
}

static CURLcode start_CONNECT(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              struct h1_tunnel_state *ts)
{
  struct httpreq *req = NULL;
  int http_minor;
  CURLcode result;

    /* This only happens if we have looped here due to authentication
       reasons, and we do not really use the newly cloned URL here
       then. Just free() it. */
  Curl_safefree(data->req.newurl);

  if(cf->conn->bits.udp_tunnel_proxy) {
    result = Curl_http_proxy_create_CONNECTUDP(&req, cf, data, 1);
  }
  else {
    result = Curl_http_proxy_create_CONNECT(&req, cf, data, 1);
  }
  if(result)
    goto out;

  if(cf->conn->bits.udp_tunnel_proxy)
    infof(data, "Establishing HTTP proxy UDP tunnel to %s:%s",
                      data->state.up.hostname, data->state.up.port);
  else
    infof(data, "Establishing HTTP proxy tunnel to %s", req->authority);

  curlx_dyn_reset(&ts->request_data);
  ts->nsent = 0;
  ts->headerlines = 0;
  http_minor = (cf->conn->http_proxy.proxytype == CURLPROXY_HTTP_1_0) ? 0 : 1;

  result = Curl_h1_req_write_head(req, http_minor, &ts->request_data);
  if(!result)
    result = Curl_creader_set_null(data);

out:
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  if(req)
    Curl_http_req_free(req);
  return result;
}

static CURLcode send_CONNECT(struct Curl_cfilter *cf,
                             struct Curl_easy *data,
                             struct h1_tunnel_state *ts,
                             bool *done)
{
  char *buf = curlx_dyn_ptr(&ts->request_data);
  size_t request_len = curlx_dyn_len(&ts->request_data);
  size_t blen = request_len;
  CURLcode result = CURLE_OK;
  ssize_t nwritten;

  if(blen <= ts->nsent)
    goto out;  /* we are done */

  blen -= ts->nsent;
  buf += ts->nsent;

  nwritten = cf->next->cft->do_send(cf->next, data, buf, blen, FALSE, &result);
  if(nwritten < 0) {
    if(result == CURLE_AGAIN) {
      result = CURLE_OK;
    }
    goto out;
  }

  DEBUGASSERT(blen >= (size_t)nwritten);
  ts->nsent += (size_t)nwritten;
  Curl_debug(data, CURLINFO_HEADER_OUT, buf, (size_t)nwritten);

out:
  if(result)
    failf(data, "Failed sending CONNECT to proxy");
  *done = (!result && (ts->nsent >= request_len));
  return result;
}

static CURLcode on_resp_header_udp(struct Curl_easy *data,
                                   struct h1_tunnel_state *ts,
                                   const char *header)
{
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;

  if(checkprefix("Transfer-Encoding:", header)) {
    if(Curl_compareheader(header,
                           STRCONST("Transfer-Encoding:"),
                           STRCONST("chunked"))) {
      infof(data, "MASQUE FIX: CONNECT-UDP Response --> "
                  "Transfer-Encoding: chunked");
      ts->chunked_encoding = TRUE;
      /* reset our chunky engine */
      Curl_httpchunk_reset(data, &ts->ch, TRUE);
    }
  }
  else if(checkprefix("Capsule-protocol:", header)) {
    if(Curl_compareheader(header,
                           STRCONST("Capsule-protocol:"),
                           STRCONST("?1"))) {
      infof(data, "MASQUE FIX: CONNECT-UDP Response --> Capsule-protocol: ?1");
    }
  }
  else if(Curl_compareheader(header,
                              STRCONST("Connection:"), STRCONST("close"))) {
    ts->close_connection = TRUE;
    infof(data, "MASQUE FIX: CONNECT-UDP Response --> Connection: close");
  }
  else if(!strncmp(header, "HTTP/1.", 7) &&
           ((header[7] == '0') || (header[7] == '1')) &&
           (header[8] == ' ') &&
           ISDIGIT(header[9]) && ISDIGIT(header[10]) && ISDIGIT(header[11]) &&
           !ISDIGIT(header[12])) {
    /* store the HTTP code from the proxy */
    data->info.httpproxycode = k->httpcode = (header[9] - '0') * 100 +
                          (header[10] - '0') * 10 + (header[11] - '0');
    infof(data, "MASQUE FIX: CONNECT-UDP Response --> %d", k->httpcode);
  }
  return result;
}

static CURLcode on_resp_header(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h1_tunnel_state *ts,
                               const char *header)
{
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  (void)cf;

  if((checkprefix("WWW-Authenticate:", header) &&
      (401 == k->httpcode)) ||
     (checkprefix("Proxy-authenticate:", header) &&
      (407 == k->httpcode))) {

    bool proxy = (k->httpcode == 407);
    char *auth = Curl_copy_header_value(header);
    if(!auth)
      return CURLE_OUT_OF_MEMORY;

    CURL_TRC_CF(data, cf, "CONNECT: fwd auth header '%s'", header);
    result = Curl_http_input_auth(data, proxy, auth);

    free(auth);

    if(result)
      return result;
  }
  else if(checkprefix("Content-Length:", header)) {
    if(k->httpcode/100 == 2) {
      /* A client MUST ignore any Content-Length or Transfer-Encoding
         header fields received in a successful response to CONNECT.
         "Successful" described as: 2xx (Successful). RFC 7231 4.3.6 */
      infof(data, "Ignoring Content-Length in CONNECT %03d response",
            k->httpcode);
    }
    else {
      const char *p = header + strlen("Content-Length:");
      if(curlx_str_numblanks(&p, &ts->cl)) {
        failf(data, "Unsupported Content-Length value");
        return CURLE_WEIRD_SERVER_REPLY;
      }
    }
  }
  else if(Curl_compareheader(header,
                             STRCONST("Connection:"), STRCONST("close")))
    ts->close_connection = TRUE;
  else if(checkprefix("Transfer-Encoding:", header)) {
    if(k->httpcode/100 == 2) {
      /* A client MUST ignore any Content-Length or Transfer-Encoding
         header fields received in a successful response to CONNECT.
         "Successful" described as: 2xx (Successful). RFC 7231 4.3.6 */
      infof(data, "Ignoring Transfer-Encoding in "
            "CONNECT %03d response", k->httpcode);
    }
    else if(Curl_compareheader(header,
                               STRCONST("Transfer-Encoding:"),
                               STRCONST("chunked"))) {
      infof(data, "CONNECT responded chunked");
      ts->chunked_encoding = TRUE;
      /* reset our chunky engine */
      Curl_httpchunk_reset(data, &ts->ch, TRUE);
    }
  }
  else if(Curl_compareheader(header,
                             STRCONST("Proxy-Connection:"),
                             STRCONST("close")))
    ts->close_connection = TRUE;
  else if(!strncmp(header, "HTTP/1.", 7) &&
          ((header[7] == '0') || (header[7] == '1')) &&
          (header[8] == ' ') &&
          ISDIGIT(header[9]) && ISDIGIT(header[10]) && ISDIGIT(header[11]) &&
          !ISDIGIT(header[12])) {
    /* store the HTTP code from the proxy */
    data->info.httpproxycode =  k->httpcode = (header[9] - '0') * 100 +
      (header[10] - '0') * 10 + (header[11] - '0');
  }
  return result;
}

static CURLcode recv_CONNECT_resp(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h1_tunnel_state *ts,
                                  bool *done)
{
  CURLcode result = CURLE_OK;
  struct SingleRequest *k = &data->req;
  char *linep;
  size_t line_len;
  int error, writetype;

#define SELECT_OK      0
#define SELECT_ERROR   1

  error = SELECT_OK;
  *done = FALSE;

  if(!Curl_conn_data_pending(data, cf->sockindex))
    return CURLE_OK;

  while(ts->keepon) {
    ssize_t nread;
    char byte;

    /* Read one byte at a time to avoid a race condition. Wait at most one
       second before looping to ensure continuous pgrsUpdates. */
    result = Curl_conn_recv(data, cf->sockindex, &byte, 1, &nread);
    if(result == CURLE_AGAIN)
      /* socket buffer drained, return */
      return CURLE_OK;

    if(Curl_pgrsUpdate(data))
      return CURLE_ABORTED_BY_CALLBACK;

    if(result) {
      ts->keepon = KEEPON_DONE;
      break;
    }

    if(nread <= 0) {
      if(data->set.proxyauth && data->state.authproxy.avail &&
         data->state.aptr.proxyuserpwd) {
        /* proxy auth was requested and there was proxy auth available,
           then deem this as "mere" proxy disconnect */
        ts->close_connection = TRUE;
        infof(data, "Proxy CONNECT connection closed");
      }
      else {
        error = SELECT_ERROR;
        failf(data, "Proxy CONNECT aborted");
      }
      ts->keepon = KEEPON_DONE;
      break;
    }

    if(ts->keepon == KEEPON_IGNORE) {
      /* This means we are currently ignoring a response-body */

      if(ts->cl) {
        /* A Content-Length based body: simply count down the counter
           and make sure to break out of the loop when we are done! */
        ts->cl--;
        if(ts->cl <= 0) {
          ts->keepon = KEEPON_DONE;
          break;
        }
      }
      else if(ts->chunked_encoding) {
        /* chunked-encoded body, so we need to do the chunked dance
           properly to know when the end of the body is reached */
        size_t consumed = 0;

        /* now parse the chunked piece of data so that we can
           properly tell when the stream ends */
        result = Curl_httpchunk_read(data, &ts->ch, &byte, 1, &consumed);
        if(result)
          return result;
        if(Curl_httpchunk_is_done(data, &ts->ch)) {
          /* we are done reading chunks! */
          infof(data, "chunk reading DONE");
          ts->keepon = KEEPON_DONE;
        }
      }
      continue;
    }

    if(curlx_dyn_addn(&ts->rcvbuf, &byte, 1)) {
      failf(data, "CONNECT response too large");
      return CURLE_RECV_ERROR;
    }

    /* if this is not the end of a header line then continue */
    if(byte != 0x0a)
      continue;

    ts->headerlines++;
    linep = curlx_dyn_ptr(&ts->rcvbuf);
    line_len = curlx_dyn_len(&ts->rcvbuf); /* amount of bytes in this line */

    /* output debug if that is requested */
    Curl_debug(data, CURLINFO_HEADER_IN, linep, line_len);

    /* send the header to the callback */
    writetype = CLIENTWRITE_HEADER | CLIENTWRITE_CONNECT |
      (ts->headerlines == 1 ? CLIENTWRITE_STATUS : 0);
    result = Curl_client_write(data, writetype, linep, line_len);
    if(result)
      return result;

    result = Curl_bump_headersize(data, line_len, TRUE);
    if(result)
      return result;

    /* Newlines are CRLF, so the CR is ignored as the line is not
       really terminated until the LF comes. Treat a following CR
       as end-of-headers as well.*/

    if(('\r' == linep[0]) ||
       ('\n' == linep[0])) {
      /* end of response-headers from the proxy */

      if((407 == k->httpcode) && !data->state.authproblem) {
        /* If we get a 407 response code with content length
           when we have no auth problem, we must ignore the
           whole response-body */
        ts->keepon = KEEPON_IGNORE;

        if(ts->cl) {
          infof(data, "Ignore %" FMT_OFF_T " bytes of response-body", ts->cl);
        }
        else if(ts->chunked_encoding) {
          infof(data, "Ignore chunked response-body");
        }
        else {
          /* without content-length or chunked encoding, we
             cannot keep the connection alive since the close is
             the end signal so we bail out at once instead */
          CURL_TRC_CF(data, cf, "CONNECT: no content-length or chunked");
          ts->keepon = KEEPON_DONE;
        }
      }
      else {
        ts->keepon = KEEPON_DONE;
      }

      DEBUGASSERT(ts->keepon == KEEPON_IGNORE
                  || ts->keepon == KEEPON_DONE);
      continue;
    }

    if(cf->conn->bits.udp_tunnel_proxy) {
      result = on_resp_header_udp(data, ts, linep);
    }
    else {
      result = on_resp_header(cf, data, ts, linep);
    }
    if(result)
      return result;

    curlx_dyn_reset(&ts->rcvbuf);
  } /* while there is buffer left and loop is requested */

  if(error)
    result = CURLE_RECV_ERROR;
  *done = (ts->keepon == KEEPON_DONE);
  if(!result && *done && data->info.httpproxycode/100 != 2) {
    /* Deal with the possibly already received authenticate
       headers. 'newurl' is set to a new URL if we must loop. */
    result = Curl_http_auth_act(data);
  }
  return result;
}

static CURLcode H1_CONNECT(struct Curl_cfilter *cf,
                           struct Curl_easy *data,
                           struct h1_tunnel_state *ts)
{
  struct connectdata *conn = cf->conn;
  CURLcode result;
  bool done;

  if(tunnel_is_established(ts))
    return CURLE_OK;
  if(tunnel_is_failed(ts))
    return CURLE_RECV_ERROR; /* Need a cfilter close and new bootstrap */

  do {
    timediff_t check;

    check = Curl_timeleft(data, NULL, TRUE);
    if(check <= 0) {
      failf(data, "Proxy CONNECT aborted due to timeout");
      result = CURLE_OPERATION_TIMEDOUT;
      goto out;
    }

    switch(ts->tunnel_state) {
    case H1_TUNNEL_INIT:
      /* Prepare the CONNECT request and make a first attempt to send. */
      CURL_TRC_CF(data, cf, "CONNECT start");
      result = start_CONNECT(cf, data, ts);
      if(result)
        goto out;
      h1_tunnel_go_state(cf, ts, H1_TUNNEL_CONNECT, data);
      FALLTHROUGH();

    case H1_TUNNEL_CONNECT:
      /* see that the request is completely sent */
      CURL_TRC_CF(data, cf, "CONNECT send");
      result = send_CONNECT(cf, data, ts, &done);
      if(result || !done)
        goto out;
      h1_tunnel_go_state(cf, ts, H1_TUNNEL_RECEIVE, data);
      FALLTHROUGH();

    case H1_TUNNEL_RECEIVE:
      /* read what is there */
      CURL_TRC_CF(data, cf, "CONNECT receive");
      result = recv_CONNECT_resp(cf, data, ts, &done);
      if(Curl_pgrsUpdate(data)) {
        result = CURLE_ABORTED_BY_CALLBACK;
        goto out;
      }
      /* error or not complete yet. return for more multi-multi */
      if(result || !done)
        goto out;
      /* got it */
      h1_tunnel_go_state(cf, ts, H1_TUNNEL_RESPONSE, data);
      FALLTHROUGH();

    case H1_TUNNEL_RESPONSE:
      CURL_TRC_CF(data, cf, "CONNECT response");
      if(data->req.newurl) {
        /* not the "final" response, we need to do a follow up request.
         * If the other side indicated a connection close, or if someone
         * else told us to close this connection, do so now.
         */
        Curl_req_soft_reset(&data->req, data);
        if(ts->close_connection || conn->bits.close) {
          /* Close this filter and the sub-chain, re-connect the
           * sub-chain and continue. Closing this filter will
           * reset our tunnel state. To avoid recursion, we return
           * and expect to be called again.
           */
          CURL_TRC_CF(data, cf, "CONNECT need to close+open");
          infof(data, "Connect me again please");
          Curl_conn_cf_close(cf, data);
          connkeep(conn, "HTTP proxy CONNECT");
          result = Curl_conn_cf_connect(cf->next, data, &done);
          goto out;
        }
        else {
          /* staying on this connection, reset state */
          h1_tunnel_go_state(cf, ts, H1_TUNNEL_INIT, data);
        }
      }
      break;

    default:
      break;
    }

  } while(data->req.newurl);

  DEBUGASSERT(ts->tunnel_state == H1_TUNNEL_RESPONSE);
  if(cf->conn->bits.udp_tunnel_proxy) {
    /* MASQUE FIX: envoy and h2o has different behaviour */
    /* envoy returns 200 OK, h2o returns 101 Switching Protocols */
    if(data->info.httpproxycode != 200 && data->info.httpproxycode != 101) {
      /* a non-2xx response and we have no next URL to try. */
      Curl_safefree(data->req.newurl);
      /* failure, close this connection to avoid reuse */
      streamclose(conn, "proxy CONNECT-UDP failure");
      h1_tunnel_go_state(cf, ts, H1_TUNNEL_FAILED, data);
      failf(data, "CONNECT-UDP tunnel failed, response %d",
                                        data->req.httpcode);
      return CURLE_RECV_ERROR;
    }
  }
  else {
    if(data->info.httpproxycode/100 != 2) {
      /* a non-2xx response and we have no next URL to try. */
      Curl_safefree(data->req.newurl);
      /* failure, close this connection to avoid reuse */
      streamclose(conn, "proxy CONNECT failure");
      h1_tunnel_go_state(cf, ts, H1_TUNNEL_FAILED, data);
      failf(data, "CONNECT tunnel failed, response %d", data->req.httpcode);
      return CURLE_RECV_ERROR;
    }
  }
  /* 2xx response, SUCCESS! */
  /* 101 Switching Protocol for CONNECT-UDP */
  h1_tunnel_go_state(cf, ts, H1_TUNNEL_ESTABLISHED, data);
  if(cf->conn->bits.udp_tunnel_proxy)
    infof(data, "CONNECT-UDP tunnel established, response %d",
                                    data->info.httpproxycode);
  else
    infof(data, "CONNECT tunnel established, response %d",
                                    data->info.httpproxycode);
  result = CURLE_OK;

out:
  if(result)
    h1_tunnel_go_state(cf, ts, H1_TUNNEL_FAILED, data);
  return result;
}

static CURLcode cf_h1_proxy_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *done)
{
  CURLcode result;
  struct h1_tunnel_state *ts = cf->ctx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  CURL_TRC_CF(data, cf, "connect");
  result = cf->next->cft->do_connect(cf->next, data, done);
  if(result || !*done)
    return result;

  *done = FALSE;
  if(!ts) {
    result = tunnel_init(cf, data, &ts);
    if(result)
      return result;
    cf->ctx = ts;
  }

  /* We want "seamless" operations through HTTP proxy tunnel */

  result = H1_CONNECT(cf, data, ts);
  if(result)
    goto out;
  Curl_safefree(data->state.aptr.proxyuserpwd);

out:
  *done = (result == CURLE_OK) && tunnel_is_established(cf->ctx);
  if(*done) {
    cf->connected = TRUE;
    /* The real request will follow the CONNECT, reset request partially */
    Curl_req_soft_reset(&data->req, data);
    Curl_client_reset(data);
    Curl_pgrsSetUploadCounter(data, 0);
    Curl_pgrsSetDownloadCounter(data, 0);

    /* For UDP tunnel proxy, keep the tunnel state for ongoing operations */
    if(!cf->conn->bits.udp_tunnel_proxy) {
      tunnel_free(cf, data);
    }
  }
  return result;
}

static void cf_h1_proxy_adjust_pollset(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  struct h1_tunnel_state *ts = cf->ctx;

  if(!cf->connected) {
    /* If we are not connected, but the filter "below" is
     * and not waiting on something, we are tunneling. */
    curl_socket_t sock = Curl_conn_cf_get_socket(cf, data);
    if(ts) {
      /* when we have sent a CONNECT to a proxy, we should rather either
         wait for the socket to become readable to be able to get the
         response headers or if we are still sending the request, wait
         for write. */
      if(tunnel_want_send(ts))
        Curl_pollset_set_out_only(data, ps, sock);
      else
        Curl_pollset_set_in_only(data, ps, sock);
    }
    else
      Curl_pollset_set_out_only(data, ps, sock);
  }
}

static void cf_h1_proxy_destroy(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  CURL_TRC_CF(data, cf, "destroy");
  tunnel_free(cf, data);
}

static void cf_h1_proxy_close(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  CURL_TRC_CF(data, cf, "close");
  if(cf) {
    cf->connected = FALSE;
    if(cf->ctx) {
      h1_tunnel_go_state(cf, cf->ctx, H1_TUNNEL_INIT, data);
      /* For UDP tunnel proxy, free the tunnel state on close */
      if(cf->conn->bits.udp_tunnel_proxy) {
        tunnel_free(cf, data);
      }
    }
    if(cf->next)
      cf->next->cft->do_close(cf->next, data);
  }
}

#define HTTP_INVALID_VARINT             ((uint64_t) ~0)
#define HTTP_CAPSULE_HEADER_MAX_SIZE    10

#define foreach_http_capsule_type _ (0, DATAGRAM)
typedef enum http_capsule_type_
{
#define _(n, s) HTTP_CAPSULE_TYPE_##s = n,
  foreach_http_capsule_type
#undef _
} __attribute__((packed)) http_capsule_type_t;

static uint64_t
custom_ntohll(uint64_t value)
{
  union {
      uint64_t u64;
      uint32_t u32[2];
  } src, dst;

  src.u64 = value;

  dst.u32[0] = ntohl(src.u32[1]);
  dst.u32[1] = ntohl(src.u32[0]);

  return dst.u64;
}

static void
http_encode_varint(struct dynbuf *dyn, uint64_t value)
{
  CURLcode result;
  DEBUGASSERT(value <= 0x3FFFFFFFFFFFFFFF);

  if(value <= 0x3F) {
    uint8_t encoded;
    encoded = (char)value;
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else if(value <= 0x3FFF) {
    /* Set bits 15-14 to "01", preserve lower 14 bits */
    uint16_t encoded;
    encoded = (uint16_t)value & 0x3FFF;
    encoded = ntohs(encoded | 0x4000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else if(value <= 0x3FFFFFFF) {
    /* Set bits 31-30 to "10", preserve lower 30 bits */
    uint32_t encoded;
    encoded = (uint32_t)value & 0x3FFFFFFF;
    encoded = ntohl(encoded | 0x80000000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else {
    /* Set bits 63-62 to "11", preserve lower 62 bits */
    uint64_t encoded;
    encoded = (uint64_t)value & 0x3FFFFFFFFFFFFFFF;
    encoded = custom_ntohll(encoded | 0xC000000000000000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
}

static ssize_t
cf_h1_proxy_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                 const void *buf, size_t len, bool eos, CURLcode *err)
{
  int rv;
  CURLcode result;

  if(!cf->next)
    return CURLE_SEND_ERROR;

  if(data->conn->bits.udp_tunnel_proxy) {
    struct dynbuf dyn;

    uint8_t cap_type = 0;
    uint8_t ctx_id = 0;

    curlx_dyn_init(&dyn, HTTP_CAPSULE_HEADER_MAX_SIZE + len);

    result = curlx_dyn_addn(&dyn, &cap_type, sizeof(cap_type));

    http_encode_varint(&dyn, len + 1);

    result = curlx_dyn_addn(&dyn, &ctx_id, sizeof(ctx_id));

    result = curlx_dyn_addn(&dyn, buf, len);

    rv = cf->next->cft->do_send(cf->next, data, dyn.bufr, dyn.leng, eos, err);
  }
  else {
    rv = cf->next->cft->do_send(cf->next, data, buf, len, eos, err);
  }

  return rv;
}

#define HTTP_INVALID_VARINT             ((uint64_t) ~0)
#define HTTP_CAPSULE_HEADER_MAX_SIZE    10

# define BIO_MSG_N(array, stride, n) \
  (*(BIO_MSG *)((char *)(array) + (n)*(stride)))

static uint64_t
http_decode_varint(char **start)
{
  uint8_t first_byte;
  uint8_t bytes_left;
  uint64_t value;
  char *pos;

  pos = *start;
  first_byte = *pos;
  pos++;

  if(first_byte <= 0x3F) {
    *start = pos;
    return first_byte;
  }

  /* remove length bits, encoded in the first two bits of the first byte */
  value = first_byte & 0x3F;
  bytes_left = (1 << (first_byte >> 6)) - 1;

  do
  {
    value = (value << 8) | (uint8_t)(*pos);
    pos++;
  }
  while(--bytes_left);

  *start = pos;
  return value;
}

struct cf_h1_proxy_reader_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
};

static ssize_t proxy_nw_in_reader(void *reader_ctx,
                               unsigned char *buf, size_t buflen,
                               CURLcode *err)
{
  struct cf_h1_proxy_reader_ctx *rctx = reader_ctx;
  ssize_t nread;

  nread = rctx->cf->next->cft->do_recv(rctx->cf->next, rctx->data,
                                       (char *)buf, buflen, err);
  return nread;
}

static ssize_t process_udp_capsule(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct h1_tunnel_state *ts,
                                   char *buf, size_t len, CURLcode *err)
{
  BIO_MSG *my_bio = (BIO_MSG *)buf;
  /* MASQUE FIX: how to get this value from OpenSSL code? */
  size_t num_msg = 32;
  size_t stride = len;
  uint8_t idx = 0;
  ssize_t nread = -1;
  ssize_t bytes_consumed = 0;
  CURLcode result = CURLE_OK;

  /* Parse data in ts->recvbuf, which is formatted as udp capsules,
     into BIO_MSG structures obtained from BIO_MSG_N (my_bio, stride, idx),
     so that we can use the BIO_MSG API to read them.
     The data is formatted as:
     [capsule_type][varint_length][context_id][data] where capsule_type is 0
     for HTTP Datagram, context_id is 0 for UDP Proxying Payload, and data is
     the actual payload.
  */

  /* Process available capsules from recvbuf until full or no more data */
  while(idx < num_msg && !Curl_bufq_is_empty(&ts->recvbuf)) {
    uint8_t *context_id, *capsule_type;
    unsigned char *capsule_data;
    unsigned char *temp_buf;
    size_t read_size, temp_size = 0;
    char *decode_ptr;
    size_t offset = 0, capsule_length;

    /* Read the capsule type (should be 0 for HTTP Datagram) */
    if(!Curl_bufq_peek(&ts->recvbuf, &capsule_type, &read_size))
      break;

    if(capsule_type[0]) {
      infof(data, "Error! Invalid capsule type: %zd", *capsule_type);
      result = CURLE_RECV_ERROR;
      break;
    }

    offset += 1;

    /* Read enough bytes to determine varint length
     * NOTE handle spread over multiple chunks */
    Curl_bufq_peek_at(&ts->recvbuf, offset,
                      (const unsigned char **)&temp_buf, &temp_size);
    if(temp_size < 1)
      break;

    /* Determine varint length */
    decode_ptr = (char *)temp_buf;
    capsule_length = http_decode_varint(&decode_ptr);

    if(capsule_length == HTTP_INVALID_VARINT) {
      infof(data, "Error! Invalid varint length encoding");
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the varint in the actual buffer */
    offset += (decode_ptr - (char *)temp_buf);

    /* Read context ID (should be 0 for UDP Proxying Payload) */
    if(!Curl_bufq_peek_at(&ts->recvbuf, offset, &context_id,
                           &read_size))
      break;

    if(*context_id) {
      infof(data, "Error! Invalid context ID: %02x", context_id);
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the context ID */
    offset += 1;

    /* Adjust length (subtract context ID length) */
    capsule_length--;
    if(Curl_bufq_len(&ts->recvbuf) < offset + capsule_length) {
      infof(data, "Error! Not enough data for capsule length: %zu",
            capsule_length);
      result = CURLE_OK;
      break;
    }

    /* Get a pointer to the BIO_MSG data buffer */
    capsule_data = (unsigned char *)BIO_MSG_N(my_bio, stride, idx).data;
    size_t data_buf_size = BIO_MSG_N(my_bio, stride, idx).data_len;

    if(data_buf_size < capsule_length) {
      infof(data, "Error! Capsule too large: %zd", capsule_length);
      result = CURLE_RECV_ERROR;
      break;
    }

    Curl_bufq_skip(&ts->recvbuf, offset);
    bytes_consumed += offset;

    /* Read the actual payload data */
    size_t bytes_read = Curl_bufq_read(&ts->recvbuf, capsule_data,
                                       capsule_length, err);

    if(bytes_read != capsule_length) {
      infof(data, "Error! Read less than expected %zd %zd", capsule_length,
            bytes_read);
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Set the actual data length in the BIO_MSG structure */
    BIO_MSG_N(my_bio, stride, idx).data_len = bytes_read;

    bytes_consumed += bytes_read;

    /* Move to the next message */
    idx++;

    infof(data, "Processed UDP capsule: size=%zu length_left %zu",
          capsule_length, Curl_bufq_len(&ts->recvbuf));
  }

  nread = idx ? idx : -1;
  *err = CURLE_AGAIN;
  return nread;
}

static ssize_t
cf_h1_proxy_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                 char *buf, size_t len, CURLcode *err)
{
  struct h1_tunnel_state *ts = cf->ctx;
  ssize_t rv;

  if(!cf->next)
    return CURLE_RECV_ERROR;

  if(data->conn->bits.udp_tunnel_proxy) {
    /* For UDP tunnel proxy, we need to handle capsule processing */
    if(!ts) {
      *err = CURLE_RECV_ERROR;
      return -1;
    }

    /* First, try to read more data from the network into our recvbuf */
    if(!Curl_bufq_is_full(&ts->recvbuf)) {
      struct cf_h1_proxy_reader_ctx rctx = { cf, data };
      ssize_t nread = Curl_bufq_slurp(&ts->recvbuf, proxy_nw_in_reader,
                                      &rctx, err);
      if(nread < 0 && *err != CURLE_AGAIN) {
        return nread;
      }
    }

    /* Now process capsules from recvbuf into BIO_MSG format */
    rv = process_udp_capsule(cf, data, ts, buf, len, err);
  }
  else {
    rv = cf->next->cft->do_recv(cf->next, data, buf, len, err);
  }
  return rv;
}

struct Curl_cftype Curl_cft_h1_proxy = {
  "H1-PROXY",
  CF_TYPE_IP_CONNECT|CF_TYPE_PROXY,
  0,
  cf_h1_proxy_destroy,
  cf_h1_proxy_connect,
  cf_h1_proxy_close,
  Curl_cf_def_shutdown,
  Curl_cf_http_proxy_get_host,
  cf_h1_proxy_adjust_pollset,
  Curl_cf_def_data_pending,
  cf_h1_proxy_send,
  cf_h1_proxy_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

CURLcode Curl_cf_h1_proxy_insert_after(struct Curl_cfilter *cf_at,
                                       struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  (void)data;
  result = Curl_cf_create(&cf, &Curl_cft_h1_proxy, NULL);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  return result;
}

#endif /* !CURL_DISABLE_PROXY && ! CURL_DISABLE_HTTP */
