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
#include "dynbuf.h"
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
#include "curlx.h"
#include "vtls/vtls.h"
#include "transfer.h"
#include "multiif.h"
#include "strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


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
  Curl_dyn_reset(&ts->rcvbuf);
  Curl_dyn_reset(&ts->request_data);
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

  Curl_dyn_init(&ts->rcvbuf, DYN_PROXY_CONNECT_HEADERS);
  Curl_dyn_init(&ts->request_data, DYN_HTTP_REQUEST);
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
    Curl_dyn_reset(&ts->rcvbuf);
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
    if(cf->conn->bits.udp_tunnel_proxy) {
      infof(data, "CONNECT-UDP phase completed");
    }
    else {
      infof(data, "CONNECT phase completed");
    }
    data->state.authproxy.done = TRUE;
    data->state.authproxy.multipass = FALSE;
    FALLTHROUGH();
  case H1_TUNNEL_FAILED:
    if(new_state == H1_TUNNEL_FAILED)
      CURL_TRC_CF(data, cf, "new tunnel state 'failed'");
    ts->tunnel_state = new_state;
    Curl_dyn_reset(&ts->rcvbuf);
    Curl_dyn_reset(&ts->request_data);
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
      Curl_dyn_free(&ts->rcvbuf);
      Curl_dyn_free(&ts->request_data);
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

  if(cf->conn->bits.udp_tunnel_proxy) {
    infof(data, "Establish HTTP UDP proxy tunnel to %s", req->authority);
  }
  else {
    infof(data, "Establish HTTP proxy tunnel to %s", req->authority);
  }

  Curl_dyn_reset(&ts->request_data);
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
  char *buf = Curl_dyn_ptr(&ts->request_data);
  size_t request_len = Curl_dyn_len(&ts->request_data);
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
      infof(data, "ABASU TEST CONNECT-UDP Response Transfer-Encoding");
      ts->chunked_encoding = TRUE;
      /* reset our chunky engine */
      Curl_httpchunk_reset(data, &ts->ch, TRUE);
    }
  }
  else if(checkprefix("Capsule-protocol:", header)) {
    if(Curl_compareheader(header,
                           STRCONST("Capsule-protocol:"),
                           STRCONST("?1"))) {
      infof(data, "ABASU TEST CONNECT-UDP Response Capsule-protocol");
    }
  }
  else if(Curl_compareheader(header,
                              STRCONST("Connection:"), STRCONST("close"))) {
    ts->close_connection = TRUE;
    infof(data, "ABASU TEST CONNECT-UDP Response Connection: close");
  }
  else if(!strncmp(header, "HTTP/1.", 7) &&
           ((header[7] == '0') || (header[7] == '1')) &&
           (header[8] == ' ') &&
           ISDIGIT(header[9]) && ISDIGIT(header[10]) && ISDIGIT(header[11]) &&
           !ISDIGIT(header[12])) {
    /* store the HTTP code from the proxy */
    data->info.httpproxycode = k->httpcode = (header[9] - '0') * 100 +
                          (header[10] - '0') * 10 + (header[11] - '0');
    infof(data, "ABASU TEST CONNECT-UDP Response 200 OK");
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
      if(Curl_str_numblanks(&p, &ts->cl)) {
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

    if(Curl_dyn_addn(&ts->rcvbuf, &byte, 1)) {
      failf(data, "CONNECT response too large");
      return CURLE_RECV_ERROR;
    }

    /* if this is not the end of a header line then continue */
    if(byte != 0x0a)
      continue;

    ts->headerlines++;
    linep = Curl_dyn_ptr(&ts->rcvbuf);
    line_len = Curl_dyn_len(&ts->rcvbuf); /* amount of bytes in this line */

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

    Curl_dyn_reset(&ts->rcvbuf);
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
  if(data->info.httpproxycode/100 != 2) {
    /* a non-2xx response and we have no next URL to try. */
    Curl_safefree(data->req.newurl);
    /* failure, close this connection to avoid reuse */
    streamclose(conn, "proxy CONNECT failure");
    h1_tunnel_go_state(cf, ts, H1_TUNNEL_FAILED, data);
    failf(data, "CONNECT tunnel failed, response %d", data->req.httpcode);
    return CURLE_RECV_ERROR;
  }
  /* 2xx response, SUCCESS! */
  h1_tunnel_go_state(cf, ts, H1_TUNNEL_ESTABLISHED, data);
  if(cf->conn->bits.udp_tunnel_proxy) {
    infof(data, "CONNECT-UDP tunnel established, response %d",
                data->info.httpproxycode);
  }
  else {
  infof(data, "CONNECT tunnel established, response %d",
        data->info.httpproxycode);
  }
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

    tunnel_free(cf, data);
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
  DEBUGASSERT(value <= 0x3FFFFFFFFFFFFFFF);

  if(value <= 0x3F) {
    uint8_t encoded;
    encoded = (char)value;
    Curl_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else if(value <= 0x3FFF) {
    /* Set bits 15-14 to "01", preserve lower 14 bits */
    uint16_t encoded;
    encoded = (uint16_t)value & 0x3FFF;
    encoded = ntohs(encoded | 0x4000);
    Curl_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else if(value <= 0x3FFFFFFF) {
    /* Set bits 31-30 to "10", preserve lower 30 bits */
    uint32_t encoded;
    encoded = (uint32_t)value & 0x3FFFFFFF;
    encoded = ntohl(encoded | 0x80000000);
    Curl_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  else {
    /* Set bits 63-62 to "11", preserve lower 62 bits */
    uint64_t encoded;
    encoded = (uint64_t)value & 0x3FFFFFFFFFFFFFFF;
    encoded = custom_ntohll(encoded | 0xC000000000000000);
    Curl_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
}

static CURLcode
encap_udp_payload_datagram(struct dynbuf *dyn,
                           char **buf, size_t *blen)
{
  CURLcode result = CURLE_OK;
  uint8_t cap_type = 0; /* HTTP Datagram */
  uint8_t ctx_id = 0; /* Context ID for UDP Proxying Payload */

  Curl_dyn_init(dyn, HTTP_CAPSULE_HEADER_MAX_SIZE + *blen);

  Curl_dyn_addn(dyn, &cap_type, sizeof(cap_type));

  http_encode_varint(dyn, *blen + 1);

  Curl_dyn_addn(dyn, &ctx_id, sizeof(ctx_id));

  Curl_dyn_addn(dyn, buf, *blen);

  *buf = dyn->bufr;
  *blen = dyn->leng;

  return result;
}

static ssize_t
cf_h1_proxy_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                 const void *buf, size_t len, bool eos, CURLcode *err)
{
  int rv;
  if(!cf->next)
    CURLE_SEND_ERROR;

  if(data->conn->bits.udp_tunnel_proxy) {
    struct dynbuf dyn;
    /* MASQUE FIX : WHY IS THIS FAILING? :( */
    /* encap_udp_payload_datagram(&dyn, &buf, &len); */

    uint8_t cap_type = 0;
    uint8_t ctx_id = 0;

    Curl_dyn_init(&dyn, HTTP_CAPSULE_HEADER_MAX_SIZE + len);

    Curl_dyn_addn(&dyn, &cap_type, sizeof(cap_type));

    http_encode_varint(&dyn, len + 1);

    Curl_dyn_addn(&dyn, &ctx_id, sizeof(ctx_id));

    Curl_dyn_addn(&dyn, buf, len);

    rv = cf->next->cft->do_send(cf->next, data, dyn.bufr, dyn.leng, eos, err);
  }
  else {
    rv = cf->next->cft->do_send(cf->next, data, buf, len, eos, err);
  }

  return rv;
}

static uint8_t
http_var_length_bytes(char *start)
{
  uint8_t first_byte = *start;

  /* Check the first 2 bits */
  if((first_byte & 0xC0) == 0x00) /* 00xxxxxx */
    return 1;
  else if((first_byte & 0xC0) == 0x40) /* 01xxxxxx */
    return 2;
  else if((first_byte & 0xC0) == 0x80) /* 10xxxxxx */
    return 4;
  else /* 11xxxxxx */
    return 8;
}

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

#define TMP_BUF_SIZE (size_t) 131072
static uint64_t head = 0;
static uint64_t tail = 0;
static char tmp_buf[TMP_BUF_SIZE] = {0};
/* MASQUE FIX: DELETE, ONLY FOR DEBUGGING */
static uint64_t written = 0;
static uint64_t received = 0;

# define BIO_MSG_N(array, stride, n) \
  (*(BIO_MSG *)((char *)(array) + (n)*(stride)))

/* Add data to the circular queue, handling wrapping if needed */
static CURLcode
add_to_circular_queue(struct Curl_easy *data,
                      char *buf, size_t stride, uint8_t idx)
{
  BIO_MSG *my_bio = (BIO_MSG *)buf;
  char *stream_data;
  size_t stream_data_len;
  size_t remaining_space;
  size_t bytes_to_copy;

  /* Calculate remaining space in tmp_buf */
  remaining_space = (head <= tail) ?
                    (TMP_BUF_SIZE - tail + head) :
                    (head - tail);

  stream_data = (char *)(BIO_MSG_N(my_bio, stride, idx).data);
  stream_data_len = (size_t)(BIO_MSG_N(my_bio, stride, idx).data_len);
  /* infof(data, "ABASU TEST %lld stream data len received",
              stream_data_len); */

  if(stream_data_len > remaining_space) {
    /* Ideally we should not be hitting this case */
    infof(data, "Buffer overflow - not enough space in circular buffer");
    abort();
    return CURLE_TOO_LARGE;
  }

  /* Copy data into circular queue */
  if(tail + stream_data_len < TMP_BUF_SIZE) {
    /* Continuous copy */
    memcpy(tmp_buf + tail, stream_data, stream_data_len);
    tail += stream_data_len;
    if(tail == TMP_BUF_SIZE)
      tail = 0;
  }
  else {
    /* Split copy into circular queue */
    bytes_to_copy = TMP_BUF_SIZE - tail;
    memcpy(tmp_buf + tail, stream_data, bytes_to_copy);
    memcpy(tmp_buf, stream_data + bytes_to_copy,
            stream_data_len - bytes_to_copy);
    tail = stream_data_len - bytes_to_copy;
  }
  /* MASQUE FIX: DELETE, ONLY FOR DEBUGGING */
  received += stream_data_len;

  return CURLE_OK;
}

/* | <empty> | <data> | <empty> */
/*         head      tail       */
/* ..............OR............ */
/* | <data> | <empty> | <data>  */
/*         tail      head       */

static CURLcode
process_chunked_capsules(struct Curl_easy *data,
                         char *buf, size_t stride, size_t idx)
{
  char *chunk_start;
  char *capsule_start;
  char *pos;
  size_t tot_avail_bytes;
  size_t unwrapped_bytes;
  char chunk_size[4] = {0};
  uint8_t chunk_len_bytes;
  curl_off_t chunk_len;
  size_t var_enc_bytes;
  uint64_t capsule_length;
  uint64_t output_len = 0;
  uint64_t offset;
  size_t bytes_to_copy;

  BIO_MSG *my_bio = (BIO_MSG*)buf;
  char *dgram = (char *)(BIO_MSG_N(my_bio, stride, idx).data);

  /* Process capsules from circular buffer */
  /* Calculate available data */
  tot_avail_bytes = (tail >= head) ?
                    (tail - head) :
                    (TMP_BUF_SIZE - head + tail);

  /* Need minimum 8 bytes */
  if(tot_avail_bytes < 8)
    return CURLE_RECV_ERROR;

  unwrapped_bytes = (head < tail) ?
                    (tail - head) :
                    (TMP_BUF_SIZE - head);

  chunk_start = tmp_buf + head;
  /* Find the first \r\n */
  char *first_crlf = strstr(chunk_start, "\r\n");
  if(!first_crlf) {
    infof(data, "Cannot find chunk start");
    return CURLE_RECV_ERROR;
  }

  /* Extract the chunk len from the buf (stored in ASCII as hex) */
  chunk_len_bytes = first_crlf - chunk_start;
  if(chunk_len_bytes >= sizeof(chunk_size)) {
    infof(data, "Chunk len exceeds max expected size of 65535");
    return CURLE_RECV_ERROR;
  }
  memcpy(chunk_size, chunk_start, chunk_len_bytes);

  /* Convert the hex string to int */
  Curl_str_number(&chunk_size, &chunk_len, 0xFFFF);
  if(chunk_len == 0) {
    infof(data, "Invalid chunk length");
    return CURLE_RECV_ERROR;
  }

  /* Point to start of data after first \r\n */
  capsule_start = first_crlf + 2;
  unwrapped_bytes = unwrapped_bytes - chunk_len_bytes - 2;
  tot_avail_bytes = tot_avail_bytes - chunk_len_bytes - 2;

  /* Verify capsule starts with 0x00 */
  if(capsule_start[0] != 0x00) {
    infof(data, "Invalid capsule start byte: %02x", capsule_start[0]);
    return CURLE_RECV_ERROR;
  }
  capsule_start++;
  unwrapped_bytes--;
  tot_avail_bytes--;

  pos = capsule_start;
  var_enc_bytes = http_var_length_bytes(pos);
  /* Cannot process capsule length since we do not have enough bytes */
  if(var_enc_bytes > tot_avail_bytes)
    return CURLE_RECV_ERROR;

  if(var_enc_bytes + 1 > unwrapped_bytes) {
    /* Need to handle wrapped length value */
    char temp[8];
    size_t first = unwrapped_bytes;
    size_t second = var_enc_bytes - unwrapped_bytes;

    memcpy(temp, pos, first);
    memcpy(temp + first, tmp_buf, second);
    pos = tmp_buf + second;
    char *decode = &temp[0];
    capsule_length = http_decode_varint(&decode);
    capsule_start = pos;
    unwrapped_bytes = tail - second;
    tot_avail_bytes -= var_enc_bytes;
  }
  else {
    capsule_length = http_decode_varint(&pos);
    capsule_start = pos;
    unwrapped_bytes -= var_enc_bytes;
    tot_avail_bytes -= var_enc_bytes;
  }

  /* Verify context ID is 0x00 */
  if(capsule_start[0] != 0x00) {
    infof(data, "Invalid context ID: %02x", capsule_start[0]);
    return CURLE_RECV_ERROR;
  }
  capsule_start++;
  unwrapped_bytes--;
  tot_avail_bytes--;
  capsule_length--; /* Account for the context ID byte */

  /* Cannot process capsule because we do not have enough bytes */
  if(capsule_length > tot_avail_bytes + 2)
    return CURLE_RECV_ERROR;;

  offset = chunk_len_bytes + 2 + var_enc_bytes + 2;
  /* Check if the chunked data actually ends with /r/n */
  if(head + offset + capsule_length <= TMP_BUF_SIZE) {
    if(capsule_start[capsule_length] != '\r'
          || capsule_start[capsule_length + 1] != '\n') {
      infof(data, "Cannot find chunk end 1");
      return CURLE_RECV_ERROR;
    }
  }
  else {
    bytes_to_copy = TMP_BUF_SIZE - (head + offset);
    if(tmp_buf[capsule_length - bytes_to_copy] != '\r'
          || tmp_buf[capsule_length - bytes_to_copy + 1] != '\n') {
      infof(data, "Cannot find chunk end 2");
      return CURLE_RECV_ERROR;
    }
  }

  /* Copy payload, handling wrap if needed */
  if(head + offset + capsule_length <= TMP_BUF_SIZE) {
    /* Continuous copy */
    memcpy(dgram, capsule_start, capsule_length);
  }
  else {
    /* Split circular copy */
    bytes_to_copy = TMP_BUF_SIZE - (head + offset);
    memcpy(dgram, capsule_start, bytes_to_copy);
    memcpy(dgram + bytes_to_copy, tmp_buf,
            capsule_length - bytes_to_copy);
  }

  BIO_MSG_N(my_bio, stride, idx).data_len = capsule_length;
  /* infof(data, "ABASU TEST %lld dgram filled",
    capsule_length); */
  /* Update head */
  head += (offset + capsule_length + 2);
  if(head >= TMP_BUF_SIZE)
    head -= TMP_BUF_SIZE;

  /* MASQUE FIX: DELETE, ONLY FOR DEBUGGING */
  written += (offset + capsule_length + 2);
  return CURLE_OK;
}

static size_t
decap_udp_payload_datagram2(struct Curl_easy *data,
                            char *buf, uint8_t count,
                            size_t stride)
{
  size_t idx;
  size_t last_cap = 0;
  /* MASQUE FIX: how to get this value from OpenSSL code? */
  size_t num_msg = 32;
  CURLcode res;
  infof(data, "ABASU TEST %d filled buf received", count);

  for(idx = 0; idx < count; idx++) {
    /* append data from all the filled buffers in BIO_MSG to tmp_buf */
    res = add_to_circular_queue(data, buf, stride, idx);
    if(res != CURLE_OK)
      break;

    /* process capsules from circular buffer */
    res = process_chunked_capsules(data, buf, stride, idx);
    if(res != CURLE_OK)
      break;
    last_cap = idx + 1;
  }

  /* process capsules from circular buffer */
  for(; idx < num_msg; idx++) {
    res = process_chunked_capsules(data, buf, stride, idx);
    if(res != CURLE_OK)
      break;
    last_cap = idx + 1;
  }

  infof(data, "ABASU TEST %d filled dgram sent", idx);
  if(head == tail) {
    head = 0;
    tail = 0;
  }
  if(tail < head)
    infof(data, "ABASU TEST "
      "head=%lld, tail=%lld, written=%lld, received=%lld",
      head, tail, written, received);
  return idx;
}

static int
decap_udp_payload_datagram(struct Curl_easy *data,
                           char *buf, int *len)
{
  /* When Transfer Encoding: Chunked, the following is the data
     format on the wire : <xxx>\r\n<Capsule>\r\n */

  /* Find the first \r\n */
  char *first_crlf = strstr(buf, "\r\n");
  if(!first_crlf)
    abort();

  /* Extract the chunk len from the buf (stored in ASCII as hex) */
  char chunk_size[4] = {0};
  uint8_t chunk_len_bytes = first_crlf - buf;
  if(chunk_len_bytes >= sizeof(chunk_size))
    abort();
  memcpy(chunk_size, buf, chunk_len_bytes);

  /* Convert the hex string to int */
  curl_off_t chunk_len;
  Curl_str_number(&chunk_size, &chunk_len, 0xFFFF);
  if(chunk_len == 0)
    abort();

  /* Point to start of data after first \r\n */
  char *capsule_start = first_crlf + 2;

  /* RFC9297: Check if the first byte in the capsule is 0x00
     Capsule Type: DATAGRAM (0x00) */
  if(capsule_start[0] != 0x00)
    abort();
  capsule_start++;

  uint64_t data_len = http_decode_varint(&capsule_start);

  /* RFC9298: Check if the context ID is 0x00
     Context ID: 0x00 (UDP Proxying Payload) */
  if(capsule_start[0] != 0x00)
    abort();
  capsule_start++;
  data_len--;

  /* Check if the chunked data actually ends with /r/n */
  if(capsule_start[data_len] != '\r' || capsule_start[data_len + 1] != '\n')
    abort();

  infof(data, "ABASU TESTING ............... "
        "............... len=%d, chunk_len=%d, data_len=%d",
        *len, chunk_len, data_len);

  memcpy(buf, capsule_start, data_len);
  *len = data_len;

  return 0;
}

/* ABASU FIX: Read multiple capsules */
static ssize_t
cf_h1_proxy_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                 char *buf, size_t len, CURLcode *err)
{
  int rv;
  if(!cf->next)
    CURLE_RECV_ERROR;

  /*
  if(data->conn->bits.udp_tunnel_proxy)
    decap_udp_payload_datagram(data, buf, &rv);
  */
  if(data->conn->bits.udp_tunnel_proxy) {
    BIO_MSG *my_bio = (BIO_MSG*)buf;
    /* MASQUE FIX: how to get this value from OpenSSL code? */
    size_t num_msg = 32;
    size_t stride = len;
    uint8_t idx = 0;
    for(idx = 0; idx < num_msg; idx++) {
      rv = cf->next->cft->do_recv(cf->next, data,
                          (char *)(BIO_MSG_N(my_bio, stride, idx).data),
                          (size_t)(BIO_MSG_N(my_bio, stride, idx).data_len),
                          err);
      if(rv < 0)
        break;
      BIO_MSG_N(my_bio, stride, idx).data_len = rv;
    }
    if(idx > 0)
      rv = decap_udp_payload_datagram2(data, (char *)my_bio, idx, stride);
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
