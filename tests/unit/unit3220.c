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

#include "unitcheck.h"

#include "bufq.h"
#include "capsule.h"

static void queue_bytes(struct bufq *q, const unsigned char *src, size_t len)
{
  size_t nwritten = 0;
  CURLcode result = Curl_bufq_write(q, src, len, &nwritten);
  fail_unless(result == CURLE_OK, "queue failed");
  fail_unless(nwritten == len, "queue short write");
}

static void check_capsule_result(struct bufq *q,
                                 const unsigned char *capsule, size_t capslen,
                                 size_t outlen, CURLcode expect_err,
                                 size_t expect_nread)
{
  unsigned char out[32];
  CURLcode err = CURLE_OK;
  size_t nread;

  memset(out, 0, sizeof(out));
  Curl_bufq_reset(q);
  if(capsule && capslen)
    queue_bytes(q, capsule, capslen);

  nread = Curl_capsule_process_udp_raw(NULL, NULL, q, out, outlen, &err);
  fail_unless(err == expect_err, "unexpected capsule error");
  fail_unless(nread == expect_nread, "unexpected capsule read size");
}

static CURLcode test_unit3220(const char *arg)
{
  UNITTEST_BEGIN_SIMPLE

#ifdef USE_NGTCP2
  struct bufq q;
  unsigned char out[8];
  CURLcode err = CURLE_OK;
  size_t nread;
  const unsigned char invalid_type[] = { 0x01 };
  const unsigned char partial_len[] = { 0x00, 0x40 };
  const unsigned char invalid_context[] = { 0x00, 0x01, 0x01 };
  const unsigned char invalid_caps_len[] = { 0x00, 0x00, 0x00 };
  const unsigned char partial_payload[] = { 0x00, 0x04, 0x00, 0x11, 0x22 };
  const unsigned char payload_3b[] = { 0x00, 0x04, 0x00, 0x11, 0x22, 0x33 };
  const unsigned char payload_empty[] = { 0x00, 0x01, 0x00 };

  (void)arg;

  Curl_bufq_init2(&q, 32, 4, BUFQ_OPT_NONE);

  check_capsule_result(&q, NULL, 0, 0, CURLE_BAD_FUNCTION_ARGUMENT, 0);
  check_capsule_result(&q, NULL, 0, sizeof(out), CURLE_AGAIN, 0);
  check_capsule_result(&q, invalid_type, sizeof(invalid_type), sizeof(out),
                       CURLE_RECV_ERROR, 0);
  check_capsule_result(&q, partial_len, sizeof(partial_len), sizeof(out),
                       CURLE_AGAIN, 0);
  check_capsule_result(&q, invalid_context, sizeof(invalid_context),
                       sizeof(out), CURLE_RECV_ERROR, 0);
  check_capsule_result(&q, invalid_caps_len, sizeof(invalid_caps_len),
                       sizeof(out), CURLE_RECV_ERROR, 0);
  check_capsule_result(&q, partial_payload, sizeof(partial_payload),
                       sizeof(out), CURLE_AGAIN, 0);

  /* payload does not fit output buffer -> AGAIN and no consumption */
  Curl_bufq_reset(&q);
  queue_bytes(&q, payload_3b, sizeof(payload_3b));
  nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, 2, &err);
  fail_unless(err == CURLE_AGAIN, "expected AGAIN for short output buffer");
  fail_unless(nread == 0, "expected zero read on short output buffer");
  fail_unless(Curl_bufq_len(&q) == sizeof(payload_3b),
              "capsule must remain buffered on short output");

  /* zero-length UDP payload is accepted and consumed */
  Curl_bufq_reset(&q);
  queue_bytes(&q, payload_empty, sizeof(payload_empty));
  nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, sizeof(out), &err);
  fail_unless(err == CURLE_OK, "zero-length UDP payload should succeed");
  fail_unless(nread == 0, "zero-length UDP payload should read zero");
  fail_unless(Curl_bufq_is_empty(&q), "zero-length capsule must be consumed");

  /* normal payload decode */
  Curl_bufq_reset(&q);
  queue_bytes(&q, payload_3b, sizeof(payload_3b));
  memset(out, 0, sizeof(out));
  nread = Curl_capsule_process_udp_raw(NULL, NULL, &q, out, sizeof(out), &err);
  fail_unless(err == CURLE_OK, "payload decode should succeed");
  fail_unless(nread == 3, "payload decode size mismatch");
  fail_unless(out[0] == 0x11 && out[1] == 0x22 && out[2] == 0x33,
              "payload decode bytes mismatch");
  fail_unless(Curl_bufq_is_empty(&q), "payload capsule must be consumed");

  Curl_bufq_free(&q);
#else
  (void)arg;
#endif

  UNITTEST_END_SIMPLE
}
