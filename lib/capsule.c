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

#if !defined(CURL_DISABLE_PROXY) && !defined(CURL_DISABLE_HTTP) && \
    defined(USE_NGHTTP3) && (defined(USE_OPENSSL_QUIC) || defined(USE_NGTCP2))

#include <openssl/bio.h>
#include <curl/curl.h>
#include "urldata.h"
#include "curlx/dynbuf.h"
#include "cfilters.h"
#include "curl_trc.h"
#include "bufq.h"
#include "capsule.h"


/**
 * Convert 64-bit value from network byte order to host byte order
 */
static uint64_t capsule_ntohll(uint64_t value)
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

static size_t capsule_varint_len(uint64_t value)
{
  if(value <= 0x3F)
    return 1;
  else if(value <= 0x3FFF)
    return 2;
  else if(value <= 0x3FFFFFFF)
    return 4;
  return 8;
}

/**
 * Encode a variable-length integer according to HTTP/3 spec
 * @param dyn   Dynamic buffer to write encoded varint to
 * @param value Value to encode (must be <= 0x3FFFFFFFFFFFFFFF)
 * @return CURLE_OK on success, error code on failure
 */
static CURLcode capsule_encode_varint(struct dynbuf *dyn, uint64_t value)
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
    encoded = capsule_ntohll(encoded | 0xC000000000000000);
    result = curlx_dyn_addn(dyn, &encoded, sizeof(encoded));
  }
  return result;
}

static CURLcode capsule_peek_u8(struct bufq *recvbufq,
                                size_t offset,
                                uint8_t *pbyte)
{
  const unsigned char *peek = NULL;
  size_t peeklen = 0;

  if(!Curl_bufq_peek_at(recvbufq, offset, &peek, &peeklen) || !peeklen)
    return CURLE_AGAIN;
  *pbyte = peek[0];
  return CURLE_OK;
}

static CURLcode capsule_decode_varint_at(struct bufq *recvbufq,
                                         size_t offset,
                                         uint64_t *pvalue,
                                         size_t *pconsumed)
{
  uint8_t first_byte, byte;
  uint64_t value;
  size_t nbytes;
  size_t i;
  CURLcode result;

  result = capsule_peek_u8(recvbufq, offset, &first_byte);
  if(result)
    return result;

  nbytes = (size_t)1 << (first_byte >> 6); /* 1, 2, 4 or 8 bytes */
  value = first_byte & 0x3F;

  for(i = 1; i < nbytes; ++i) {
    result = capsule_peek_u8(recvbufq, offset + i, &byte);
    if(result)
      return result;
    value = (value << 8) | byte;
  }

  *pvalue = value;
  *pconsumed = nbytes;
  return CURLE_OK;
}

CURLcode Curl_capsule_encap_udp_datagram(struct dynbuf *dyn,
                                         const void *buf, size_t blen)
{
  CURLcode result = CURLE_OK;
  uint8_t cap_type = 0; /* HTTP Datagram */
  uint8_t ctx_id = 0; /* Context ID for UDP Proxying Payload */

  curlx_dyn_init(dyn, HTTP_CAPSULE_HEADER_MAX_SIZE + blen);

  result = curlx_dyn_addn(dyn, &cap_type, sizeof(cap_type));
  if(result)
    return result;

  result = capsule_encode_varint(dyn, blen + 1);
  if(result)
    return result;

  result = curlx_dyn_addn(dyn, &ctx_id, sizeof(ctx_id));
  if(result)
    return result;

  result = curlx_dyn_addn(dyn, buf, blen);

  return result;
}

size_t Curl_capsule_udp_payload_written(size_t payload_len,
                                        size_t capsule_bytes)
{
  uint64_t capsule_len;
  size_t hdr_len = 2; /* capsule type + context ID */

  if(payload_len >= 0x3FFFFFFFFFFFFFFFULL)
    capsule_len = 0x3FFFFFFFFFFFFFFFULL;
  else
    capsule_len = (uint64_t)payload_len + 1;
  hdr_len += capsule_varint_len(capsule_len);

  if(capsule_bytes <= hdr_len)
    return 0;
  capsule_bytes -= hdr_len;
  if(capsule_bytes > payload_len)
    capsule_bytes = payload_len;
  return capsule_bytes;
}

size_t Curl_capsule_process_udp(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct bufq *recvbufq,
                                 char *buf, size_t len, CURLcode *err)
{
  /* All variable declarations at the beginning */
  BIO_MSG *my_bio = (BIO_MSG *)buf;
  BIO_MSG *bio_msg = NULL;
  const unsigned char *context_id, *capsule_type;
  unsigned char *capsule_data;
  size_t num_msg;
  size_t stride = sizeof(BIO_MSG);
  size_t read_size;
  size_t varint_len;
  size_t offset, capsule_length;
  size_t remaining_capsule_length;
  size_t bytes_read, bytes_to_read;
  size_t total_available_space;
  size_t idx = 0;
  CURLcode result = CURLE_OK;

  if(len < stride) {
    *err = CURLE_BAD_FUNCTION_ARGUMENT;
    return 0;
  }

  num_msg = len / stride;

  /* Parse data in recvbufq, which is formatted as udp capsules,
     into BIO_MSG structures obtained from BIO_MSG_N (my_bio, stride, idx),
     so that we can use the BIO_MSG API to read them.
     The data is formatted as:
     [capsule_type][varint_length][context_id][data] where capsule_type is 0
     for HTTP Datagram, context_id is 0 for UDP Proxying Payload, and data is
     the actual payload.
  */

  /* Process available capsules from recvbuf until full or no more data */
  while(idx < num_msg && !Curl_bufq_is_empty(recvbufq)) {
    offset = 0;

    /* Read the capsule type (should be 0 for HTTP Datagram) */
    if(!Curl_bufq_peek(recvbufq, &capsule_type, &read_size))
      break;

    if(capsule_type[0]) {
      infof(data, "Error! Invalid capsule type: %d", capsule_type[0]);
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the capsule type */
    offset += 1;

    result = capsule_decode_varint_at(recvbufq, offset, &capsule_length,
                                      &varint_len);
    if(result == CURLE_AGAIN) {
      result = CURLE_OK;
      break;
    }
    else if(result) {
      result = CURLE_RECV_ERROR;
      break;
    }
    offset += varint_len;

    /* Read context ID (should be 0 for UDP Proxying Payload) */
    if(!Curl_bufq_peek_at(recvbufq, offset, &context_id, &read_size) ||
       !read_size)
      break;

    if(*context_id) {
      infof(data, "Error! Invalid context ID: %02x", *context_id);
      result = CURLE_RECV_ERROR;
      break;
    }

    /* Skip over the context ID */
    offset += 1;

    /* Adjust length (subtract context ID length) */
    if(!capsule_length) {
      infof(data, "Error! Invalid capsule length: 0");
      result = CURLE_RECV_ERROR;
      break;
    }
    capsule_length--;
    if(Curl_bufq_len(recvbufq) < offset + capsule_length) {
      infof(data, "Not enough data for capsule length: %zu, "
            "retry after reading more data", capsule_length);
      result = CURLE_OK;
      break;
    }

    /* Handle large capsules that span multiple BIO_MSG buffers */
    remaining_capsule_length = capsule_length;

    /* Check if we have enough BIO_MSG buffers to fit the entire capsule */
    bio_msg = &BIO_MSG_N(my_bio, stride, idx);
    total_available_space = (num_msg - idx) * bio_msg->data_len;

    if(total_available_space < capsule_length) {
      /* Not enough space in this call - we need to buffer for next call */
      infof(data, "Capsule too large for available buffers: capsule=%zu,"
            "available_space=%zu, retry after reading more data",
            capsule_length, total_available_space);
      result = CURLE_AGAIN;
      break;
    }

    /* Skip capsule header (type + varint + context_id) in recvbuf */
    Curl_bufq_skip(recvbufq, offset);

    /* Read capsule data across multiple BIO_MSG buffers as needed */
    while(remaining_capsule_length > 0 && idx < num_msg) {
      /* Get pointer to current BIO_MSG data buffer */
      bio_msg = &BIO_MSG_N(my_bio, stride, idx);
      capsule_data = (unsigned char *)bio_msg->data;

      /* Determine how much to read into this buffer */
      bytes_to_read = remaining_capsule_length < bio_msg->data_len ?
                            remaining_capsule_length : bio_msg->data_len;

      /* Read data into current buffer */
      bytes_read = 0;
      *err = Curl_bufq_read(recvbufq, capsule_data,
                            bytes_to_read, &bytes_read);

      if(bytes_read != bytes_to_read) {
        infof(data, "Error! Read less than expected %zu %zu",
              bytes_to_read, bytes_read);
        result = CURLE_RECV_ERROR;
        break;
      }

      /* Set the actual data length in the BIO_MSG structure */
      bio_msg->data_len = bytes_read;
      remaining_capsule_length -= bytes_read;

      /* Move to next BIO_MSG buffer */
      idx++;
    }

    /* Verify we read the entire capsule */
    if(remaining_capsule_length > 0) {
      infof(data, "Error! Could not fit entire capsule: remaining=%zu",
            remaining_capsule_length);
      result = CURLE_RECV_ERROR;
      break;
    }

    CURL_TRC_CF(data, cf, "Processed UDP capsule: size=%zu length_left %zu",
                           capsule_length, Curl_bufq_len(recvbufq));
  }

  if(result != CURLE_OK)
    *err = result;
  else if(idx)
    *err = CURLE_OK;
  else
    *err = CURLE_AGAIN;
  return (idx ? idx : 0);
}

size_t Curl_capsule_process_udp_raw(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct bufq *recvbufq,
                                    unsigned char *buf, size_t len,
                                    CURLcode *err)
{
  const unsigned char *context_id, *capsule_type;
  size_t read_size, varint_len;
  size_t offset, capsule_length, payload_len;
  size_t bytes_read = 0;
  CURLcode result = CURLE_OK;

  if(!len) {
    *err = CURLE_BAD_FUNCTION_ARGUMENT;
    return 0;
  }

  if(Curl_bufq_is_empty(recvbufq)) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(!Curl_bufq_peek(recvbufq, &capsule_type, &read_size) || !read_size) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(capsule_type[0]) {
    infof(data, "Error! Invalid capsule type: %d", capsule_type[0]);
    *err = CURLE_RECV_ERROR;
    return 0;
  }

  offset = 1;
  result = capsule_decode_varint_at(recvbufq, offset, &capsule_length,
                                    &varint_len);
  if(result == CURLE_AGAIN) {
    *err = CURLE_AGAIN;
    return 0;
  }
  else if(result) {
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  offset += varint_len;

  if(!Curl_bufq_peek_at(recvbufq, offset, &context_id, &read_size) ||
     !read_size) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(*context_id) {
    infof(data, "Error! Invalid context ID: %02x", *context_id);
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  offset += 1;

  if(!capsule_length) {
    infof(data, "Error! Invalid capsule length: 0");
    *err = CURLE_RECV_ERROR;
    return 0;
  }
  payload_len = capsule_length - 1;

  if(Curl_bufq_len(recvbufq) < offset + payload_len) {
    *err = CURLE_AGAIN;
    return 0;
  }

  if(payload_len > len) {
    infof(data, "UDP payload does not fit destination buffer: %zu > %zu",
          payload_len, len);
    *err = CURLE_AGAIN;
    return 0;
  }

  Curl_bufq_skip(recvbufq, offset);
  result = Curl_bufq_read(recvbufq, buf, payload_len, &bytes_read);
  if(result || (bytes_read != payload_len)) {
    infof(data, "Error! Read less than expected %zu %zu",
          payload_len, bytes_read);
    *err = CURLE_RECV_ERROR;
    return 0;
  }

  CURL_TRC_CF(data, cf, "Processed UDP capsule raw: size=%zu length_left %zu",
              payload_len, Curl_bufq_len(recvbufq));
  *err = CURLE_OK;
  return bytes_read;
}

#endif /* !CURL_DISABLE_PROXY && !CURL_DISABLE_HTTP &&
                USE_NGHTTP3 && (USE_OPENSSL_QUIC || USE_NGTCP2) */
