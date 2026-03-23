#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#
import os
import subprocess
import time

import pytest

from testenv import Env, CurlClient


def _download_path(curl: CurlClient) -> str:
    return os.path.join(curl.run_dir, 'download_#1.data')


def _check_download_message(curl: CurlClient, expected: str):
    dpath = _download_path(curl)
    assert os.path.exists(dpath), f"Download file not found: {dpath}"
    with open(dpath, 'r') as fd:
        content = fd.read()
    assert expected in content, f"Unexpected response content: {content}"


def _nghttpx_proxy_args(env: Env, nghttpx, proxy_proto: str,
                        tunnel: bool, tunneludp: bool):
    xargs = [
        '--proxy', f'https://{env.proxy_domain}:{nghttpx._port}/',
        '--resolve', f'{env.proxy_domain}:{nghttpx._port}:127.0.0.1',
        '--proxy-cacert', env.ca.cert_file
    ]
    if proxy_proto == 'h3':
        xargs.append('--proxy-http3')
    elif proxy_proto == 'h2':
        xargs.append('--proxy-http2')

    if tunnel:
        xargs.append('--proxytunnel')
    elif tunneludp:
        xargs.append('--proxyudptunnel')

    xargs.extend(['--cacert', env.ca.cert_file, '--proxy-insecure'])
    return xargs


def _h2o_proxy_args(env: Env, h2o_proxy, proxy_proto: str,
                    tunnel: bool, tunneludp: bool):
    if proxy_proto == 'h3':
        pport = h2o_proxy._port
    elif proxy_proto == 'h2':
        pport = h2o_proxy._h2_port
    else:
        pport = h2o_proxy._h1_port

    xargs = [
        '--proxy', f'https://{env.proxy_domain}:{pport}/',
        '--resolve', f'{env.proxy_domain}:{pport}:127.0.0.1',
        '--proxy-cacert', env.ca.cert_file
    ]
    if proxy_proto == 'h2':
        xargs.append('--proxy-http2')
    elif proxy_proto == 'h3':
        xargs.append('--proxy-http3')

    if tunnel:
        xargs.append('--proxytunnel')
    elif tunneludp:
        xargs.append('--proxyudptunnel')

    xargs.extend(['--cacert', env.ca.cert_file, '--proxy-insecure'])
    return xargs


class TestH3ProxySuccess:
    """Success matrix for HTTP/3 proxy CONNECT / CONNECT-UDP."""

    pytestmark = [
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                           reason='curl lacks HTTPS-proxy support'),
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                           reason='curl lacks HTTP/3 support'),
        pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                           reason='only supported with nghttp3'),
        pytest.mark.skipif(condition=not Env.have_h2o(),
                           reason='no h2o available'),
    ]

    @pytest.mark.parametrize(
        ['alpn_proto', 'proxy_proto', 'tunnel', 'tunneludp'],
        [
            pytest.param('http/1.1', 'h3', True, False,
                         id='h1_over_h3_proxytunnel'),
            pytest.param('h2', 'h3', True, False,
                         marks=pytest.mark.skipif(
                             condition=not Env.curl_uses_lib('nghttp2'),
                             reason='only supported with nghttp2'),
                         id='h2_over_h3_proxytunnel'),
            pytest.param('h3', 'h3', False, True,
                         id='h3_over_h3_proxyudptunnel'),
            pytest.param('h3', 'h2', False, True,
                         marks=pytest.mark.skipif(
                             condition=not Env.curl_uses_lib('nghttp2'),
                             reason='only supported with nghttp2'),
                         id='h3_over_h2_proxyudptunnel'),
            pytest.param('h3', 'http/1.1', False, True,
                         id='h3_over_h1_proxyudptunnel'),
        ]
    )
    def test_success_matrix(self, env: Env, h2o_server, h2o_proxy,
                            alpn_proto, proxy_proto, tunnel, tunneludp):
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = _h2o_proxy_args(env, h2o_proxy, proxy_proto,
                                     tunnel, tunneludp)
        proxy_args.append('--insecure')

        r = curl.http_download(urls=[url], alpn_proto=alpn_proto, with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)
        _check_download_message(curl, '"message": "Hello from h2o HTTP/3 server"')


class TestH3ProxyFailure:
    """Failure matrix when proxy side does not support requested mode."""

    pytestmark = [
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                           reason='curl lacks HTTPS-proxy support'),
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                           reason='curl lacks HTTP/3 support'),
        pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                           reason='only supported with nghttp3'),
        pytest.mark.skipif(condition=not Env.have_nghttpx(),
                           reason='no nghttpx available'),
    ]

    @pytest.mark.parametrize(
        ['alpn_proto', 'proxy_proto', 'tunnel', 'tunneludp', 'exp_err'],
        [
            pytest.param('http/1.1', 'h3', True, False,
                         'failed: could not connect to server',
                         id='fail_h1_over_h3_proxytunnel'),
            pytest.param('h2', 'h3', True, False,
                         'failed: could not connect to server',
                         marks=pytest.mark.skipif(
                             condition=not Env.curl_uses_lib('nghttp2'),
                             reason='only supported with nghttp2'),
                         id='fail_h2_over_h3_proxytunnel'),
            pytest.param('h3', 'h3', False, True,
                         'failed: could not connect to server',
                         id='fail_h3_over_h3_proxyudptunnel'),
            pytest.param('h3', 'h2', False, True,
                         'connect-udp response status 400',
                         marks=pytest.mark.skipif(
                             condition=not Env.curl_uses_lib('nghttp2'),
                             reason='only supported with nghttp2'),
                         id='fail_h3_over_h2_proxyudptunnel'),
            pytest.param('h3', 'http/1.1', False, True,
                         'connect-udp tunnel failed, response 404',
                         id='fail_h3_over_h1_proxyudptunnel'),
        ]
    )
    def test_failure_matrix(self, env: Env, httpd, nghttpx, alpn_proto,
                            proxy_proto, tunnel, tunneludp, exp_err):
        if not httpd or not nghttpx:
            pytest.skip('httpd or nghttpx not available')

        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = _nghttpx_proxy_args(env, nghttpx, proxy_proto,
                                         tunnel, tunneludp)
        r = curl.http_download(urls=[url], alpn_proto=alpn_proto, with_stats=True,
                               extra_args=proxy_args)
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        assert exp_err in r.stderr.lower(), \
            f"Expected protocol/proxy error but got: {r.stderr}"


class TestH3ProxyRuntimeGuards:
    """Runtime guard checks for non-ngtcp2 builds."""

    pytestmark = [
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                           reason='curl lacks HTTPS-proxy support'),
        pytest.mark.skipif(condition=Env.curl_uses_lib('ngtcp2'),
                           reason='guard only applies to non-ngtcp2 builds'),
    ]

    def test_guard_proxy_http3_unsupported(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', 'https://127.0.0.1:1/',
            '--proxy-http3',
            '--proxytunnel',
            '--proxy-insecure',
            '--cacert', env.ca.cert_file
        ]

        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=proxy_args)
        r.check_exit_code(1)
        assert 'only supported with the ngtcp2 quic stack' in r.stderr.lower(), \
            f"Expected ngtcp2 guard failure but got: {r.stderr}"

    @pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                        reason='curl lacks HTTP/3 support')
    def test_guard_proxyudptunnel_unsupported(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f'https://localhost:{httpd.ports["https"]}/data.json'
        proxy_args = [
            '--proxy', 'https://127.0.0.1:1/',
            '--proxyudptunnel',
            '--proxy-insecure',
            '--cacert', env.ca.cert_file
        ]

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        r.check_exit_code(1)
        assert 'only supported with the ngtcp2 quic stack' in r.stderr.lower(), \
            f"Expected ngtcp2 guard failure but got: {r.stderr}"


class TestH3ProxyRobustness:
    """Robustness checks for shutdown and proxy loss during transfer."""

    pytestmark = [
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTPS-proxy'),
                           reason='curl lacks HTTPS-proxy support'),
        pytest.mark.skipif(condition=not Env.curl_has_feature('HTTP3'),
                           reason='curl lacks HTTP/3 support'),
        pytest.mark.skipif(condition=not Env.curl_uses_lib('nghttp3'),
                           reason='only supported with nghttp3'),
        pytest.mark.skipif(condition=not Env.have_h2o(),
                           reason='no h2o available'),
    ]

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        doc_root = os.path.join(env.gen_dir, 'docs')
        env.make_data_file(indir=doc_root, fname='proxy-drop-20m',
                           fsize=20 * 1024 * 1024)

    def test_graceful_shutdown_sends_connection_close(self, env: Env,
                                                      h2o_server, h2o_proxy):
        if not env.curl_is_debug():
            pytest.skip('needs debug curl for shutdown trace lines')
        if not env.curl_is_verbose():
            pytest.skip('needs verbose-strings curl build')

        curl = CurlClient(env=env, run_env={
            'CURL_DEBUG': 'all'
        })
        url = f'https://localhost:{h2o_server.port}/data.json'
        proxy_args = curl.get_proxy_args(proto='h3', tunneludp=True)
        proxy_args.extend(['--cacert', env.ca.cert_file, '--insecure'])

        r = curl.http_download(urls=[url], alpn_proto='h3', with_stats=True,
                               extra_args=proxy_args)
        r.check_response(count=1, http_status=200)

        shutdown_lines = [
            line for line in r.trace_lines
            if ('start shutdown(' in line.lower()) or
               ('shutdown completely sent off' in line.lower())
        ]
        assert shutdown_lines, f"No shutdown trace lines found:\n{r.stderr}"

    def test_proxy_goes_away_mid_transfer(self, env: Env, h2o_server, h2o_proxy):
        if not h2o_server or not h2o_proxy:
            pytest.skip('h2o server or proxy not available')

        proxy_port = h2o_proxy.port
        url = f'https://localhost:{h2o_server.port}/proxy-drop-20m'
        out_path = os.path.join(env.gen_dir, 'proxy-drop.out')
        args = [
            env.curl,
            '--http1.1',
            '--proxy', f'https://{env.proxy_domain}:{proxy_port}/',
            '--resolve', f'{env.proxy_domain}:{proxy_port}:127.0.0.1',
            '--proxy-cacert', env.ca.cert_file,
            '--proxy-http3',
            '--proxytunnel',
            '--proxy-insecure',
            '--cacert', env.ca.cert_file,
            '--limit-rate', '100k',
            '--max-time', '20',
            '-o', out_path,
            url
        ]

        proc = None
        try:
            proc = subprocess.Popen(args=args, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
            time.sleep(1.0)
            assert h2o_proxy.stop(), "failed to stop h2o proxy"
            _, stderr = proc.communicate(timeout=30)
            assert proc.returncode != 0, \
                "curl should fail when proxy is terminated mid-transfer"
            serr = stderr.lower()
            assert ('failed' in serr or 'transfer closed' in serr or
                    'recv failure' in serr or 'connection' in serr), \
                f"Unexpected error output: {stderr}"
        finally:
            if proc and (proc.poll() is None):
                proc.kill()
                proc.wait(timeout=5)
            assert h2o_proxy.start(), "failed to restart h2o proxy"
