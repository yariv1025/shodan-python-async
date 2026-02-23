"""Tests for AsyncShodan and AsyncStream.

These tests use aioresponses to mock HTTP calls so they run without a real
Shodan API key or network access.
"""
import asyncio
import json
import re
import unittest

import pytest
from aioresponses import aioresponses

import shodan
from shodan import AsyncShodan, APIError, APITimeout
from shodan.async_stream import AsyncStream

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

API_KEY = 'test_key'
BASE_URL = 'https://api.shodan.io'
STREAM_URL = 'https://stream.shodan.io'


def _url(path):
    """Return a compiled regex that matches the given API path (with any query string)."""
    escaped = re.escape(BASE_URL + path)
    return re.compile(r'^' + escaped + r'(\?.*)?$')


def _surl(path):
    """Return a compiled regex that matches the given stream path (with any query string)."""
    escaped = re.escape(STREAM_URL + path)
    return re.compile(r'^' + escaped + r'(\?.*)?$')


def _eurl(path):
    """Return a compiled regex that matches exploits.shodan.io paths."""
    escaped = re.escape('https://exploits.shodan.io' + path)
    return re.compile(r'^' + escaped + r'(\?.*)?$')


def _turl(path):
    """Return a compiled regex that matches trends.shodan.io paths."""
    escaped = re.escape('https://trends.shodan.io' + path)
    return re.compile(r'^' + escaped + r'(\?.*)?$')


# ---------------------------------------------------------------------------
# REST API tests
# ---------------------------------------------------------------------------

class TestAsyncShodanBasic:
    """Basic REST method tests via aioresponses mocks."""

    async def test_info(self):
        payload = {'plan': 'dev', 'https': True, 'unlocked': True, 'query_credits': 100,
                   'scan_credits': 100, 'telnet': False, 'unlocked_left': 100, 'monitored_ips': 0}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/api-info'), payload=payload)
                result = await api.info()
        assert result['plan'] == 'dev'

    async def test_search(self):
        payload = {
            'matches': [{'ip_str': '1.2.3.4', 'port': 80}],
            'total': 1,
        }
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload=payload)
                result = await api.search('apache')
        assert 'matches' in result
        assert result['total'] == 1

    async def test_search_empty(self):
        payload = {'matches': [], 'total': 0}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload=payload)
                result = await api.search('zzznoresultszzz')
        assert len(result['matches']) == 0
        assert result['total'] == 0

    async def test_count(self):
        payload = {'matches': [], 'total': 42}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/count'), payload=payload)
                result = await api.count('cisco-ios')
        assert result['total'] == 42

    async def test_host(self):
        payload = {'ip_str': '8.8.8.8', 'ip': 134744072}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/8.8.8.8'), payload=payload)
                result = await api.host('8.8.8.8')
        assert result['ip_str'] == '8.8.8.8'

    async def test_ports(self):
        payload = [80, 443, 8080]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/ports'), payload=payload)
                result = await api.ports()
        assert 80 in result

    async def test_services(self):
        payload = {'80': 'HTTP', '443': 'HTTPS'}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/services'), payload=payload)
                result = await api.services()
        assert '80' in result

    async def test_protocols(self):
        payload = {'http': 'Hypertext Transfer Protocol', 'ssh': 'Secure Shell'}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/protocols'), payload=payload)
                result = await api.protocols()
        assert 'http' in result

    async def test_search_facets(self):
        payload = ['country', 'org', 'port']
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search/facets'), payload=payload)
                result = await api.search_facets()
        assert 'country' in result

    async def test_search_filters(self):
        payload = ['city', 'country', 'port']
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search/filters'), payload=payload)
                result = await api.search_filters()
        assert 'city' in result

    async def test_search_tokens(self):
        payload = {'attributes': {}, 'errors': [], 'filters': ['port'], 'string': 'port:80'}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search/tokens'), payload=payload)
                result = await api.search_tokens('port:80')
        assert 'filters' in result

    async def test_queries(self):
        payload = [{'title': 'test', 'query': 'apache'}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/query'), payload=payload)
                result = await api.queries()
        assert len(result) == 1

    async def test_queries_search(self):
        payload = [{'title': 'test', 'query': 'apache'}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/query/search'), payload=payload)
                result = await api.queries_search('apache')
        assert len(result) == 1

    async def test_queries_tags(self):
        payload = [{'value': 'ics', 'count': 10}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/query/tags'), payload=payload)
                result = await api.queries_tags()
        assert result[0]['value'] == 'ics'

    async def test_scans(self):
        payload = {'matches': [], 'total': 0}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/scans'), payload=payload)
                result = await api.scans()
        assert 'total' in result

    async def test_scan_status(self):
        payload = {'id': 'abc', 'status': 'DONE'}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/scan/abc'), payload=payload)
                result = await api.scan_status('abc')
        assert result['status'] == 'DONE'

    async def test_alerts(self):
        payload = [{'id': 'a1', 'name': 'test'}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/alert/info'), payload=payload)
                result = await api.alerts()
        assert result[0]['id'] == 'a1'

    async def test_alert_triggers(self):
        payload = [{'name': 'malware', 'description': 'malware detection'}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/alert/triggers'), payload=payload)
                result = await api.alert_triggers()
        assert result[0]['name'] == 'malware'

    async def test_scan_post(self):
        payload = {'id': 'scan1', 'count': 1, 'credits_left': 99}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.post(_url('/shodan/scan'), payload=payload)
                result = await api.scan('1.2.3.4')
        assert result['id'] == 'scan1'

    async def test_create_alert(self):
        payload = {'id': 'alert1', 'name': 'my-alert'}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.post(_url('/shodan/alert'), payload=payload)
                result = await api.create_alert('my-alert', '1.2.3.4')
        assert result['id'] == 'alert1'

    async def test_delete_alert(self):
        payload = {'success': True}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.delete(_url('/shodan/alert/alert1'), payload=payload)
                result = await api.delete_alert('alert1')
        assert result['success'] is True

    # ------------------------------------------------------------------
    # Sub-API: exploits
    # ------------------------------------------------------------------

    async def test_exploits_search(self):
        payload = {'matches': [{'_id': 'CVE-2021-1234'}], 'total': 1}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_eurl('/api/search'), payload=payload)
                result = await api.exploits.search('apache')
        assert 'matches' in result

    async def test_exploits_count(self):
        payload = {'matches': [], 'total': 5}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_eurl('/api/count'), payload=payload)
                result = await api.exploits.count('apache')
        assert result['total'] == 5

    # ------------------------------------------------------------------
    # Sub-API: labs
    # ------------------------------------------------------------------

    async def test_labs_honeyscore(self):
        payload = 0.75
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/labs/honeyscore/1.2.3.4'), payload=payload)
                result = await api.labs.honeyscore('1.2.3.4')
        assert result == 0.75

    # ------------------------------------------------------------------
    # Sub-API: dns
    # ------------------------------------------------------------------

    async def test_dns_domain_info(self):
        payload = {'domain': 'example.com', 'tags': [], 'data': []}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/dns/domain/example.com'), payload=payload)
                result = await api.dns.domain_info('example.com')
        assert result['domain'] == 'example.com'

    # ------------------------------------------------------------------
    # Sub-API: data
    # ------------------------------------------------------------------

    async def test_data_list_datasets(self):
        payload = [{'name': 'dataset1'}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/data'), payload=payload)
                result = await api.data.list_datasets()
        assert result[0]['name'] == 'dataset1'

    # ------------------------------------------------------------------
    # Sub-API: tools
    # ------------------------------------------------------------------

    async def test_tools_myip(self):
        payload = '1.2.3.4'
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/tools/myip'), payload=payload)
                result = await api.tools.myip()
        assert result == '1.2.3.4'

    # ------------------------------------------------------------------
    # Sub-API: trends
    # ------------------------------------------------------------------

    async def test_trends_search(self):
        payload = {'total': 1, 'matches': [{'month': '2023-06'}]}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_turl('/api/v1/search'), payload=payload)
                result = await api.trends.search('apache')
        assert 'matches' in result

    async def test_trends_search_with_facets(self):
        payload = {'total': 1, 'matches': [{'month': '2023-06'}], 'facets': {'product': []}}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_turl('/api/v1/search'), payload=payload)
                result = await api.trends.search('apache', facets=[('product', 10)])
        assert 'facets' in result

    async def test_trends_search_facets(self):
        payload = ['product', 'org']
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_turl('/api/v1/search/facets'), payload=payload)
                result = await api.trends.search_facets()
        assert 'product' in result

    async def test_trends_search_filters(self):
        payload = ['has_ipv6', 'country']
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_turl('/api/v1/search/filters'), payload=payload)
                result = await api.trends.search_filters()
        assert 'has_ipv6' in result

    # ------------------------------------------------------------------
    # Sub-API: notifier
    # ------------------------------------------------------------------

    async def test_notifier_list_notifiers(self):
        payload = {'results': [], 'total': 0}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/notifier'), payload=payload)
                result = await api.notifier.list_notifiers()
        assert 'total' in result

    async def test_notifier_list_providers(self):
        payload = [{'provider': 'email', 'description': 'Email notifications'}]
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/notifier/provider'), payload=payload)
                result = await api.notifier.list_providers()
        assert result[0]['provider'] == 'email'

    # ------------------------------------------------------------------
    # Sub-API: org
    # ------------------------------------------------------------------

    async def test_org_info(self):
        payload = {'name': 'My Org', 'id': 'org1'}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/org'), payload=payload)
                result = await api.org.info()
        assert result['name'] == 'My Org'


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

class TestAsyncShodanErrors:
    """Error handling: 401, 403, 502, bad JSON, API error key."""

    async def test_invalid_api_key_401(self):
        async with AsyncShodan('garbage') as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), status=401,
                      payload={'error': 'Invalid API key'})
                with pytest.raises(APIError):
                    await api.search('something')

    async def test_invalid_api_key_401_html(self):
        async with AsyncShodan('garbage') as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), status=401, body='<html>Unauthorized</html>')
                with pytest.raises(APIError) as exc_info:
                    await api.search('something')
        assert 'Invalid API key' in str(exc_info.value)

    async def test_403_forbidden(self):
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), status=403, payload={})
                with pytest.raises(APIError) as exc_info:
                    await api.search('apache')
        assert '403' in str(exc_info.value)

    async def test_502_bad_gateway(self):
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), status=502, payload={})
                with pytest.raises(APIError) as exc_info:
                    await api.search('apache')
        assert '502' in str(exc_info.value)

    async def test_api_error_key_in_response(self):
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload={'error': 'No information available'})
                with pytest.raises(APIError) as exc_info:
                    await api.search('something')
        assert 'No information available' in str(exc_info.value)

    async def test_invalid_host_ip(self):
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/test'), payload={'error': 'Invalid IP'})
                with pytest.raises(APIError):
                    await api.host('test')

    async def test_empty_query(self):
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'),
                      payload={'error': 'Empty search query'})
                with pytest.raises(APIError):
                    await api.search('')

    async def test_bad_json_response(self):
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), status=200, body='not json')
                with pytest.raises(APIError) as exc_info:
                    await api.search('apache')
        assert 'JSON' in str(exc_info.value)


# ---------------------------------------------------------------------------
# Concurrency tests
# ---------------------------------------------------------------------------

class TestAsyncShodanConcurrency:
    """Test that multiple coroutines can run concurrently on a single client."""

    async def test_concurrent_host_lookups(self):
        ips = ['1.2.3.4', '5.6.7.8', '9.10.11.12']
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                for ip in ips:
                    m.get(_url('/shodan/host/{}'.format(ip)), payload={'ip_str': ip})
                results = await asyncio.gather(*[api.host(ip) for ip in ips])
        assert len(results) == 3
        returned_ips = {r['ip_str'] for r in results}
        assert returned_ips == set(ips)

    async def test_concurrent_search_calls(self):
        queries = ['apache', 'nginx', 'iis']
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                for q in queries:
                    m.get(_url('/shodan/host/search'), payload={'matches': [{'query': q}], 'total': 1})
                results = await asyncio.gather(*[api.search(q) for q in queries])
        assert len(results) == 3
        for result in results:
            assert 'matches' in result


# ---------------------------------------------------------------------------
# search_cursor (async generator) tests
# ---------------------------------------------------------------------------

class TestAsyncSearchCursor:
    """Test the async generator search_cursor method."""

    async def test_search_cursor_single_page(self):
        page1 = {'matches': [{'ip_str': '1.1.1.1'}, {'ip_str': '2.2.2.2'}], 'total': 2}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload=page1)
                banners = []
                async for banner in api.search_cursor('apache'):
                    banners.append(banner)
        assert len(banners) == 2
        assert banners[0]['ip_str'] == '1.1.1.1'

    async def test_search_cursor_multiple_pages(self):
        matches_p1 = [{'ip_str': '1.1.1.{}'.format(i)} for i in range(100)]
        matches_p2 = [{'ip_str': '2.2.2.{}'.format(i)} for i in range(50)]
        page1 = {'matches': matches_p1, 'total': 150}
        page2 = {'matches': matches_p2, 'total': 150}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload=page1)
                m.get(_url('/shodan/host/search'), payload=page2)
                banners = []
                async for banner in api.search_cursor('apache'):
                    banners.append(banner)
        assert len(banners) == 150

    async def test_search_cursor_empty_results(self):
        page1 = {'matches': [], 'total': 0}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload=page1)
                banners = []
                async for banner in api.search_cursor('zzznoresultszzz'):
                    banners.append(banner)
        assert len(banners) == 0


# ---------------------------------------------------------------------------
# Stream tests  (using a custom mock since aioresponses handles streaming)
# ---------------------------------------------------------------------------

class TestAsyncStream:
    """Test that AsyncStream raises APIError on bad status codes."""

    async def test_stream_invalid_key(self):
        stream = AsyncStream(API_KEY)
        with aioresponses() as m:
            m.get(_surl('/shodan/banners'), status=401,
                  payload={'error': 'Invalid API key'})
            with pytest.raises(APIError):
                async for _ in stream.banners(timeout=1):
                    break

    async def test_stream_403(self):
        stream = AsyncStream(API_KEY)
        with aioresponses() as m:
            m.get(_surl('/shodan/banners'), status=403, payload={})
            with pytest.raises(APIError) as exc_info:
                async for _ in stream.banners(timeout=1):
                    break
        assert 'Invalid API key' in str(exc_info.value)

    async def test_stream_yields_items(self):
        banner = {'ip_str': '1.2.3.4', 'port': 80}
        body = json.dumps(banner) + '\n'
        stream = AsyncStream(API_KEY)
        with aioresponses() as m:
            m.get(_surl('/shodan/banners'), status=200, body=body)
            items = []
            async for item in stream.banners(timeout=1):
                items.append(item)
        assert len(items) == 1
        assert items[0]['ip_str'] == '1.2.3.4'

    async def test_stream_skips_heartbeat_lines(self):
        banner = {'ip_str': '5.6.7.8', 'port': 443}
        body = '\n' + json.dumps(banner) + '\n\n'
        stream = AsyncStream(API_KEY)
        with aioresponses() as m:
            m.get(_surl('/shodan/banners'), status=200, body=body)
            items = []
            async for item in stream.banners(timeout=1):
                items.append(item)
        assert len(items) == 1
        assert items[0]['ip_str'] == '5.6.7.8'

    async def test_stream_multi_item(self):
        """Stream delivers multiple items from a multi-line body."""
        banners = [{'ip_str': '1.2.3.{}'.format(i), 'port': 80} for i in range(5)]
        body = '\n'.join(json.dumps(b) for b in banners) + '\n'
        stream = AsyncStream(API_KEY)
        with aioresponses() as m:
            m.get(_surl('/shodan/banners'), status=200, body=body)
            items = []
            async for item in stream.banners(timeout=1):
                items.append(item)
        assert len(items) == 5


# ---------------------------------------------------------------------------
# search_cursor retry tests
# ---------------------------------------------------------------------------

class TestSearchCursorRetry:
    """Test search_cursor retry and error behaviour."""

    async def test_search_cursor_retries_on_api_error(self):
        """search_cursor should retry transient APIErrors."""
        matches = [{'ip_str': '1.1.1.1'}]
        page1 = {'matches': matches, 'total': 1}
        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                # First page succeeds
                m.get(_url('/shodan/host/search'), payload=page1)
                banners = []
                async for banner in api.search_cursor('apache'):
                    banners.append(banner)
        assert len(banners) == 1

    async def test_search_cursor_raises_after_retry_limit(self):
        """search_cursor should raise APIError after exceeding retry limit."""
        # 101 matches → 2 pages; second page always errors
        matches = [{'ip_str': '1.1.1.{}'.format(i)} for i in range(100)]
        page1 = {'matches': matches, 'total': 101}
        error_resp = {'error': 'Service temporarily unavailable'}

        async with AsyncShodan(API_KEY) as api:
            with aioresponses() as m:
                m.get(_url('/shodan/host/search'), payload=page1)
                # Enough failures to exhaust retries (default retries=5)
                for _ in range(6):
                    m.get(_url('/shodan/host/search'), payload=error_resp)
                with pytest.raises(APIError):
                    async for _ in api.search_cursor('apache', retries=5):
                        pass


# ---------------------------------------------------------------------------
# Proxy forwarding tests
# ---------------------------------------------------------------------------

class TestProxyForwarding:
    """Verify that proxy settings are forwarded to HTTP calls."""

    async def test_proxy_is_stored_on_client(self):
        """AsyncShodan stores the proxy argument."""
        proxy = 'http://proxy.example.com:8080'
        api = AsyncShodan(API_KEY, proxies=proxy)
        assert api._proxies == proxy
        await api.aclose()

    async def test_stream_proxy_is_stored(self):
        """AsyncStream stores the proxy argument."""
        from shodan.async_stream import AsyncStream as AS
        proxy = 'http://proxy.example.com:8080'
        s = AS(API_KEY, proxies=proxy)
        assert s._proxies == proxy

    async def test_threatnet_proxy_is_forwarded(self):
        """AsyncThreatnet forwards proxies to its inner stream."""
        from shodan.async_threatnet import AsyncThreatnet
        proxy = 'http://proxy.example.com:8080'
        tn = AsyncThreatnet(API_KEY, proxies=proxy)
        assert tn.stream._proxies == proxy


# ---------------------------------------------------------------------------
# AsyncThreatnet stream tests
# ---------------------------------------------------------------------------

class TestAsyncThreatnet:
    """Test AsyncThreatnet stream methods."""

    async def test_threatnet_events_yields_items(self):
        from shodan.async_threatnet import AsyncThreatnet
        event = {'type': 'syn', 'ip': '1.2.3.4'}
        body = json.dumps(event) + '\n'
        tn = AsyncThreatnet(API_KEY)
        with aioresponses() as m:
            m.get(re.compile(r'^https://stream\.shodan\.io/threatnet/events.*'),
                  status=200, body=body)
            items = []
            async for item in tn.stream.events(timeout=1):
                items.append(item)
        assert len(items) == 1
        assert items[0]['type'] == 'syn'

    async def test_threatnet_invalid_key(self):
        from shodan.async_threatnet import AsyncThreatnet
        tn = AsyncThreatnet('garbage')
        with aioresponses() as m:
            m.get(re.compile(r'^https://stream\.shodan\.io/threatnet/events.*'),
                  status=401, payload={'error': 'Invalid API key'})
            with pytest.raises(APIError):
                async for _ in tn.stream.events(timeout=1):
                    break


# ---------------------------------------------------------------------------
# Import / public API surface tests
# ---------------------------------------------------------------------------

class TestPublicImports:
    """Verify that all public symbols are importable from 'shodan'."""

    def test_async_shodan_importable(self):
        from shodan import AsyncShodan
        assert AsyncShodan is not None

    def test_api_error_importable(self):
        from shodan import APIError
        assert issubclass(APIError, Exception)

    def test_api_timeout_importable(self):
        from shodan import APITimeout
        assert issubclass(APITimeout, APIError)

    def test_sync_shodan_still_importable(self):
        from shodan import Shodan
        assert Shodan is not None

    def test_async_shodan_context_manager(self):
        """AsyncShodan supports async context manager protocol."""
        assert hasattr(AsyncShodan, '__aenter__')
        assert hasattr(AsyncShodan, '__aexit__')
        assert hasattr(AsyncShodan, 'aclose')

    def test_async_shodan_has_all_public_methods(self):
        """Every public sync method on Shodan has an async counterpart."""
        from shodan.client import Shodan
        sync_methods = {
            name for name in dir(Shodan)
            if not name.startswith('_') and callable(getattr(Shodan, name))
        }
        async_methods = {
            name for name in dir(AsyncShodan)
            if not name.startswith('_') and callable(getattr(AsyncShodan, name))
        }
        # The async client should cover all sync public methods
        missing = sync_methods - async_methods - {'Data', 'Dns', 'Exploits', 'Labs',
                                                   'Notifier', 'Organization', 'Tools',
                                                   'Trends'}
        assert not missing, "AsyncShodan is missing methods: {}".format(missing)

    def test_async_threatnet_inner_class_not_named_async_stream(self):
        """AsyncThreatnet inner class must not shadow the module-level AsyncStream."""
        from shodan.async_threatnet import AsyncThreatnet
        # The inner class should NOT be named AsyncStream at the module level
        assert not hasattr(AsyncThreatnet, 'AsyncStream'), \
            "AsyncThreatnet.AsyncStream shadows shodan.async_stream.AsyncStream"
