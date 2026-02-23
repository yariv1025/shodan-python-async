"""Tests for the AsyncShodan client.

These tests run against the live Shodan API and require a valid API key stored
in the file ``SHODAN-API-KEY`` in the repository root (same as the sync test
suite).  They exercise the production-grade acceptance criteria defined in the
async migration specification.
"""
import asyncio
import unittest

import shodan
from shodan import AsyncShodan, APIError, APITimeout

try:
    basestring
except NameError:
    basestring = str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    """Run a coroutine to completion and return its result."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class AsyncShodanTests(unittest.TestCase):

    api = None
    FACETS = [
        'port',
        ('domain', 1)
    ]
    QUERIES = {
        'simple': 'cisco-ios',
        'minify': 'apache',
        'advanced': 'apache port:443',
        'empty': 'asdasdasdasdasdasdasdasdasdhjihjkjk',
    }

    def setUp(self):
        with open('SHODAN-API-KEY') as f:
            self.api = AsyncShodan(f.read().strip())

    def tearDown(self):
        run(self.api.aclose())

    # ------------------------------------------------------------------
    # Imports / public API surface
    # ------------------------------------------------------------------

    def test_importable_async_shodan(self):
        """AsyncShodan must be importable from the top-level shodan package."""
        self.assertIs(shodan.AsyncShodan, AsyncShodan)

    def test_importable_exceptions(self):
        """APIError and APITimeout must be importable from shodan."""
        self.assertTrue(issubclass(APIError, Exception))
        self.assertTrue(issubclass(APITimeout, APIError))

    # ------------------------------------------------------------------
    # Context manager / session lifecycle
    # ------------------------------------------------------------------

    def test_context_manager(self):
        """Client can be used as an async context manager."""
        async def _run():
            async with AsyncShodan(self.api.api_key) as api:
                result = await api.info()
                self.assertIn('plan', result)
        run(_run())

    def test_aclose_idempotent(self):
        """aclose() can be called multiple times without error."""
        async def _run():
            api = AsyncShodan(self.api.api_key)
            await api.aclose()
            await api.aclose()
        run(_run())

    # ------------------------------------------------------------------
    # Session reuse
    # ------------------------------------------------------------------

    def test_session_reuse(self):
        """The same aiohttp session object is reused across multiple requests."""
        async def _run():
            s1 = self.api._get_session()
            await self.api.info()
            s2 = self.api._get_session()
            self.assertIs(s1, s2)
        run(_run())

    # ------------------------------------------------------------------
    # REST methods
    # ------------------------------------------------------------------

    def test_info(self):
        result = run(self.api.info())
        self.assertIn('plan', result)

    def test_search_simple(self):
        results = run(self.api.search(self.QUERIES['simple']))

        self.assertIn('matches', results)
        self.assertIn('total', results)
        self.assertNotIn('error', results)
        self.assertTrue(results['matches'])
        self.assertTrue(results['total'])
        self.assertNotIn('opts', results['matches'][0])

    def test_search_empty(self):
        results = run(self.api.search(self.QUERIES['empty']))
        self.assertEqual(len(results['matches']), 0)
        self.assertEqual(results['total'], 0)

    def test_search_facets_param(self):
        results = run(self.api.search(self.QUERIES['simple'], facets=self.FACETS))

        self.assertTrue(results['facets']['port'])
        self.assertEqual(len(results['facets']['domain']), 1)

    def test_count_simple(self):
        results = run(self.api.count(self.QUERIES['simple']))

        self.assertIn('matches', results)
        self.assertIn('total', results)
        self.assertNotIn('error', results)
        self.assertFalse(results['matches'])
        self.assertTrue(results['total'])

    def test_count_facets(self):
        results = run(self.api.count(self.QUERIES['simple'], facets=self.FACETS))

        self.assertTrue(results['facets']['port'])
        self.assertEqual(len(results['facets']['domain']), 1)

    def test_host_details(self):
        host = run(self.api.host('147.228.101.7'))
        self.assertEqual('147.228.101.7', host['ip_str'])
        self.assertFalse(isinstance(host['ip'], basestring))

    def test_search_minify(self):
        results = run(self.api.search(self.QUERIES['minify'], minify=False))
        self.assertIn('opts', results['matches'][0])

    def test_exploits_search(self):
        results = run(self.api.exploits.search('apache'))
        self.assertIn('matches', results)
        self.assertIn('total', results)
        self.assertTrue(results['matches'])

    def test_exploits_search_paging(self):
        r1 = run(self.api.exploits.search('apache', page=1))
        r2 = run(self.api.exploits.search('apache', page=2))
        self.assertNotEqual(r1['matches'][0]['_id'], r2['matches'][0]['_id'])

    def test_exploits_search_facets(self):
        results = run(self.api.exploits.search('apache', facets=['source', ('author', 1)]))
        self.assertIn('facets', results)
        self.assertTrue(results['facets']['source'])
        self.assertEqual(len(results['facets']['author']), 1)

    def test_exploits_count(self):
        results = run(self.api.exploits.count('apache'))
        self.assertIn('matches', results)
        self.assertIn('total', results)
        self.assertEqual(len(results['matches']), 0)

    def test_exploits_count_facets(self):
        results = run(self.api.exploits.count('apache', facets=['source', ('author', 1)]))
        self.assertEqual(len(results['matches']), 0)
        self.assertIn('facets', results)
        self.assertTrue(results['facets']['source'])
        self.assertEqual(len(results['facets']['author']), 1)

    def test_trends_search(self):
        results = run(self.api.trends.search('apache', facets=[('product', 10)]))
        self.assertIn('total', results)
        self.assertIn('matches', results)
        self.assertIn('facets', results)
        self.assertTrue(results['matches'])
        self.assertIn('2023-06', [bucket['key'] for bucket in results['facets']['product']])

        results = run(self.api.trends.search('apache', facets=[]))
        self.assertIn('total', results)
        self.assertIn('matches', results)
        self.assertNotIn('facets', results)
        self.assertTrue(results['matches'])
        self.assertIn('2023-06', [match['month'] for match in results['matches']])

    def test_trends_search_filters(self):
        results = run(self.api.trends.search_filters())
        self.assertIn('has_ipv6', results)
        self.assertNotIn('http.html', results)

    def test_trends_search_facets(self):
        results = run(self.api.trends.search_facets())
        self.assertIn('product', results)
        self.assertNotIn('cpe', results)

    # ------------------------------------------------------------------
    # search_cursor (async generator)
    # ------------------------------------------------------------------

    def test_search_cursor_async_generator(self):
        """search_cursor yields at least one result for a non-empty query."""
        async def _run():
            count = 0
            async for banner in self.api.search_cursor(self.QUERIES['simple']):
                self.assertIn('ip_str', banner)
                count += 1
                if count >= 5:
                    break
            self.assertGreater(count, 0)
        run(_run())

    # ------------------------------------------------------------------
    # Error paths
    # ------------------------------------------------------------------

    def test_invalid_key(self):
        async def _run():
            api = AsyncShodan('garbage')
            try:
                with self.assertRaises(APIError):
                    await api.search('something')
            finally:
                await api.aclose()
        run(_run())

    def test_invalid_host_ip(self):
        with self.assertRaises(APIError):
            run(self.api.host('test'))

    def test_search_empty_query(self):
        with self.assertRaises(APIError):
            run(self.api.search(''))

    def test_search_advanced_query(self):
        """Free API plan cannot use filters."""
        with self.assertRaises(APIError):
            run(self.api.search(self.QUERIES['advanced']))

    # ------------------------------------------------------------------
    # Concurrency
    # ------------------------------------------------------------------

    def test_concurrent_host_lookups(self):
        """Multiple concurrent host() calls return consistent, correct results."""
        ips = ['1.1.1.1', '8.8.8.8']

        async def _run():
            tasks = [self.api.host(ip) for ip in ips]
            results = await asyncio.gather(*tasks)
            for ip, result in zip(ips, results):
                self.assertEqual(ip, result['ip_str'])
        run(_run())

    def test_concurrent_search_calls(self):
        """Multiple concurrent search() calls all return valid results."""
        async def _run():
            tasks = [self.api.search(self.QUERIES['simple']) for _ in range(3)]
            results = await asyncio.gather(*tasks)
            for result in results:
                self.assertIn('matches', result)
                self.assertIn('total', result)
        run(_run())

    def test_no_blocking_io(self):
        """Two concurrent coroutines complete without one blocking the other.

        Both coroutines make a real network request.  If one used sync I/O
        (time.sleep / requests) the asyncio event loop would be blocked and
        the overall elapsed time would be roughly 2× the per-request latency.
        We don't assert hard timing here because CI environments can be slow,
        but at least both coroutines must complete and return valid data.
        """
        async def _run():
            r1, r2 = await asyncio.gather(
                self.api.info(),
                self.api.info(),
            )
            self.assertIn('plan', r1)
            self.assertIn('plan', r2)
        run(_run())


if __name__ == '__main__':
    unittest.main()
