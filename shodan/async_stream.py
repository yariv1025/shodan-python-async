# -*- coding: utf-8 -*-
"""
shodan.async_stream
~~~~~~~~~~~~~~~~~~~

This module implements the asynchronous Shodan Streaming API client.

:copyright: (c) 2014- by John Matherly
"""
import json

import aiohttp

from .exception import APIError


class AsyncStream:
    """Async wrapper around the Shodan Streaming API.

    Stream methods are async generators that can be consumed with ``async for``.

    :param api_key: The Shodan API key.
    :type api_key: str
    :param proxies: A proxy URL string or dict, e.g. ``'http://user:pass@host:port'``
    :type proxies: str or dict, optional
    """

    base_url = 'https://stream.shodan.io'

    def __init__(self, api_key, proxies=None):
        self.api_key = api_key
        self._proxies = proxies

    def _get_proxy(self):
        """Return a proxy URL string suitable for aiohttp."""
        if self._proxies is None:
            return None
        if isinstance(self._proxies, str):
            return self._proxies
        return self._proxies.get('https') or self._proxies.get('http')

    async def _iter_stream(self, name, query=None, timeout=None, raw=False):
        """Async generator that opens a streaming connection and yields parsed lines.

        :param name: Stream endpoint path (e.g. '/shodan/banners')
        :type name: str
        :param query: Optional query string for filtered streams
        :type query: str, optional
        :param timeout: Connection timeout in seconds; ``None`` or ``0`` for no timeout
        :type timeout: int or float or None
        :param raw: If True, yield raw bytes instead of parsed JSON dicts
        :type raw: bool
        :raises APIError: on connection errors, authentication failures, or stream errors
        """
        params = {
            'key': self.api_key,
        }
        stream_url = self.base_url + name

        # Normalise timeout: 0 means "no timeout" (same as sync client)
        if timeout is not None and timeout <= 0:
            timeout = None

        # Disable heartbeat when a finite timeout is requested
        if timeout is not None:
            params['heartbeat'] = 'false'

        if query is not None:
            params['query'] = query

        proxy = self._get_proxy()
        connector = aiohttp.TCPConnector(ssl=False)

        client_timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=None,
            sock_read=None,
        ) if timeout is not None else aiohttp.ClientTimeout(total=None)

        while True:
            try:
                async with aiohttp.ClientSession(
                    connector=connector,
                    connector_owner=True,
                    timeout=client_timeout,
                ) as session:
                    async with session.get(
                        stream_url,
                        params=params,
                        proxy=proxy,
                    ) as resp:
                        # 524 is Cloudflare's "origin timeout" — retry unless the
                        # caller requested a finite timeout.
                        if resp.status == 524:
                            if timeout is not None:
                                return
                            continue  # retry

                        if resp.status != 200:
                            try:
                                body = await resp.text()
                                data = json.loads(body)
                                raise APIError(data['error'])
                            except APIError:
                                raise
                            except Exception:
                                pass
                            raise APIError(
                                'Invalid API key or you do not have access to the Streaming API'
                            )

                        while True:
                            raw_line = await resp.content.readline()
                            if not raw_line:
                                return  # stream ended normally
                            line = raw_line.strip()
                            # Skip heartbeat newlines
                            if not line:
                                continue
                            if raw:
                                yield line
                            else:
                                yield json.loads(line)
                        return  # stream ended normally
            except APIError:
                raise
            except aiohttp.ClientConnectionError:
                raise APIError('Unable to contact the Shodan Streaming API')
            except aiohttp.ServerTimeoutError:
                raise APIError('Stream timed out')
            except aiohttp.ClientError:
                raise APIError('Stream timed out')
            except Exception:
                raise APIError('Unable to contact the Shodan Streaming API')

    async def alert(self, aid=None, timeout=None, raw=False):
        """Stream banners for one or all network alerts.

        :param aid: Alert ID; omit to stream all alerts
        :type aid: str, optional
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        """
        if aid:
            path = '/shodan/alert/{}'.format(aid)
        else:
            path = '/shodan/alert'

        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item

    async def asn(self, asn, raw=False, timeout=None):
        """A filtered stream returning banners that match the given ASNs.

        :param asn: A list of ASNs to return banner data on.
        :type asn: list[str]
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        path = '/shodan/asn/{}'.format(','.join(asn))
        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item

    async def banners(self, raw=False, timeout=None):
        """A real-time feed of all data that Shodan is currently collecting.

        Note: only available on API subscription plans and returns a fraction of data.

        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        async for item in self._iter_stream('/shodan/banners', timeout=timeout, raw=raw):
            yield item

    async def countries(self, countries, raw=False, timeout=None):
        """A filtered stream returning banners that match the given countries.

        :param countries: A list of country codes to return banner data on.
        :type countries: list[str]
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        path = '/shodan/countries/{}'.format(','.join(countries))
        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item

    async def custom(self, query, raw=False, timeout=None):
        """A filtered stream returning banners that match the given query.

        :param query: A space-separated list of key:value filters.
        :type query: str
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        async for item in self._iter_stream('/shodan/custom', query=query, timeout=timeout, raw=raw):
            yield item

    async def ports(self, ports, raw=False, timeout=None):
        """A filtered stream returning banners that match the given ports.

        :param ports: A list of ports to return banner data on.
        :type ports: list[int]
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        path = '/shodan/ports/{}'.format(','.join([str(p) for p in ports]))
        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item

    async def tags(self, tags, raw=False, timeout=None):
        """A filtered stream returning banners that match the given tags.

        :param tags: A list of tags to return banner data on.
        :type tags: list[str]
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        path = '/shodan/tags/{}'.format(','.join(tags))
        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item

    async def vulns(self, vulns, raw=False, timeout=None):
        """A filtered stream returning banners that match the given vulnerabilities.

        :param vulns: A list of CVEs/vulnerability IDs to return banner data on.
        :type vulns: list[str]
        :param raw: Yield raw bytes instead of parsed dicts
        :type raw: bool
        :param timeout: Stream timeout in seconds
        :type timeout: int or float or None
        """
        path = '/shodan/vulns/{}'.format(','.join(vulns))
        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item
