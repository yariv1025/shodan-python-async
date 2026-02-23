# -*- coding: utf-8 -*-
"""
shodan.async_stream
~~~~~~~~~~~~~~~~~~~

Asynchronous Shodan Streaming API client.

:copyright: (c) 2014- by John Matherly
"""
import asyncio
import json

import aiohttp

from .exception import APIError


class AsyncStream:
    """Async wrapper around the Shodan Streaming API.

    All stream methods are async generators and can be consumed with ``async for``.

    :param api_key: The Shodan API key
    :type api_key: str
    :param proxies: A proxy URL string for aiohttp, e.g. ``'http://user:pass@host:port'``
    :type proxies: str or None
    """

    base_url = 'https://stream.shodan.io'

    def __init__(self, api_key, proxies=None):
        self.api_key = api_key
        self._proxies = proxies

    async def _iter_stream(self, name, query=None, timeout=None, raw=False):
        """Open a streaming connection and yield banner lines.

        :param name: Stream endpoint path (e.g. ``'/shodan/banners'``)
        :type name: str
        :param query: Optional filter query
        :type query: str or None
        :param timeout: Connection timeout in seconds. ``None`` or ``<= 0`` means no
                        timeout (heartbeats are enabled). A positive value disables
                        heartbeats and the generator raises
                        :class:`~shodan.exception.APIError` when the timeout expires.
        :type timeout: int or None
        :param raw: If True, yield raw bytes; otherwise yield parsed dicts
        :type raw: bool
        :raises APIError: on connection errors or non-200 status codes
        """
        params = {
            'key': self.api_key,
        }

        # Normalise timeout: 0 or negative → None (no timeout)
        if timeout is not None and timeout <= 0:
            timeout = None

        # If the user requested a timeout then disable heartbeat messages;
        # otherwise enable them to keep the connection alive.
        # Convert bool to string so aiohttp accepts the value.
        params['heartbeat'] = 'true' if timeout is None else 'false'

        if query is not None:
            params['query'] = query

        url = self.base_url + name
        aio_timeout = aiohttp.ClientTimeout(total=timeout) if timeout else aiohttp.ClientTimeout(total=None)

        retry_delay = 1
        while True:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params, proxy=self._proxies,
                                           timeout=aio_timeout) as resp:
                        # Status code 524 is special to Cloudflare — no data from streaming servers
                        if resp.status == 524:
                            if timeout is not None and timeout > 0:
                                # User specified a timeout; exit on 524
                                return
                            # No timeout specified: back off and retry
                            await asyncio.sleep(retry_delay)
                            retry_delay = min(retry_delay * 2, 60)
                            continue

                        if resp.status != 200:
                            try:
                                data = await resp.json(content_type=None)
                                raise APIError(data['error'])
                            except APIError:
                                raise
                            except Exception:
                                pass
                            raise APIError('Invalid API key or you do not have access to the Streaming API')

                        retry_delay = 1  # reset on successful connection
                        async for line in resp.content:
                            # Strip whitespace; ignore heartbeat (empty) lines
                            line = line.strip()
                            if not line:
                                continue
                            if raw:
                                yield line
                            else:
                                yield json.loads(line)
                        # Stream closed normally
                        return
            except GeneratorExit:
                raise
            except APIError:
                raise
            except asyncio.TimeoutError:
                raise APIError('Stream timed out')
            except aiohttp.ClientError:
                raise APIError('Unable to contact the Shodan Streaming API')

    async def alert(self, aid=None, timeout=None, raw=False):
        """Stream banners for one or all of the user's network alerts.

        :param aid: (optional) Alert ID; omit to stream all alerts
        :type aid: str or None
        :param timeout: Connection timeout in seconds. A value of ``None`` or ``<= 0``
                        means no timeout; heartbeat messages are enabled to keep the
                        connection alive. A positive value disables heartbeats and the
                        stream will raise :class:`~shodan.exception.APIError` on timeout.
        :type timeout: int or None
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        """
        if aid:
            path = '/shodan/alert/{}'.format(aid)
        else:
            path = '/shodan/alert'

        async for item in self._iter_stream(path, timeout=timeout, raw=raw):
            yield item

    async def asn(self, asn, raw=False, timeout=None):
        """Stream banners filtered by ASN(s).

        :param asn: A list of ASN numbers to filter on
        :type asn: list of str
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream(
                '/shodan/asn/{}'.format(','.join(asn)), timeout=timeout, raw=raw):
            yield item

    async def banners(self, raw=False, timeout=None):
        """Real-time feed of the data that Shodan is currently collecting.

        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream('/shodan/banners', timeout=timeout, raw=raw):
            yield item

    async def countries(self, countries, raw=False, timeout=None):
        """Stream banners filtered by country code(s).

        :param countries: A list of 2-letter country codes
        :type countries: list of str
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream(
                '/shodan/countries/{}'.format(','.join(countries)), timeout=timeout, raw=raw):
            yield item

    async def custom(self, query, raw=False, timeout=None):
        """Stream banners matching an arbitrary filter query.

        :param query: A space-separated list of key:value filters
        :type query: str
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream('/shodan/custom', query=query, timeout=timeout, raw=raw):
            yield item

    async def ports(self, ports, raw=False, timeout=None):
        """Stream banners filtered by port(s).

        :param ports: A list of port numbers
        :type ports: list of int
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream(
                '/shodan/ports/{}'.format(','.join([str(port) for port in ports])),
                timeout=timeout, raw=raw):
            yield item

    async def tags(self, tags, raw=False, timeout=None):
        """Stream banners filtered by tag(s).

        :param tags: A list of tags to filter on
        :type tags: list of str
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream(
                '/shodan/tags/{}'.format(','.join(tags)), timeout=timeout, raw=raw):
            yield item

    async def vulns(self, vulns, raw=False, timeout=None):
        """Stream banners filtered by vulnerability CVE(s).

        :param vulns: A list of CVE IDs to filter on
        :type vulns: list of str
        :param raw: If True, yield raw bytes lines
        :type raw: bool
        :param timeout: Connection timeout in seconds
        :type timeout: int or None
        """
        async for item in self._iter_stream(
                '/shodan/vulns/{}'.format(','.join(vulns)), timeout=timeout, raw=raw):
            yield item
