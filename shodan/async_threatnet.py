# -*- coding: utf-8 -*-
"""
shodan.async_threatnet
~~~~~~~~~~~~~~~~~~~~~~

This module implements the asynchronous Shodan Threatnet Streaming API client.

:copyright: (c) 2014- by John Matherly
"""
import json

import aiohttp

from .exception import APIError


class AsyncThreatnet:
    """Async wrapper around the Shodan Threatnet Streaming API.

    :param key: The Shodan API key.
    :type key: str

    Example usage::

        async with AsyncThreatnet('MY_API_KEY') as tn:
            async for event in tn.stream.events():
                print(event)
    """

    class Stream:
        """Async stream methods for the Threatnet API."""

        base_url = 'https://stream.shodan.io'

        def __init__(self, parent, proxies=None):
            self.parent = parent
            self._proxies = proxies

        def _get_proxy(self):
            if self._proxies is None:
                return None
            if isinstance(self._proxies, str):
                return self._proxies
            return self._proxies.get('https') or self._proxies.get('http')

        async def _create_stream(self, name):
            """Open a streaming connection to the given Threatnet endpoint.

            Returns an active ``aiohttp.ClientResponse`` that the caller must
            use as an async context manager.
            """
            proxy = self._get_proxy()
            connector = aiohttp.TCPConnector(ssl=False)
            session = aiohttp.ClientSession(
                connector=connector,
                connector_owner=True,
                timeout=aiohttp.ClientTimeout(total=None),
            )
            try:
                resp = await session.get(
                    self.base_url + name,
                    params={'key': self.parent.api_key},
                    proxy=proxy,
                )
            except Exception:
                await session.close()
                raise APIError('Unable to contact the Shodan Streaming API')

            if resp.status != 200:
                try:
                    body = await resp.text()
                    data = json.loads(body)
                    raise APIError(data['error'])
                except APIError:
                    await session.close()
                    raise
                except Exception:
                    pass
                await session.close()
                raise APIError('Invalid API key or you do not have access to the Streaming API')

            return session, resp

        async def _iter_lines(self, name):
            session, resp = await self._create_stream(name)
            try:
                while True:
                    raw_line = await resp.content.readline()
                    if not raw_line:
                        return
                    line = raw_line.strip()
                    if line:
                        yield json.loads(line)
            finally:
                resp.close()
                await session.close()

        async def events(self):
            """Stream Threatnet events.

            :yields: dict -- individual Threatnet event records
            """
            async for item in self._iter_lines('/threatnet/events'):
                yield item

        async def backscatter(self):
            """Stream Threatnet backscatter data.

            :yields: dict -- individual backscatter records
            """
            async for item in self._iter_lines('/threatnet/backscatter'):
                yield item

        async def activity(self):
            """Stream Threatnet SSH activity.

            :yields: dict -- individual SSH activity records
            """
            async for item in self._iter_lines('/threatnet/ssh'):
                yield item

    def __init__(self, key, proxies=None):
        """Initializes the async Threatnet client.

        :param key: The Shodan API key.
        :type key: str
        :param proxies: Proxy URL or dict
        :type proxies: str or dict, optional
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.stream = self.Stream(self, proxies=proxies)
