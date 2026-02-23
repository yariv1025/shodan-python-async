# -*- coding: utf-8 -*-
"""
shodan.async_threatnet
~~~~~~~~~~~~~~~~~~~~~~

Asynchronous Shodan Threatnet Streaming API client.

:copyright: (c) 2014- by John Matherly
"""
import asyncio
import json

import aiohttp

from .exception import APIError


class AsyncThreatnet:
    """Async wrapper around the Threatnet Streaming API.

    All stream methods are async generators consumable with ``async for``.

    :param key: The Shodan API key
    :type key: str
    :param proxies: A proxy URL string for aiohttp, e.g. ``'http://user:pass@host:port'``
    :type proxies: str or None
    """

    class _Stream:
        """Async stream methods for the Threatnet API."""

        base_url = 'https://stream.shodan.io'

        def __init__(self, parent, proxies=None):
            self.parent = parent
            self._proxies = proxies

        async def _iter_stream(self, name, timeout=None):
            """Async generator that yields parsed JSON objects from a Threatnet stream.

            :param name: Stream endpoint path
            :type name: str
            :param timeout: Connection timeout in seconds (``None`` for no timeout)
            :type timeout: int or None
            :raises APIError: on connection errors or non-200 responses
            """
            url = self.base_url + name
            params = {'key': self.parent.api_key}
            aio_timeout = aiohttp.ClientTimeout(total=timeout)

            retry_delay = 1
            while True:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, params=params, proxy=self._proxies,
                                               timeout=aio_timeout) as resp:
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
                                line = line.strip()
                                if line:
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
                    # Transient network error — back off and reconnect
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)

        async def events(self, timeout=None):
            """Stream Threatnet events.

            :param timeout: Connection timeout in seconds (``None`` for no timeout)
            :type timeout: int or None

            Yields parsed event dicts as they arrive.
            """
            async for item in self._iter_stream('/threatnet/events', timeout=timeout):
                yield item

        async def backscatter(self, timeout=None):
            """Stream Threatnet backscatter events.

            :param timeout: Connection timeout in seconds (``None`` for no timeout)
            :type timeout: int or None

            Yields parsed event dicts as they arrive.
            """
            async for item in self._iter_stream('/threatnet/backscatter', timeout=timeout):
                yield item

        async def activity(self, timeout=None):
            """Stream Threatnet SSH activity events.

            :param timeout: Connection timeout in seconds (``None`` for no timeout)
            :type timeout: int or None

            Yields parsed event dicts as they arrive.
            """
            async for item in self._iter_stream('/threatnet/ssh', timeout=timeout):
                yield item

    def __init__(self, key, proxies=None):
        """Initializes the AsyncThreatnet object.

        :param key: The Shodan API key.
        :type key: str
        :param proxies: A proxy URL string for aiohttp, e.g. ``'http://user:pass@host:port'``
        :type proxies: str or None
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.stream = self._Stream(self, proxies=proxies)
