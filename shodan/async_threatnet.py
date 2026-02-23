# -*- coding: utf-8 -*-
"""
shodan.async_threatnet
~~~~~~~~~~~~~~~~~~~~~~

Asynchronous Shodan Threatnet Streaming API client.

:copyright: (c) 2014- by John Matherly
"""
import json

import aiohttp

from .exception import APIError


class AsyncThreatnet:
    """Async wrapper around the Threatnet Streaming API.

    All stream methods are async generators consumable with ``async for``.

    :param key: The Shodan API key
    :type key: str
    """

    class AsyncStream:
        """Async stream methods for the Threatnet API."""

        base_url = 'https://stream.shodan.io'

        def __init__(self, parent, proxies=None):
            self.parent = parent
            self._proxies = proxies

        async def _iter_stream(self, name):
            """Async generator that yields parsed JSON objects from a Threatnet stream.

            :param name: Stream endpoint path
            :type name: str
            :raises APIError: on connection errors or non-200 responses
            """
            url = self.base_url + name
            params = {'key': self.parent.api_key}

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params, proxy=self._proxies) as resp:
                        if resp.status != 200:
                            try:
                                data = await resp.json(content_type=None)
                                raise APIError(data['error'])
                            except APIError:
                                raise
                            except Exception:
                                pass
                            raise APIError('Invalid API key or you do not have access to the Streaming API')

                        async for line in resp.content:
                            line = line.strip()
                            if line:
                                yield json.loads(line)
            except APIError:
                raise
            except Exception:
                raise APIError('Stream timed out')

        async def events(self):
            """Stream Threatnet events.

            Yields parsed event dicts as they arrive.
            """
            async for item in self._iter_stream('/threatnet/events'):
                yield item

        async def backscatter(self):
            """Stream Threatnet backscatter events.

            Yields parsed event dicts as they arrive.
            """
            async for item in self._iter_stream('/threatnet/backscatter'):
                yield item

        async def activity(self):
            """Stream Threatnet SSH activity events.

            Yields parsed event dicts as they arrive.
            """
            async for item in self._iter_stream('/threatnet/ssh'):
                yield item

    def __init__(self, key):
        """Initializes the AsyncThreatnet object.

        :param key: The Shodan API key.
        :type key: str
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.stream = self.AsyncStream(self)
