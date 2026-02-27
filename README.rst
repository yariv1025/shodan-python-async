shodan-python (async)
=====================

.. image:: https://img.shields.io/pypi/v/shodan.svg
    :target: https://pypi.org/project/shodan/

.. image:: https://img.shields.io/github/contributors/achillean/shodan-python.svg
    :target: https://github.com/achillean/shodan-python/graphs/contributors

An async-first Python library and CLI for the `Shodan <https://shodan.io>`_ search engine.

**Based on the original** `shodan-python <https://github.com/achillean/shodan-python>`_
**library by** `John Matherly <https://twitter.com/achillean>`_ **(jmath@shodan.io) and all
its** `contributors <https://github.com/achillean/shodan-python/graphs/contributors>`_,
**released under the** `MIT License <https://github.com/achillean/shodan-python/blob/master/LICENSE>`_.
**This fork adds a fully async API layer built on** ``aiohttp``.

Shodan is a search engine for Internet-connected devices.  This library gives
developers **non-blocking** access to all of the data stored in Shodan so they
can automate tasks and integrate into modern async Python applications.

Features
--------

- Fully **async** REST and Streaming APIs via ``AsyncShodan`` / ``AsyncStream`` (Python 3.8+, powered by ``aiohttp``)
- `Search Shodan <https://developer.shodan.io/api>`_
- `Fast / bulk IP lookups <https://help.shodan.io/developer-fundamentals/looking-up-ip-info>`_
- Streaming API support for real-time banner consumption (``async for``)
- `Network alerts / private firehose <https://help.shodan.io/guides/how-to-monitor-network>`_
- `Manage email notifications <https://asciinema.org/a/7WvyDtNxn0YeNU70ozsxvXDmL>`_
- Exploit search and bulk data downloads
- Shodan DNS DB — domain information lookup
- `Trends <https://trends.shodan.io>`_ historical search
- `Command-line interface <https://cli.shodan.io>`_ (backed by the async client via ``asyncio.run()``)

.. image:: https://cli.shodan.io/img/shodan-cli-preview.png
    :target: https://asciinema.org/~Shodan
    :width: 400px
    :align: center


Quick Start
-----------

Grab your API key from https://account.shodan.io

.. code-block:: bash

    $ pip install shodan

.. code-block:: python

    import asyncio
    from shodan import AsyncShodan

    async def main():
        async with AsyncShodan('MY_API_KEY') as api:
            # API plan information
            info = await api.info()
            print(info)

            # Single IP lookup
            host = await api.host('8.8.8.8')
            print(host['ip_str'], host.get('org', 'n/a'))

            # Count results
            result = await api.count('tag:ics')
            print('ICS devices:', result['total'])

            # Iterate over all results with the async cursor
            async for banner in api.search_cursor('apache'):
                print(banner['ip_str'])

            # Real-time banner stream (stops after 30 seconds)
            async for banner in api.stream.banners(timeout=30):
                print(banner)

    asyncio.run(main())


Concurrent lookups with asyncio
---------------------------------

.. code-block:: python

    import asyncio
    from shodan import AsyncShodan

    async def main():
        ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        async with AsyncShodan('MY_API_KEY') as api:
            results = await asyncio.gather(*[api.host(ip) for ip in ips])
            for r in results:
                print(r['ip_str'], r.get('org', 'n/a'))

    asyncio.run(main())


Streaming API
-------------

All stream methods are **async generators** — consume them with ``async for``:

.. code-block:: python

    from shodan import AsyncShodan

    async def main():
        async with AsyncShodan('MY_API_KEY') as api:
            # All banners
            async for banner in api.stream.banners():
                print(banner)

            # Filtered by port
            async for banner in api.stream.ports([22, 80, 443]):
                print(banner)

            # Filtered by country
            async for banner in api.stream.countries(['US', 'DE']):
                print(banner)

            # Filtered by ASN
            async for banner in api.stream.asn(['AS15169']):
                print(banner)

            # Custom filter query
            async for banner in api.stream.custom('port:8080 country:US'):
                print(banner)

            # Network alert (private firehose)
            async for banner in api.stream.alert(aid='MY_ALERT_ID'):
                print(banner)


Session management
------------------

Use the async context manager to ensure the HTTP session is properly closed:

.. code-block:: python

    async with AsyncShodan('MY_API_KEY') as api:
        result = await api.search('nginx')

Or close manually when the context manager is not convenient:

.. code-block:: python

    api = AsyncShodan('MY_API_KEY')
    try:
        result = await api.search('nginx')
    finally:
        await api.aclose()


Python version support
----------------------

**Python 3.8 or newer** is required.  ``aiohttp >= 3.9.0`` is used for all
HTTP and streaming communication.


Installation
------------

.. code-block:: bash

    $ pip install shodan

Or from source:

.. code-block:: bash

    $ git clone https://github.com/achillean/shodan-python
    $ cd shodan-python
    $ pip install -e .


Security
--------

This library follows OWASP best practices:

- All communication uses **HTTPS** exclusively; plain-HTTP base-URL overrides
  via ``SHODAN_API_URL`` are rejected at startup (OWASP A02).
- API keys are never included in ``__repr__`` output or exception messages to
  prevent accidental exposure in logs and tracebacks (OWASP A02 / A09).
- URL path parameters are validated to reject null bytes and newline characters,
  guarding against null-byte and HTTP header injection (OWASP A03).
- ``aiohttp`` performs TLS certificate verification by default.


Documentation
-------------

- Official Shodan API reference: https://developer.shodan.io/api
- Shodan help centre: https://help.shodan.io
- ReadTheDocs: https://shodan.readthedocs.org/


Credits
-------

This project is a fork of `shodan-python <https://github.com/achillean/shodan-python>`_,
the official Shodan Python library originally created and maintained by
`John Matherly <https://twitter.com/achillean>`_ (Shodan founder, jmath@shodan.io) and the
`contributor community <https://github.com/achillean/shodan-python/graphs/contributors>`_.

The original library is copyright (c) 2014- John Matherly and is released under the
`MIT License <https://github.com/achillean/shodan-python/blob/master/LICENSE>`_.

This async fork retains all original functionality and replaces the
``requests``-based implementation with a fully non-blocking ``AsyncShodan`` /
``AsyncStream`` API layer built on ``aiohttp``.
