shodan: The official Python library and CLI for Shodan
======================================================

.. image:: https://img.shields.io/pypi/v/shodan.svg
    :target: https://pypi.org/project/shodan/

.. image:: https://img.shields.io/github/contributors/achillean/shodan-python.svg
    :target: https://github.com/achillean/shodan-python/graphs/contributors

Shodan is a search engine for Internet-connected devices. Google lets you search for websites,
Shodan lets you search for devices. This library provides developers easy access to all of the
data stored in Shodan in order to automate tasks and integrate into existing tools.

Features
--------

- Search Shodan
- `Fast/ bulk IP lookups <https://help.shodan.io/developer-fundamentals/looking-up-ip-info>`_
- Streaming API support for real-time consumption of Shodan firehose
- `Network alerts (aka private firehose) <https://help.shodan.io/guides/how-to-monitor-network>`_
- `Manage Email Notifications <https://asciinema.org/a/7WvyDtNxn0YeNU70ozsxvXDmL>`_
- Exploit search API fully implemented
- Bulk data downloads
- Access the Shodan DNS DB to view domain information
- `Command-line interface <https://cli.shodan.io>`_
- **Async support** via ``AsyncShodan`` (Python 3.8+, powered by ``aiohttp``)

.. image:: https://cli.shodan.io/img/shodan-cli-preview.png
    :target: https://asciinema.org/~Shodan
    :width: 400px
    :align: center


Quick Start
-----------

.. code-block:: python

    from shodan import Shodan

    api = Shodan('MY API KEY')

    # Lookup an IP
    ipinfo = api.host('8.8.8.8')
    print(ipinfo)

    # Search for websites that have been "hacked"
    for banner in api.search_cursor('http.title:"hacked by"'):
        print(banner)

    # Get the total number of industrial control systems services on the Internet
    ics_services = api.count('tag:ics')
    print('Industrial Control Systems: {}'.format(ics_services['total']))

Grab your API key from https://account.shodan.io

Async Quick Start
-----------------

Use ``AsyncShodan`` for fully async, non-blocking operation (Python 3.8+):

.. code-block:: python

    import asyncio
    from shodan import AsyncShodan

    async def main():
        async with AsyncShodan('MY API KEY') as api:
            # Lookup API plan info
            info = await api.info()
            print(info)

            # Search for Apache servers
            results = await api.search('apache')
            for banner in results['matches']:
                print(banner['ip_str'])

            # Iterate over all results with the async cursor
            async for banner in api.search_cursor('http.title:"hacked by"'):
                print(banner['ip_str'])

            # Stream real-time banners
            async for banner in api.stream.banners(timeout=10):
                print(banner)

    asyncio.run(main())

Migrating from Sync to Async
-----------------------------

The synchronous ``Shodan`` client and the asynchronous ``AsyncShodan`` client
share the same public API surface.  Migration is straightforward:

+----------------------------------------------+----------------------------------------------------+
| Sync                                         | Async                                              |
+==============================================+====================================================+
| ``from shodan import Shodan``                | ``from shodan import AsyncShodan``                 |
+----------------------------------------------+----------------------------------------------------+
| ``api = Shodan(key)``                        | ``async with AsyncShodan(key) as api:``            |
+----------------------------------------------+----------------------------------------------------+
| ``api.search(query)``                        | ``await api.search(query)``                        |
+----------------------------------------------+----------------------------------------------------+
| ``api.host(ip)``                             | ``await api.host(ip)``                             |
+----------------------------------------------+----------------------------------------------------+
| ``for b in api.search_cursor(q):``           | ``async for b in api.search_cursor(q):``           |
+----------------------------------------------+----------------------------------------------------+
| ``for b in api.stream.banners():``           | ``async for b in api.stream.banners():``           |
+----------------------------------------------+----------------------------------------------------+

Key differences:

- Every REST method on ``AsyncShodan`` is a coroutine; prefix calls with ``await``.
- ``search_cursor`` is an async generator; use ``async for``.
- All stream methods (``banners``, ``alert``, ``asn``, etc.) are async generators.
- Use the client as an async context manager (``async with``) or call ``await api.aclose()``
  when done to release the underlying HTTP session.
- Requires Python 3.8+ and ``aiohttp>=3.9.0``.

Python version support
----------------------

The synchronous ``Shodan`` client supports Python 2.7 and Python 3.x.

The asynchronous ``AsyncShodan`` client requires **Python 3.8 or newer**.

Installation
------------

To install the Shodan library, simply:

.. code-block:: bash

    $ pip install shodan

Or if you don't have pip installed (which you should seriously install):

.. code-block:: bash

    $ easy_install shodan


Documentation
-------------

Documentation is available at https://shodan.readthedocs.org/ and https://help.shodan.io

