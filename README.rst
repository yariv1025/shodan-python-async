shodan-async: Async Python library and CLI for Shodan
=======================================================

.. image:: https://img.shields.io/pypi/v/shodan.svg
    :target: https://pypi.org/project/shodan/

.. image:: https://img.shields.io/github/contributors/achillean/shodan-python.svg
    :target: https://github.com/achillean/shodan-python/graphs/contributors

An async-first fork of the official Shodan Python library. Shodan is a search engine for
Internet-connected devices — this library gives developers non-blocking access to all of the
data stored in Shodan so they can automate tasks and integrate into existing async applications.

Features
--------

- Fully **async** REST and Streaming APIs via ``AsyncShodan`` / ``AsyncStream`` (Python 3.8+, powered by ``aiohttp``)
- Search Shodan
- `Fast/ bulk IP lookups <https://help.shodan.io/developer-fundamentals/looking-up-ip-info>`_
- Streaming API support for real-time consumption of Shodan firehose (``async for``)
- `Network alerts (aka private firehose) <https://help.shodan.io/guides/how-to-monitor-network>`_
- `Manage Email Notifications <https://asciinema.org/a/7WvyDtNxn0YeNU70ozsxvXDmL>`_
- Exploit search API fully implemented
- Bulk data downloads
- Access the Shodan DNS DB to view domain information
- `Command-line interface <https://cli.shodan.io>`_ (uses the sync client internally)
- Legacy synchronous ``Shodan`` client retained for backward compatibility

.. image:: https://cli.shodan.io/img/shodan-cli-preview.png
    :target: https://asciinema.org/~Shodan
    :width: 400px
    :align: center


Quick Start
-----------

.. code-block:: python

    import asyncio
    from shodan import AsyncShodan

    async def main():
        async with AsyncShodan('MY API KEY') as api:
            # Lookup API plan info
            info = await api.info()
            print(info)

            # Lookup an IP
            ipinfo = await api.host('8.8.8.8')
            print(ipinfo)

            # Iterate over all results with the async cursor
            async for banner in api.search_cursor('http.title:"hacked by"'):
                print(banner['ip_str'])

            # Get the total number of industrial control systems services on the Internet
            ics_services = await api.count('tag:ics')
            print('Industrial Control Systems: {}'.format(ics_services['total']))

            # Stream real-time banners
            async for banner in api.stream.banners(timeout=30):
                print(banner)

    asyncio.run(main())

Grab your API key from https://account.shodan.io

Migrating from the Sync API
----------------------------

The asynchronous ``AsyncShodan`` client has the same public API surface as the legacy
``Shodan`` client.  Migration is a one-for-one swap:

+----------------------------------------------+----------------------------------------------------+
| Sync (legacy)                                | Async                                              |
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

The asynchronous ``AsyncShodan`` client requires **Python 3.8 or newer**.

The legacy synchronous ``Shodan`` client supports Python 2.7 and Python 3.x (retained for
backward compatibility — existing code that imports ``from shodan import Shodan`` continues to work).

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

