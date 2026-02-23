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
- **Async API** (``AsyncShodan``) for use in ``asyncio``-based applications

.. image:: https://cli.shodan.io/img/shodan-cli-preview.png
    :target: https://asciinema.org/~Shodan
    :width: 400px
    :align: center


Quick Start (synchronous)
--------------------------

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

The library ships an async-first client (``AsyncShodan``) that uses
`aiohttp <https://docs.aiohttp.org/>`_ and requires Python 3.8 or later.

.. code-block:: python

    import asyncio
    from shodan import AsyncShodan

    async def main():
        async with AsyncShodan('MY API KEY') as api:
            # Fetch API plan info
            info = await api.info()
            print('Plan:', info['plan'])

            # Search
            results = await api.search('apache')
            print('Total results:', results['total'])

            # Look up an IP
            host = await api.host('8.8.8.8')
            print('Hostnames:', host['hostnames'])

            # Iterate over all results with the async cursor
            async for banner in api.search_cursor('http.title:"hacked by"'):
                print(banner['ip_str'])

            # Run several requests concurrently
            r1, r2 = await asyncio.gather(
                api.host('1.1.1.1'),
                api.host('8.8.4.4'),
            )
            print(r1['ip_str'], r2['ip_str'])

    asyncio.run(main())

Async streaming example:

.. code-block:: python

    import asyncio
    from shodan import AsyncShodan

    async def main():
        async with AsyncShodan('MY API KEY') as api:
            # Consume the first 10 banners from the real-time stream
            count = 0
            async for banner in api.stream.banners():
                print(banner)
                count += 1
                if count >= 10:
                    break

    asyncio.run(main())

Migration Guide (Sync → Async)
-------------------------------

+-------------------------------------------+-----------------------------------------------+
| Sync (``Shodan``)                         | Async (``AsyncShodan``)                       |
+===========================================+===============================================+
| ``from shodan import Shodan``             | ``from shodan import AsyncShodan``            |
+-------------------------------------------+-----------------------------------------------+
| ``api = Shodan(key)``                     | ``api = AsyncShodan(key)``                    |
+-------------------------------------------+-----------------------------------------------+
| ``result = api.search(q)``                | ``result = await api.search(q)``              |
+-------------------------------------------+-----------------------------------------------+
| ``result = api.host(ip)``                 | ``result = await api.host(ip)``               |
+-------------------------------------------+-----------------------------------------------+
| ``result = api.info()``                   | ``result = await api.info()``                 |
+-------------------------------------------+-----------------------------------------------+
| ``for b in api.search_cursor(q):``        | ``async for b in api.search_cursor(q):``      |
+-------------------------------------------+-----------------------------------------------+
| ``for b in api.stream.banners():``        | ``async for b in api.stream.banners():``      |
+-------------------------------------------+-----------------------------------------------+
| ``api.exploits.search(q)``                | ``await api.exploits.search(q)``              |
+-------------------------------------------+-----------------------------------------------+

* The async client is used as an ``async with`` context manager (recommended) or
  you can call ``await api.aclose()`` manually when done.
* All public method names, parameters, and return values are identical to the
  sync ``Shodan`` class.  Simply add ``await`` (or ``async for`` for generators).
* Exceptions are the same: ``shodan.APIError`` and ``shodan.APITimeout``.
* The sync ``Shodan`` client is still available and unchanged for existing code.

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

