# -*- coding: utf-8 -*-
"""
shodan.compat
~~~~~~~~~~~~~

Synchronous compatibility shim over :class:`~shodan.async_client.AsyncShodan`.

Every public async method on ``AsyncShodan`` is re-exposed here as a blocking
call so that the CLI (and any existing code that uses
``from shodan import Shodan``) continues to work after the requests-based
implementation was removed.

Streaming generators (``stream.banners()``, ``search_cursor()``, etc.) are
bridged to synchronous generators through a background thread and an
unbounded queue so that the caller can use an ordinary ``for`` loop.

Security notes (OWASP):
- The API key is never included in ``__repr__`` or ``__str__`` output to
  prevent accidental exposure in logs or tracebacks (OWASP A02 / A09).
- Input sanitisation is delegated to ``AsyncShodan._sanitize_path_param``.
- All network I/O is over HTTPS; enforcement is done in ``AsyncShodan.__init__``.

:copyright: (c) 2014- by John Matherly
"""
import asyncio
import queue
import threading

from .async_client import AsyncShodan
from .exception import APIError  # re-export so callers can still catch it


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(key, proxies, coro_fn):
    """Create a fresh ``AsyncShodan``, run *coro_fn(api)*, close the session.

    A new event loop is created for every call via ``asyncio.run()``.
    Using a fresh ``AsyncShodan`` each time ensures that the underlying
    ``aiohttp.ClientSession`` is always bound to the current event loop and
    is properly closed when the call completes.

    :param key: Shodan API key
    :param proxies: Optional proxy URL string
    :param coro_fn: Callable accepting an ``AsyncShodan`` instance and
                    returning a coroutine whose result is the desired value.
    :returns: The value returned by *coro_fn*.
    """
    async def _inner():
        async with AsyncShodan(key, proxies=proxies) as api:
            return await coro_fn(api)

    return asyncio.run(_inner())


def _iter_stream(key, proxies, gen_fn):
    """Yield items from an async generator in a synchronous ``for`` loop.

    *gen_fn* is a zero-argument callable that **accepts an** ``AsyncShodan``
    instance and returns the async generator to consume.  The generator is
    driven in a background daemon thread so the calling thread is never
    blocked.  Items are transferred through a :class:`queue.SimpleQueue`.

    If the generator raises an exception it is re-raised in the calling
    thread after the background thread has joined.

    It is safe to ``break`` out of the resulting ``for`` loop early; the
    daemon thread will be abandoned and cleaned up when the process exits.

    :param key: Shodan API key
    :param proxies: Optional proxy URL string
    :param gen_fn: Callable ``(AsyncShodan) -> async_generator``
    """
    result_q = queue.SimpleQueue()
    _sentinel = object()
    _exc_holder = []

    def _thread_main():
        async def _drain():
            try:
                async with AsyncShodan(key, proxies=proxies) as api:
                    async for item in gen_fn(api):
                        result_q.put(item)
            except BaseException as exc:  # propagate everything, including APIError
                _exc_holder.append(exc)
            finally:
                result_q.put(_sentinel)

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_drain())
        finally:
            loop.close()

    thread = threading.Thread(target=_thread_main, daemon=True)
    thread.start()

    while True:
        item = result_q.get()
        if item is _sentinel:
            break
        yield item

    thread.join()

    if _exc_holder:
        raise _exc_holder[0]


# ---------------------------------------------------------------------------
# Sync sub-API wrappers
# ---------------------------------------------------------------------------

class _SyncData:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def list_datasets(self):
        return _run(self._key, self._proxies, lambda api: api.data.list_datasets())

    def list_files(self, dataset):
        return _run(self._key, self._proxies, lambda api: api.data.list_files(dataset))


class _SyncDns:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def domain_info(self, domain, history=False, type=None, page=1):
        return _run(self._key, self._proxies,
                    lambda api: api.dns.domain_info(domain, history=history, type=type, page=page))


class _SyncNotifier:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def create(self, provider, args, description=None):
        return _run(self._key, self._proxies,
                    lambda api: api.notifier.create(provider, args, description=description))

    def edit(self, nid, args):
        return _run(self._key, self._proxies, lambda api: api.notifier.edit(nid, args))

    def get(self, nid):
        return _run(self._key, self._proxies, lambda api: api.notifier.get(nid))

    def list_notifiers(self):
        return _run(self._key, self._proxies, lambda api: api.notifier.list_notifiers())

    def list_providers(self):
        return _run(self._key, self._proxies, lambda api: api.notifier.list_providers())

    def remove(self, nid):
        return _run(self._key, self._proxies, lambda api: api.notifier.remove(nid))


class _SyncTools:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def myip(self):
        return _run(self._key, self._proxies, lambda api: api.tools.myip())


class _SyncExploits:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def search(self, query, page=1, facets=None):
        return _run(self._key, self._proxies,
                    lambda api: api.exploits.search(query, page=page, facets=facets))

    def count(self, query, facets=None):
        return _run(self._key, self._proxies,
                    lambda api: api.exploits.count(query, facets=facets))


class _SyncLabs:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def honeyscore(self, ip):
        return _run(self._key, self._proxies, lambda api: api.labs.honeyscore(ip))


class _SyncOrganization:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def add_member(self, user, notify=True):
        return _run(self._key, self._proxies,
                    lambda api: api.org.add_member(user, notify=notify))

    def info(self):
        return _run(self._key, self._proxies, lambda api: api.org.info())

    def remove_member(self, user):
        return _run(self._key, self._proxies, lambda api: api.org.remove_member(user))


class _SyncTrends:
    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def search(self, query, facets=None):
        return _run(self._key, self._proxies,
                    lambda api: api.trends.search(query, facets=facets))

    def search_facets(self):
        return _run(self._key, self._proxies, lambda api: api.trends.search_facets())

    def search_filters(self):
        return _run(self._key, self._proxies, lambda api: api.trends.search_filters())


class _SyncStream:
    """Sync wrapper around :class:`~shodan.async_stream.AsyncStream`.

    Each method returns a synchronous generator that yields banner dicts (or
    raw bytes when ``raw=True``).  The underlying async generator runs in a
    background daemon thread.
    """

    def __init__(self, key, proxies):
        self._key = key
        self._proxies = proxies

    def alert(self, aid=None, timeout=None, raw=False):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.alert(aid=aid, timeout=timeout, raw=raw))

    def asn(self, asn, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.asn(asn, raw=raw, timeout=timeout))

    def banners(self, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.banners(raw=raw, timeout=timeout))

    def countries(self, countries, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.countries(countries, raw=raw, timeout=timeout))

    def custom(self, query, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.custom(query, raw=raw, timeout=timeout))

    def ports(self, ports, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.ports(ports, raw=raw, timeout=timeout))

    def tags(self, tags, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.tags(tags, raw=raw, timeout=timeout))

    def vulns(self, vulns, raw=False, timeout=None):
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.stream.vulns(vulns, raw=raw, timeout=timeout))


# ---------------------------------------------------------------------------
# Public sync client
# ---------------------------------------------------------------------------

class Shodan:
    """Synchronous wrapper around :class:`~shodan.async_client.AsyncShodan`.

    Provides the same public interface as the legacy requests-based ``Shodan``
    client so that the CLI and existing integrations continue to work without
    modification.  Internally every call delegates to an ``AsyncShodan``
    instance via ``asyncio.run()``, which creates a fresh event loop and
    ``aiohttp`` session per call.

    :param key: The Shodan API key
    :type key: str
    :param proxies: Proxy URL string, e.g. ``'http://user:pass@host:port'``
    :type proxies: str or None
    """

    def __init__(self, key, proxies=None):
        self._key = key
        self._proxies = proxies

        # Mirror the sub-API namespaces expected by callers
        self.data = _SyncData(key, proxies)
        self.dns = _SyncDns(key, proxies)
        self.exploits = _SyncExploits(key, proxies)
        self.trends = _SyncTrends(key, proxies)
        self.labs = _SyncLabs(key, proxies)
        self.notifier = _SyncNotifier(key, proxies)
        self.org = _SyncOrganization(key, proxies)
        self.tools = _SyncTools(key, proxies)
        self.stream = _SyncStream(key, proxies)

        # Expose commonly-read attributes for CLI compatibility
        self.base_url = 'https://api.shodan.io'
        self.base_exploits_url = 'https://exploits.shodan.io'
        self.base_trends_url = 'https://trends.shodan.io'
        # api_key exposed so CLI code that reads it still works, but
        # __repr__ deliberately masks it (OWASP A02 / A09).
        self.api_key = key

    def __repr__(self):
        # Mask the API key to prevent accidental exposure in logs/tracebacks.
        return '<Shodan api_key=***>'

    # ------------------------------------------------------------------
    # REST API methods — each delegates to AsyncShodan via asyncio.run()
    # ------------------------------------------------------------------

    def count(self, query, facets=None):
        return _run(self._key, self._proxies, lambda api: api.count(query, facets=facets))

    def host(self, ips, history=False, minify=False):
        return _run(self._key, self._proxies,
                    lambda api: api.host(ips, history=history, minify=minify))

    def info(self):
        return _run(self._key, self._proxies, lambda api: api.info())

    def ports(self):
        return _run(self._key, self._proxies, lambda api: api.ports())

    def protocols(self):
        return _run(self._key, self._proxies, lambda api: api.protocols())

    def scan(self, ips, force=False):
        return _run(self._key, self._proxies, lambda api: api.scan(ips, force=force))

    def scans(self, page=1):
        return _run(self._key, self._proxies, lambda api: api.scans(page=page))

    def scan_internet(self, port, protocol):
        return _run(self._key, self._proxies, lambda api: api.scan_internet(port, protocol))

    def scan_status(self, scan_id):
        return _run(self._key, self._proxies, lambda api: api.scan_status(scan_id))

    def search(self, query, page=1, limit=None, offset=None, facets=None, minify=True, fields=None):
        return _run(self._key, self._proxies,
                    lambda api: api.search(query, page=page, limit=limit, offset=offset,
                                           facets=facets, minify=minify, fields=fields))

    def search_cursor(self, query, minify=True, retries=5, fields=None):
        """Return a synchronous generator over all search results."""
        return _iter_stream(self._key, self._proxies,
                            lambda api: api.search_cursor(query, minify=minify,
                                                          retries=retries, fields=fields))

    def search_facets(self):
        return _run(self._key, self._proxies, lambda api: api.search_facets())

    def search_filters(self):
        return _run(self._key, self._proxies, lambda api: api.search_filters())

    def search_tokens(self, query):
        return _run(self._key, self._proxies, lambda api: api.search_tokens(query))

    def services(self):
        return _run(self._key, self._proxies, lambda api: api.services())

    def queries(self, page=1, sort='timestamp', order='desc'):
        return _run(self._key, self._proxies,
                    lambda api: api.queries(page=page, sort=sort, order=order))

    def queries_search(self, query, page=1):
        return _run(self._key, self._proxies, lambda api: api.queries_search(query, page=page))

    def queries_tags(self, size=10):
        return _run(self._key, self._proxies, lambda api: api.queries_tags(size=size))

    def create_alert(self, name, ip, expires=0):
        return _run(self._key, self._proxies,
                    lambda api: api.create_alert(name, ip, expires=expires))

    def edit_alert(self, aid, ip):
        return _run(self._key, self._proxies, lambda api: api.edit_alert(aid, ip))

    def alerts(self, aid=None, include_expired=True):
        return _run(self._key, self._proxies,
                    lambda api: api.alerts(aid=aid, include_expired=include_expired))

    def delete_alert(self, aid):
        return _run(self._key, self._proxies, lambda api: api.delete_alert(aid))

    def alert_triggers(self):
        return _run(self._key, self._proxies, lambda api: api.alert_triggers())

    def enable_alert_trigger(self, aid, trigger):
        return _run(self._key, self._proxies,
                    lambda api: api.enable_alert_trigger(aid, trigger))

    def disable_alert_trigger(self, aid, trigger):
        return _run(self._key, self._proxies,
                    lambda api: api.disable_alert_trigger(aid, trigger))

    def ignore_alert_trigger_notification(self, aid, trigger, ip, port, vulns=None):
        return _run(self._key, self._proxies,
                    lambda api: api.ignore_alert_trigger_notification(
                        aid, trigger, ip, port, vulns=vulns))

    def unignore_alert_trigger_notification(self, aid, trigger, ip, port):
        return _run(self._key, self._proxies,
                    lambda api: api.unignore_alert_trigger_notification(aid, trigger, ip, port))

    def add_alert_notifier(self, aid, nid):
        return _run(self._key, self._proxies, lambda api: api.add_alert_notifier(aid, nid))

    def remove_alert_notifier(self, aid, nid):
        return _run(self._key, self._proxies, lambda api: api.remove_alert_notifier(aid, nid))
