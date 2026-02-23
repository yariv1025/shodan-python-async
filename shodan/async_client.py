# -*- coding: utf-8 -*-
"""
shodan.async_client
~~~~~~~~~~~~~~~~~~~

Asynchronous version of the Shodan API client.

:copyright: (c) 2014- by John Matherly
"""
import math
import os
import asyncio
import json

import aiohttp

from .exception import APIError
from .helpers import create_facet_string
from .async_stream import AsyncStream


class AsyncShodan:
    """Async wrapper around the Shodan REST and Streaming APIs.

    :param key: The Shodan API key that can be obtained from your account page (https://account.shodan.io)
    :type key: str
    :param proxies: A proxy URL string, e.g. ``'http://user:pass@host:port'``
    :type proxies: str or None

    Usage::

        import asyncio
        from shodan import AsyncShodan

        async def main():
            async with AsyncShodan('MY_API_KEY') as api:
                info = await api.info()
                print(info)

        asyncio.run(main())
    """

    class Data:
        """Access the Shodan bulk-data download API."""

        def __init__(self, parent):
            self.parent = parent

        async def list_datasets(self):
            """Returns a list of datasets that the user has permission to download.

            :returns: A list of objects where every object describes a dataset
            """
            return await self.parent._request('/shodan/data', {})

        async def list_files(self, dataset):
            """Returns a list of files that belong to the given dataset.

            :param dataset: Name of the dataset
            :type dataset: str
            :returns: A list of objects where each object contains a 'name', 'size', 'timestamp' and 'url'
            """
            return await self.parent._request('/shodan/data/{}'.format(dataset), {})

    class Dns:
        """Access the Shodan DNS API."""

        def __init__(self, parent):
            self.parent = parent

        async def domain_info(self, domain, history=False, type=None, page=1):
            """Grab the DNS information for a domain.

            :param domain: Domain name to look up
            :type domain: str
            :param history: Whether to include historical data
            :type history: bool
            :param type: DNS record type filter
            :type type: str or None
            :param page: Page number
            :type page: int
            :returns: dict with DNS information
            """
            args = {
                'page': page,
            }
            if history:
                args['history'] = history
            if type:
                args['type'] = type
            return await self.parent._request('/dns/domain/{}'.format(domain), args)

    class Notifier:
        """Manage Shodan notification providers."""

        def __init__(self, parent):
            self.parent = parent

        async def create(self, provider, args, description=None):
            """Create a new notifier.

            :param provider: Provider name
            :type provider: str
            :param args: Provider arguments
            :type args: dict
            :param description: Human-friendly description of the notifier
            :type description: str
            :returns: dict -- fields are 'success' and 'id' of the notifier
            """
            args = dict(args)
            args['provider'] = provider

            if description:
                args['description'] = description

            return await self.parent._request('/notifier', args, method='post')

        async def edit(self, nid, args):
            """Edit an existing notifier.

            :param nid: Notifier ID
            :type nid: str
            :param args: Provider arguments
            :type args: dict
            :returns: dict -- fields are 'success' and 'id' of the notifier
            """
            return await self.parent._request('/notifier/{}'.format(nid), args, method='put')

        async def get(self, nid):
            """Get the settings for a notifier.

            :param nid: Notifier ID
            :type nid: str
            :returns: dict -- object describing the notifier settings
            """
            return await self.parent._request('/notifier/{}'.format(nid), {})

        async def list_notifiers(self):
            """Returns a list of notifiers that the user has added.

            :returns: A list of notifiers that are available on the account
            """
            return await self.parent._request('/notifier', {})

        async def list_providers(self):
            """Returns a list of supported notification providers.

            :returns: A list of providers where each object describes a provider
            """
            return await self.parent._request('/notifier/provider', {})

        async def remove(self, nid):
            """Delete a notifier.

            :param nid: Notifier ID
            :type nid: str
            :returns: dict -- 'success' set to True if action succeeded
            """
            return await self.parent._request('/notifier/{}'.format(nid), {}, method='delete')

    class Tools:
        """General utility methods."""

        def __init__(self, parent):
            self.parent = parent

        async def myip(self):
            """Get your current IP address as seen from the Internet.

            :returns: str -- your IP address
            """
            return await self.parent._request('/tools/myip', {})

    class Exploits:
        """Search the Shodan Exploits database."""

        def __init__(self, parent):
            self.parent = parent

        async def search(self, query, page=1, facets=None):
            """Search the entire Shodan Exploits archive using the same query syntax as the website.

            :param query: The exploit search query; same syntax as website.
            :type query: str
            :param page: The page number to access.
            :type page: int
            :param facets: A list of strings or tuples to get summary information on.
            :type facets: list or None
            :returns: dict -- a dictionary containing the results of the search.
            """
            query_args = {
                'query': query,
                'page': page,
            }
            if facets:
                query_args['facets'] = create_facet_string(facets)

            return await self.parent._request('/api/search', query_args, service='exploits')

        async def count(self, query, facets=None):
            """Count Shodan Exploits results without returning them.

            :param query: The exploit search query; same syntax as website.
            :type query: str
            :param facets: A list of strings or tuples to get summary information on.
            :type facets: list or None
            :returns: dict -- a dictionary containing the results of the search.
            """
            query_args = {
                'query': query,
            }
            if facets:
                query_args['facets'] = create_facet_string(facets)

            return await self.parent._request('/api/count', query_args, service='exploits')

    class Labs:
        """Access the Shodan Labs experimental APIs."""

        def __init__(self, parent):
            self.parent = parent

        async def honeyscore(self, ip):
            """Calculate the probability of an IP being an ICS honeypot.

            :param ip: IP address of the device
            :type ip: str
            :returns: float -- honeyscore ranging from 0.0 to 1.0
            """
            return await self.parent._request('/labs/honeyscore/{}'.format(ip), {})

    class Organization:
        """Manage your Shodan organization."""

        def __init__(self, parent):
            self.parent = parent

        async def add_member(self, user, notify=True):
            """Add the user to the organization.

            :param user: username or email address
            :type user: str
            :param notify: whether or not to send the user an email notification
            :type notify: bool
            :returns: True if it succeeded and raises an exception otherwise
            """
            return (await self.parent._request('/org/member/{}'.format(user), {
                'notify': notify,
            }, method='PUT'))['success']

        async def info(self):
            """Returns general information about the organization the current user is a member of.

            :returns: dict with organization information
            """
            return await self.parent._request('/org', {})

        async def remove_member(self, user):
            """Remove the user from the organization.

            :param user: username or email address
            :type user: str
            :returns: True if it succeeded and raises an exception otherwise
            """
            return (await self.parent._request('/org/member/{}'.format(user), {}, method='DELETE'))['success']

    class Trends:
        """Access the Shodan Trends historical database."""

        def __init__(self, parent):
            self.parent = parent

        async def search(self, query, facets=None):
            """Search the Shodan historical database.

            :param query: Search query; identical syntax to the website
            :type query: str
            :param facets: (optional) A list of properties to get summary information on
            :type facets: list or None
            :returns: A dictionary with 3 main items: matches, facets and total.
            """
            args = {
                'query': query,
            }
            if facets:
                args['facets'] = create_facet_string(facets)

            return await self.parent._request('/api/v1/search', args, service='trends')

        async def search_facets(self):
            """Returns a list of facets that can be used in Trends searches.

            :returns: A list of strings where each is a facet name
            """
            return await self.parent._request('/api/v1/search/facets', {}, service='trends')

        async def search_filters(self):
            """Returns a list of search filters for Trends.

            :returns: A list of strings where each is a filter name
            """
            return await self.parent._request('/api/v1/search/filters', {}, service='trends')

    def __init__(self, key, proxies=None):
        """Initializes the async API object.

        :param key: The Shodan API key.
        :type key: str
        :param proxies: A proxy URL string for aiohttp, e.g. ``'http://user:pass@host:port'``
        :type proxies: str or None
        """
        self.api_key = key
        self.base_url = 'https://api.shodan.io'
        self.base_exploits_url = 'https://exploits.shodan.io'
        self.base_trends_url = 'https://trends.shodan.io'
        self._proxies = proxies
        self._session = None
        self.api_rate_limit = 1  # Requests per second
        self._api_query_time = None

        self.data = self.Data(self)
        self.dns = self.Dns(self)
        self.exploits = self.Exploits(self)
        self.trends = self.Trends(self)
        self.labs = self.Labs(self)
        self.notifier = self.Notifier(self)
        self.org = self.Organization(self)
        self.tools = self.Tools(self)
        self.stream = AsyncStream(key, proxies=proxies)

        if os.environ.get('SHODAN_API_URL'):
            self.base_url = os.environ.get('SHODAN_API_URL')

    def _get_session(self):
        """Return (creating if needed) the shared aiohttp ClientSession."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector()
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    async def aclose(self):
        """Close the underlying HTTP session.

        Call this when you are done with the client to release resources.
        In long-lived applications prefer using the client as an async context manager::

            async with AsyncShodan('MY_API_KEY') as api:
                ...
        """
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.aclose()

    @staticmethod
    def _encode_params(params):
        """Convert boolean values in *params* to lowercase strings.

        ``aiohttp`` does not accept Python booleans as query parameter values,
        so we normalise ``True`` → ``'true'`` and ``False`` → ``'false'``.
        """
        return {k: str(v).lower() if isinstance(v, bool) else v for k, v in params.items()}

    async def _request(self, function, params, service='shodan', method='get', json_data=None):
        """General-purpose coroutine to create web requests to SHODAN.

        :param function: API endpoint path
        :type function: str
        :param params: Query parameters (not mutated)
        :type params: dict
        :param service: Target Shodan service (``'shodan'``, ``'exploits'``, ``'trends'``)
        :type service: str
        :param method: HTTP method
        :type method: str
        :param json_data: Optional JSON body for POST requests
        :type json_data: dict or None
        :returns: Parsed JSON response
        :raises APIError: on non-200 responses or JSON parse failures
        """
        # Work on a copy so we never mutate the caller's dict
        params = dict(params)
        params['key'] = self.api_key

        # Determine the base_url based on which service we're interacting with
        base_url = {
            'shodan': self.base_url,
            'exploits': self.base_exploits_url,
            'trends': self.base_trends_url,
        }.get(service, self.base_url)

        # Wait for API rate limit (non-blocking)
        if self._api_query_time is not None and self.api_rate_limit > 0:
            loop = asyncio.get_running_loop()
            interval = 1.0 / self.api_rate_limit
            elapsed = loop.time() - self._api_query_time
            wait = interval - elapsed
            if wait > 0:
                await asyncio.sleep(wait)

        session = self._get_session()
        encoded = self._encode_params(params)

        try:
            method_lower = method.lower()
            url = base_url + function
            if method_lower == 'post':
                if json_data:
                    resp = await session.post(
                        url, params=encoded,
                        data=json.dumps(json_data),
                        headers={'content-type': 'application/json'},
                        proxy=self._proxies,
                    )
                else:
                    resp = await session.post(url, params=encoded, proxy=self._proxies)
            elif method_lower == 'put':
                resp = await session.put(url, params=encoded, proxy=self._proxies)
            elif method_lower == 'delete':
                resp = await session.delete(url, params=encoded, proxy=self._proxies)
            else:
                resp = await session.get(url, params=encoded, proxy=self._proxies)
            self._api_query_time = asyncio.get_running_loop().time()
        except aiohttp.ClientError:
            raise APIError('Unable to connect to Shodan')

        async with resp:
            # Check that the API key wasn't rejected
            if resp.status == 401:
                try:
                    body = await resp.json(content_type=None)
                    error = body.get('error') or 'Invalid API key'
                except Exception:
                    text = await resp.text()
                    if text.startswith('<'):
                        error = 'Invalid API key'
                    else:
                        error = 'Invalid API key'
                raise APIError(error)
            elif resp.status == 403:
                raise APIError('Access denied (403 Forbidden)')
            elif resp.status == 502:
                raise APIError('Bad Gateway (502)')

            # Parse the response as JSON
            try:
                data = await resp.json(content_type=None)
            except Exception:
                raise APIError('Unable to parse JSON response')

        # Raise an exception if an error occurred
        if isinstance(data, dict) and 'error' in data:
            raise APIError(data['error'])

        return data

    async def count(self, query, facets=None):
        """Returns the total number of search results for the query.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param facets: (optional) A list of properties to get summary information on
        :type facets: list or None
        :returns: A dictionary with 1 main property: total. If facets have been provided then another
                  property called "facets" will be available at the top-level of the dictionary.
        """
        query_args = {
            'query': query,
        }
        if facets:
            query_args['facets'] = create_facet_string(facets)
        return await self._request('/shodan/host/count', query_args)

    async def host(self, ips, history=False, minify=False):
        """Get all available information on an IP.

        :param ips: IP address or list of IP addresses to look up
        :type ips: str or list
        :param history: (optional) True if you want to grab the historical banners
        :type history: bool
        :param minify: (optional) True to only return the list of ports and general host information
        :type minify: bool
        :returns: dict with host information
        """
        if isinstance(ips, str):
            ips = [ips]

        params = {}
        if history:
            params['history'] = history
        if minify:
            params['minify'] = minify
        return await self._request('/shodan/host/{}'.format(','.join(ips)), params)

    async def info(self):
        """Returns information about the current API key.

        :returns: dict with API plan information
        """
        return await self._request('/api-info', {})

    async def ports(self):
        """Get a list of ports that Shodan crawls.

        :returns: An array containing the ports that Shodan crawls for.
        """
        return await self._request('/shodan/ports', {})

    async def protocols(self):
        """Get a list of protocols that the Shodan on-demand scanning API supports.

        :returns: A dictionary containing the protocol name and description.
        """
        return await self._request('/shodan/protocols', {})

    async def scan(self, ips, force=False):
        """Scan a network using Shodan.

        :param ips: A list of IPs or netblocks in CIDR notation, or a dict of IPs to port/protocol pairs
        :type ips: str or list or dict
        :param force: Whether to force Shodan to re-scan the provided IPs (enterprise only)
        :type force: bool
        :returns: A dictionary with a unique ID, IP count, and remaining scan credits.
        """
        if isinstance(ips, str):
            ips = [ips]

        if isinstance(ips, dict):
            networks = json.dumps(ips)
        else:
            networks = ','.join(ips)

        params = {
            'ips': networks,
            'force': force,
        }

        return await self._request('/shodan/scan', params, method='post')

    async def scans(self, page=1):
        """Get a list of scans submitted.

        :param page: Page through the list of scans 100 results at a time
        :type page: int
        :returns: dict with scan list
        """
        return await self._request('/shodan/scans', {
            'page': page,
        })

    async def scan_internet(self, port, protocol):
        """Scan a network using Shodan across the entire Internet.

        :param port: The port that should get scanned.
        :type port: int
        :param protocol: The name of the protocol as returned by the protocols() method.
        :type protocol: str
        :returns: A dictionary with a unique ID to check on the scan progress.
        """
        params = {
            'port': port,
            'protocol': protocol,
        }

        return await self._request('/shodan/scan/internet', params, method='post')

    async def scan_status(self, scan_id):
        """Get the status information about a previously submitted scan.

        :param scan_id: The unique ID for the scan that was submitted
        :type scan_id: str
        :returns: A dictionary with general information about the scan, including its status.
        """
        return await self._request('/shodan/scan/{}'.format(scan_id), {})

    async def search(self, query, page=1, limit=None, offset=None, facets=None, minify=True, fields=None):
        """Search the SHODAN database.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param page: (optional) Page number of the search results
        :type page: int
        :param limit: (optional) Number of results to return
        :type limit: int or None
        :param offset: (optional) Search offset to begin getting results from
        :type offset: int or None
        :param facets: (optional) A list of properties to get summary information on
        :type facets: list or None
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool
        :param fields: (optional) List of properties that should get returned
        :type fields: list or None
        :returns: A dictionary with 2 main items: matches and total.
        """
        args = {
            'query': query,
            'minify': minify,
        }
        if limit:
            args['limit'] = limit
            if offset:
                args['offset'] = offset
        else:
            args['page'] = page

        if facets:
            args['facets'] = create_facet_string(facets)

        if fields and isinstance(fields, list):
            args['fields'] = ','.join(fields)

        return await self._request('/shodan/host/search', args)

    async def search_cursor(self, query, minify=True, retries=5, fields=None):
        """Search the SHODAN database and iterate over all results.

        This method is an async generator that can be used directly in ``async for``.
        It does not return a "matches" array or the "total" information, and it cannot
        be used with facets.

        :param query: Search query; identical syntax to the website
        :type query: str
        :param minify: (optional) Whether to minify the banner and only return the important data
        :type minify: bool
        :param retries: (optional) How often to retry the search in case it times out
        :type retries: int
        :param fields: (optional) List of properties that should get returned
        :type fields: list or None

        Usage::

            async for banner in api.search_cursor('apache'):
                print(banner)
        """
        page = 1
        total_pages = 0
        tries = 0

        # Grab the initial page and use the total to calculate the expected number of pages
        results = await self.search(query, minify=minify, page=page, fields=fields)
        if results['total']:
            total_pages = int(math.ceil(results['total'] / 100))

        for banner in results['matches']:
            yield banner
        page += 1

        # Keep iterating over the results from page 2 onwards
        while page <= total_pages:
            try:
                results = await self.search(query, minify=minify, page=page, fields=fields)
                for banner in results['matches']:
                    yield banner
                page += 1
                tries = 0
            except APIError:
                # We've retried several times but it keeps failing, so lets error out
                if tries >= retries:
                    raise APIError('Retry limit reached ({:d})'.format(retries))

                tries += 1
                await asyncio.sleep(tries)  # wait (1 second * retry number) if the search errored out

    async def search_facets(self):
        """Returns a list of search facets.

        :returns: A list of strings where each is a facet name
        """
        return await self._request('/shodan/host/search/facets', {})

    async def search_filters(self):
        """Returns a list of search filters that are available.

        :returns: A list of strings where each is a filter name
        """
        return await self._request('/shodan/host/search/filters', {})

    async def search_tokens(self, query):
        """Returns information about the search query itself (filters used etc.)

        :param query: Search query; identical syntax to the website
        :type query: str
        :returns: A dictionary with 4 main properties: filters, errors, attributes and string.
        """
        query_args = {
            'query': query,
        }
        return await self._request('/shodan/host/search/tokens', query_args)

    async def services(self):
        """Get a list of services that Shodan crawls.

        :returns: A dictionary containing the ports/services that Shodan crawls for.
        """
        return await self._request('/shodan/services', {})

    async def queries(self, page=1, sort='timestamp', order='desc'):
        """List the search queries that have been shared by other users.

        :param page: Page number to iterate over results; each page contains 10 items
        :type page: int
        :param sort: Sort the list based on a property. Possible values are: votes, timestamp
        :type sort: str
        :param order: Sort order. Possible values are: asc, desc
        :type order: str
        :returns: A list of saved search queries (dictionaries).
        """
        args = {
            'page': page,
            'sort': sort,
            'order': order,
        }
        return await self._request('/shodan/query', args)

    async def queries_search(self, query, page=1):
        """Search the directory of saved search queries in Shodan.

        :param query: The search string to look for in the search query
        :type query: str
        :param page: Page number to iterate over results; each page contains 10 items
        :type page: int
        :returns: A list of saved search queries (dictionaries).
        """
        args = {
            'page': page,
            'query': query,
        }
        return await self._request('/shodan/query/search', args)

    async def queries_tags(self, size=10):
        """Get the most popular tags in the saved queries directory.

        :param size: The number of tags to return
        :type size: int
        :returns: A list of tags.
        """
        args = {
            'size': size,
        }
        return await self._request('/shodan/query/tags', args)

    async def create_alert(self, name, ip, expires=0):
        """Create a network alert/ private firehose for the specified IP range(s).

        :param name: Name of the alert
        :type name: str
        :param ip: Network range(s) to monitor
        :type ip: str or list
        :param expires: Number of seconds for the alert to be active (0 = indefinite)
        :type expires: int
        :returns: A dict describing the alert
        """
        data = {
            'name': name,
            'filters': {
                'ip': ip,
            },
            'expires': expires,
        }

        return await self._request('/shodan/alert', params={}, json_data=data, method='post')

    async def edit_alert(self, aid, ip):
        """Edit the IPs that should be monitored by the alert.

        :param aid: Alert ID
        :type aid: str
        :param ip: Network range(s) to monitor
        :type ip: str or list
        :returns: A dict describing the alert
        """
        data = {
            'filters': {
                'ip': ip,
            },
        }

        return await self._request('/shodan/alert/{}'.format(aid), params={}, json_data=data, method='post')

    async def alerts(self, aid=None, include_expired=True):
        """List all of the active alerts that the user created.

        :param aid: (optional) Alert ID to retrieve a specific alert
        :type aid: str or None
        :param include_expired: Whether to include expired alerts
        :type include_expired: bool
        :returns: dict or list of alert objects
        """
        if aid:
            func = '/shodan/alert/{}/info'.format(aid)
        else:
            func = '/shodan/alert/info'

        return await self._request(func, params={
            'include_expired': include_expired,
        })

    async def delete_alert(self, aid):
        """Delete the alert with the given ID.

        :param aid: Alert ID
        :type aid: str
        :returns: dict with success status
        """
        return await self._request('/shodan/alert/{}'.format(aid), params={}, method='delete')

    async def alert_triggers(self):
        """Return a list of available triggers that can be enabled for alerts.

        :returns: A list of triggers
        """
        return await self._request('/shodan/alert/triggers', {})

    async def enable_alert_trigger(self, aid, trigger):
        """Enable the given trigger on the alert.

        :param aid: Alert ID
        :type aid: str
        :param trigger: Trigger name
        :type trigger: str
        :returns: dict with success status
        """
        return await self._request('/shodan/alert/{}/trigger/{}'.format(aid, trigger), {}, method='put')

    async def disable_alert_trigger(self, aid, trigger):
        """Disable the given trigger on the alert.

        :param aid: Alert ID
        :type aid: str
        :param trigger: Trigger name
        :type trigger: str
        :returns: dict with success status
        """
        return await self._request('/shodan/alert/{}/trigger/{}'.format(aid, trigger), {}, method='delete')

    async def ignore_alert_trigger_notification(self, aid, trigger, ip, port, vulns=None):
        """Ignore trigger notifications for the provided IP and port.

        :param aid: Alert ID
        :type aid: str
        :param trigger: Trigger name
        :type trigger: str
        :param ip: IP address
        :type ip: str
        :param port: Port number
        :type port: int
        :param vulns: (optional) List of CVE IDs to ignore (for vulnerable/vulnerable_unverified triggers)
        :type vulns: list or None
        :returns: dict with success status
        """
        if trigger in ('vulnerable', 'vulnerable_unverified') and vulns and isinstance(vulns, list):
            return await self._request(
                '/shodan/alert/{}/trigger/{}/ignore/{}:{}/{}'.format(
                    aid, trigger, ip, port, ','.join(vulns)),
                {}, method='put')

        return await self._request(
            '/shodan/alert/{}/trigger/{}/ignore/{}:{}'.format(aid, trigger, ip, port),
            {}, method='put')

    async def unignore_alert_trigger_notification(self, aid, trigger, ip, port):
        """Re-enable trigger notifications for the provided IP and port.

        :param aid: Alert ID
        :type aid: str
        :param trigger: Trigger name
        :type trigger: str
        :param ip: IP address
        :type ip: str
        :param port: Port number
        :type port: int
        :returns: dict with success status
        """
        return await self._request(
            '/shodan/alert/{}/trigger/{}/ignore/{}:{}'.format(aid, trigger, ip, port),
            {}, method='delete')

    async def add_alert_notifier(self, aid, nid):
        """Enable the given notifier for an alert that has triggers enabled.

        :param aid: Alert ID
        :type aid: str
        :param nid: Notifier ID
        :type nid: str
        :returns: dict with success status
        """
        return await self._request('/shodan/alert/{}/notifier/{}'.format(aid, nid), {}, method='put')

    async def remove_alert_notifier(self, aid, nid):
        """Remove the given notifier for an alert that has triggers enabled.

        :param aid: Alert ID
        :type aid: str
        :param nid: Notifier ID
        :type nid: str
        :returns: dict with success status
        """
        return await self._request('/shodan/alert/{}/notifier/{}'.format(aid, nid), {}, method='delete')
