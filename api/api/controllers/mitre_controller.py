# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from starlette.responses import Response

from api.controllers.util import _json_response
from api.util import raise_if_exc, parse_api_param, remove_nones_to_dict
from wazuh import mitre
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_metadata(token_info, pretty: bool = False, wait_for_complete: bool = False) -> Response:
    """Return the metadata of the MITRE's database.

    Parameters
    ----------
    token_info: dict
        Security information.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    Response
        API response.
    """

    dapi = DistributedAPI(f=mitre.mitre_metadata,
                          f_kwargs={},
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)


async def get_references(token_info, reference_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                         offset: int = None, limit: int = None, sort: str = None, search: str = None,
                         select: list = None, q: str = None) -> Response:
    """Get information of specified MITRE's references.

    Parameters
    ----------
    token_info: dict
        Security information.
    reference_ids : list
        List of reference ids to be obtained.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.

    Returns
    -------
    Response
        API response with the MITRE's references information.
    """
    f_kwargs = {
        'filters': {
            'id': reference_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort else None,
        'sort_ascending': False if not sort or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search else None,
        'select': select,
        'q': q
    }

    dapi = DistributedAPI(f=mitre.mitre_references,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)


async def get_tactics(token_info, tactic_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                      offset: int = None, limit: int = None, sort: str = None, search: str = None, select: list = None,
                      q: str = None, distinct: bool = False) -> Response:
    """Get information of specified MITRE's tactics.

    Parameters
    ----------
    token_info: dict
        Security information.
    tactic_ids : list
        List of tactic ids to be obtained.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    Response
        API response with the MITRE's tactics information.
    """
    f_kwargs = {
        'filters': {
            'id': tactic_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort else None,
        'sort_ascending': False if not sort or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search else None,
        'select': select,
        'q': q,
        'distinct': distinct
    }

    dapi = DistributedAPI(f=mitre.mitre_tactics,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)


async def get_techniques(token_info, technique_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                         offset: int = None, limit: int = None, sort: str = None, search: str = None,
                         select: list = None, q: str = None, distinct: bool = False) -> Response:
    """Get information of specified MITRE's techniques.

    Parameters
    ----------
    token_info: dict
        Security information.
    technique_ids : list, optional
        List of technique ids to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    Response
        API response with the MITRE's techniques information.
    """
    f_kwargs = {'filters': {
        'id': technique_ids,
    },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select, 
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_techniques,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies'])

    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)


async def get_mitigations(token_info, mitigation_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                          offset: int = None, limit: int = None, sort: str = None, search: str = None,
                          select: list = None, q: str = None, distinct: bool = False) -> Response:
    """Get information of specified MITRE's mitigations.

    Parameters
    ----------
    token_info: dict
        Security information.
    mitigation_ids : list, optional
        List of mitigation ids to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    Response
        API response with the MITRE's mitigations information.
    """
    f_kwargs = {'filters': {
        'id': mitigation_ids,
    },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select,
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_mitigations,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)


async def get_groups(token_info, group_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                     offset: int = None, limit: int = None, sort: str = None, search: str = None, select: list = None,
                     q: str = None, distinct: bool = False) -> Response:
    """Get information of specified MITRE's groups.

    Parameters
    ----------
    token_info: dict
        Security information.
    group_ids : list, optional
        List of group IDs to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    Response
        API response with the MITRE's groups information.
    """
    f_kwargs = {
        'filters': {
            'id': group_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select,
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)


async def get_software(token_info, software_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = None, limit: int = None, sort: str = None, search: str = None, select: list = None,
                       q: str = None, distinct: bool = False) -> Response:
    """Get information of specified MITRE's software.

    Parameters
    ----------
    token_info: dict
        Security information.
    software_ids : list, optional
        List of softwware IDs to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    Response
        API response with the MITRE's software information.
    """
    f_kwargs = {
        'filters': {
            'id': software_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select,
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_software,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies'])

    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)
