# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import List

from starlette.responses import Response
from connexion import request

import wazuh.ciscat as ciscat
from api.controllers.util import json_response
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_agents_ciscat_results(token_info, agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                                    offset: int = 0, limit: int = None, select: List[str] = None, sort: str = None,
                                    search: str = None, benchmark: str = None, profile: str = None, fail: int = None,
                                    error: int = None, notchecked: int = None, unknown: int = None, score: int = None,
                                    q: str = None) -> Response:
    """Get CIS-CAT results from an agent

    Returns the agent's ciscat results info.

    Parameters
    ----------
    token_info : dict
        Security information.
    agent_id : str
        Agent ID. All posible values since 000 onwards.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    benchmark : str
        Filters by benchmark type.
    profile : str
        Filters by evaluated profile.
    fail : int
        Filters by failed checks.
    error : int
        Filters by encountered errors.
    notchecked : int
        Filters by notchecked value.
    unknown : int
        Filters by unknown results.
    score : int
        Filters by final score.
    q : str
        Query to filter results by.

    Returns
    -------
    Response
        API response.
    """
    f_kwargs = {
        'agent_list': [agent_id],
        'offset': offset,
        'limit': limit,
        'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'),
        'select': select,
        'filters': {
            'benchmark': benchmark,
            'profile': profile,
            'pass': request.query.get('pass', None),
            'fail': fail,
            'error': error,
            'notchecked': notchecked,
            'unknown': unknown,
            'score': score
        },
        'q': q
    }

    dapi = DistributedAPI(f=ciscat.get_ciscat_results,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    response = raise_if_exc(await dapi.distribute_function())

    return json_response(response, pretty=pretty)
