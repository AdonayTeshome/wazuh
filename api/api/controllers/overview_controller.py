# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from starlette.responses import Response

from api.controllers.util import _json_response
from api.util import raise_if_exc, remove_nones_to_dict
from wazuh.agent import get_full_overview
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_overview_agents(token_info, pretty: bool = False, wait_for_complete: bool = False) -> Response:
    """Get full summary of agents.

    Parameters
    ----------
    token_info: dict
        Security information.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=get_full_overview,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return _json_response(data, pretty=pretty)
