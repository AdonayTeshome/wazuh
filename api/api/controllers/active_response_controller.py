# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from starlette.responses import Response

import wazuh.active_response as active_response
from api.controllers.util import json_response
from api.models.active_response_model import ActiveResponseModel
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def run_command(body, token_info, agents_list: str = '*', pretty: bool = False,
                      wait_for_complete: bool = False) -> Response:
    """Runs an Active Response command on a specified list of agents.

    Parameters
    ----------
    body: dict
        HTTP request body.
    token_info : dict
        Security information.
    agents_list : str
        List of agents IDs. All possible values from 000 onwards. Default: '*'
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    Response
    """
    f_kwargs = await ActiveResponseModel.get_kwargs(body, additional_kwargs={'agent_list': agents_list})

    dapi = DistributedAPI(f=active_response.run_command,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
