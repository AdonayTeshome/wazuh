# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from starlette.responses import Response
from connexion import request

from api.controllers.util import json_response
from api.models.base_model_ import Body
from api.models.logtest_model import LogtestModel
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh import logtest
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def run_logtest_tool(token_info: dict, body: dict, pretty: bool = False, wait_for_complete: bool = False) -> Response:
    """Get the logtest output after sending a JSON to its socket.

    Parameters
    ----------
    token_info : dict
        Security information.
    body : dict
        HTTP body parsed from json into dict.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    Response
        API response.
    """
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await LogtestModel.get_kwargs(body)

    dapi = DistributedAPI(f=logtest.run_logtest,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def end_logtest_session(token_info: dict, pretty: bool = False,
                              wait_for_complete: bool = False, token: str = None) -> Response:
    """Delete the saved session corresponding to the specified token.

    Parameters
    ----------
    token_info : dict
        Security information.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    token : str
        Token of the saved session.
        
    Returns
    -------
    Response
        API response.
    """
    f_kwargs = {'token': token}

    dapi = DistributedAPI(f=logtest.end_logtest_session,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=token_info['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
