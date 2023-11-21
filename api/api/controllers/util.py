# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from starlette.responses import Response

from api.models.security_token_response_model import TokenResponseModel
from api.authentication import generate_token
from api.util import raise_if_exc
from api.encoder import dumps, prettify

from wazuh.core.exception import WazuhException
from wazuh.core.results import WazuhResult


def token_response(user: str, data: dict, raw: bool = True) -> Response:
    """Generate a token and returns a Response object.

    Parameters
    ----------
    user: str
        Name of the user who wants to be authenticated.
    data : dict
        Roles permissions for the user.    
    raw: bool 
        Name of the user who wants to be authenticated.

    Returns
    -------
    Response
        Raw or JSON response with the generated access token.

    Raises
    ------
    WazuhException
        ProblemException or `exc` exception type.
        
    """

    token = None
    try:
        token = generate_token(user_id=user, data=data)
    except WazuhException as exc:
        raise_if_exc(exc)

    if raw:
        res = Response(content=token, media_type='text/plain', status_code=200)
    else:
        res = Response(content=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
                       media_type="application/json",
                       status_code=200)
    return res


def json_response(data: dict, pretty: bool = False) -> Response:
    """Generate a json Response from a dictionary.

    Parameters
    ----------
    data: dict
        Data dictionary to convert to json.
    pretty:
        Prettify the response to be human readable.

    Returns
    -------
    Response
        JSON response  generated from the data.
    """
    return Response(content=prettify(data) if pretty else dumps(data),
                   media_type="application/json",
                   status_code=200)
