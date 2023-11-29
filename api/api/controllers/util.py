# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from connexion.lifecycle import ConnexionResponse

from api.encoder import dumps, prettify
from api.models.security_token_response_model import TokenResponseModel
from api.authentication import generate_token
from api.util import raise_if_exc

from wazuh.core.exception import WazuhException
from wazuh.core.results import WazuhResult


def token_response(user: str, data: dict, raw: bool = True, auth_context: dict = None) -> ConnexionResponse:
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
        token = generate_token(user_id=user, data=data, auth_context=auth_context)
    except WazuhException as exc:
        raise_if_exc(exc)

    if raw:
        res = ConnexionResponse(body=token, mimetype='text/plain', status_code=200)
    else:
        res = ConnexionResponse(body=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
                                mimetype="application/json",
                                status_code=200)
    return res


def json_response(data: dict, pretty: bool = False) -> ConnexionResponse:
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
    return ConnexionResponse(body=prettify(data) if pretty else dumps(data),
                             mimetype="application/json",
                             status_code=200)
