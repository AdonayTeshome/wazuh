# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from json import JSONDecodeError
import logging
import contextlib

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.exceptions import HTTPException
from connexion import ConnexionMiddleware
from connexion.exceptions import OAuthProblem, ProblemException, Unauthorized
from connexion.problem import problem as connexion_problem
from secure.secure import Secure
from wazuh.core import common
from wazuh.core.wlogging import TimeBasedFileRotatingHandler, SizeBasedFileRotatingHandler
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests
from wazuh.core.utils import get_utc_now

from api import alogging, configuration
from api.util import raise_if_exc, APILoggerSize
from api.constants import API_LOG_PATH

MAX_REQUESTS_EVENTS_DEFAULT = 30

# API secure headers
secure_headers = Secure(server="Wazuh", csp="none", xfo="DENY")

logger = logging.getLogger('wazuh-api')

def _cleanup_detail_field(detail: str) -> str:
    """Replace double endlines with '. ' and simple endlines with ''.

    Parameters
    ----------
    detail : str
        String to be modified.

    Returns
    -------
    str
        New value for the detail field.
    """
    return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Set secure headers."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """dispatch secure headers.
        
        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """
        resp = await call_next(request)
        secure_headers.framework.starlette(resp)
        return resp


IP_STATS = dict()
IP_BLOCK = set()
GENERAL_REQUEST_COUNTER = 0
GENERAL_CURRENT_TIME = None
EVENTS_REQUEST_COUNTER = 0
EVENTS_CURRENT_TIME = None


async def unlock_ip(request: Request, block_time: int):
    """This function blocks/unblocks the IPs that are requesting an API token.

    Parameters
    ----------
    request : web_request.BaseRequest
        API request.
    block_time : int
        Block time used to decide if the IP is going to be unlocked.
    """
    global IP_BLOCK, IP_STATS
    try:
        if get_utc_now().timestamp() - block_time >= IP_STATS[request.client.host]['timestamp']:
            del IP_STATS[request.client.host]
            IP_BLOCK.remove(request.client.host)
    except (KeyError, ValueError):
        pass

    if request.client.host in IP_BLOCK:
        logger.warning(f'IP blocked due to exceeded number of logins attempts: {request.client.host}')
        raise_if_exc(WazuhPermissionError(6000))


async def prevent_bruteforce_attack(request: Request, attempts: int = 5):
    """This function checks that the IPs that are requesting an API token do not do so repeatedly.

    Parameters
    ----------
    request : web_request.BaseRequest
        API request.
    attempts : int
        Number of attempts until an IP is blocked.
    """
    global IP_STATS, IP_BLOCK
    if request.path in {'/security/user/authenticate', '/security/user/authenticate/run_as'} and \
            request.method in {'GET', 'POST'}:
        if request.client.host not in IP_STATS.keys():
            IP_STATS[request.client.host] = dict()
            IP_STATS[request.client.host]['attempts'] = 1
            IP_STATS[request.client.host]['timestamp'] = get_utc_now().timestamp()
        else:
            IP_STATS[request.client.host]['attempts'] += 1

        if IP_STATS[request.client.host]['attempts'] >= attempts:
            IP_BLOCK.add(request.client.host)


class RequestLogginMiddleware(BaseHTTPMiddleware):
    """Log request middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Add request info to logging.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """
        self.logger.debug2(f'Receiving headers {dict(request.headers)}')
        try:
            body = await request.json()
            request['body'] = body
        except JSONDecodeError:
            pass

        return await call_next(request)


async def check_rate_limit(
    request:Request,
    request_counter_key: str,
    current_time_key: str,
    max_requests: int
) -> None:
    """This function checks that the maximum number of requests per minute
    passed in `max_requests` is not exceeded.

    Parameters
    ----------
    request : Request
        API request.
    request_counter_key : str
        Key of the request counter variable to get from globals() dict.
    current_time_key : str
        Key of the current time variable to get from globals() dict.
    max_requests : int, optional
        Maximum number of requests per minute permitted.
    """

    error_code_mapping = {
        'GENERAL_REQUEST_COUNTER': {'code': 6001},
        'EVENTS_REQUEST_COUNTER': {
            'code': 6005,
            'extra_message': f'For POST /events endpoint the limit is set to {max_requests} requests.'
        }
    }
    if not globals()[current_time_key]:
        globals()[current_time_key] = get_utc_now().timestamp()

    if get_utc_now().timestamp() - 60 <= globals()[current_time_key]:
        globals()[request_counter_key] += 1
    else:
        globals()[request_counter_key] = 0
        globals()[current_time_key] = get_utc_now().timestamp()

    if globals()[request_counter_key] > max_requests:
        logger.debug(f'Request rejected due to high request per minute: Source IP: {request.client.host}')
        raise_if_exc(WazuhTooManyRequests(**error_code_mapping[request_counter_key]))


class CheckRateLimitsMiddleware(BaseHTTPMiddleware):
    """Security Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """"Check Limits per minute"""
        access_conf = configuration.api_conf['access']
        max_request_per_minute = access_conf['max_request_per_minute']

        if max_request_per_minute > 0:
            await check_rate_limit(
                request,
                'GENERAL_REQUEST_COUNTER',
                'GENERAL_CURRENT_TIME',
                max_request_per_minute
            )

            if request.url.path == '/events':
                await check_rate_limit(
                    request,
                    'EVENTS_REQUEST_COUNTER',
                    'EVENTS_CURRENT_TIME',
                    MAX_REQUESTS_EVENTS_DEFAULT
                )

        await unlock_ip(request, block_time=access_conf['block_time'])
        return await call_next(request)


class RemoveFieldsFromErrorMiddleware(BaseHTTPMiddleware):
    """Remove fields from error response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Remove unwanted fields from error responses like 400 or 403.

        Additionally, it cleans the output given by connexion's exceptions.
        If no exception is raised during the 'await handler(request) it means
        the output will be a 200 response and no fields needs to be removed.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """

        def remove_unwanted_fields(fields_to_remove=None):
            fields_to_remove = fields_to_remove or ['status', 'type']
            for field in fields_to_remove:
                if field in problem.body:
                    del problem.body[field]
            if problem.body.get('detail') == '':
                del problem.body['detail']
            if 'code' in problem.body:
                problem.body['error'] = problem.body.pop('code')

        problem = None

        try:
            return await call_next(request)
        except (OAuthProblem, Unauthorized) as auth_exception:
            if request.path in {'/security/user/authenticate',
                                '/security/user/authenticate/run_as'} and \
                    request.method in {'GET', 'POST'}:
                await prevent_bruteforce_attack(request=request,
                                                attempts=configuration.api_conf['access']['max_login_attempts'])
                problem = connexion_problem(401, "Unauthorized",
                                            type="about:blank",
                                            detail="Invalid credentials")
            else:
                if isinstance(auth_exception, OAuthProblem):
                    problem = connexion_problem(401, "Unauthorized", type="about:blank",
                                                detail="No authorization token provided")
                else:
                    problem = connexion_problem(401, "Unauthorized",
                                                type="about:blank",
                                                detail="Invalid token")
        except ProblemException as exc:
            problem = connexion_problem(
                status=exc.__dict__['status'],
                title=exc.__dict__['title'] if exc.__dict__.get('title') else 'Bad Request',
                type=exc.__dict__.get('type', 'about:blank'),
                detail=_cleanup_detail_field(exc.__dict__['detail'])
                if 'detail' in exc.__dict__ else '',
                ext=exc.__dict__.get('ext'))
        except HTTPException as exc:
            problem = connexion_problem(status=exc.status_code,
                                        title='HTTPException',
                                        detail=exc.detail if exc.detail else '')
        finally:
            if problem:
                remove_unwanted_fields()

        return problem

@contextlib.asynccontextmanager
async def lifespan_handler(app: ConnexionMiddleware):
    plain_log = 'plain' in configuration.api_conf['logs']['format']
    json_log = 'json' in configuration.api_conf['logs']['format']
    if plain_log:
        log_path=f'{API_LOG_PATH}.log'
    elif json_log:
        log_path=f'{API_LOG_PATH}.json'

    if not configuration.api_conf['logs']['max_size']['enabled']:
        custom_handler = TimeBasedFileRotatingHandler(filename=log_path, when='midnight')
    else:
        max_size = APILoggerSize(configuration.api_conf['logs']['max_size']['size']).size
        custom_handler = SizeBasedFileRotatingHandler(filename=log_path,
                                                        maxBytes=max_size,
                                                        backupCount=1)

    for logger_name in ('uvicorn', 'uvicorn.acces', 'uvicorn.error', 'wazuh-api'):
        foreground_mode = isinstance(logging.getLogger(logger_name).handlers[0], logging.StreamHandler)
        api_logger = alogging.APILogger(
            log_path=log_path, foreground_mode=foreground_mode, logger_name=logger_name,
            debug_level='info' \
                if logger_name != 'wazuh-api' and configuration.api_conf['logs']['level'] != 'debug2' \
                    else configuration.api_conf['logs']['level']
        )
        api_logger.setup_logger(custom_handler)
    if os.path.exists(log_path):
        os.chown(log_path, common.wazuh_uid(), common.wazuh_gid())
        os.chmod(log_path, 0o660)

    yield
