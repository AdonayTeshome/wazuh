# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import binascii
import json
import logging
import hashlib
import time
import base64
import contextlib
from jose.jwt import get_unverified_claims

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.exceptions import HTTPException
from connexion import ConnexionMiddleware
from connexion.exceptions import OAuthProblem, ProblemException, Unauthorized
from connexion.problem import problem as connexion_problem
from secure import Secure, ContentSecurityPolicy, XFrameOptions, Server
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests
from wazuh.core.utils import get_utc_now

from api import configuration
from api.util import raise_if_exc

# Default of the max event requests allowed per minute
MAX_REQUESTS_EVENTS_DEFAULT = 30

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"

# API secure headers
server = Server().set("Wazuh")
csp = ContentSecurityPolicy()
csp.default_src('self')
xfo = XFrameOptions().deny()
secure_headers = Secure(server=server, csp=csp, xfo=xfo)

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
        logger.debug2(f'Receiving headers {dict(request.headers)}')
        try:
            body = await request.json()
            request['body'] = body
        except json.JSONDecodeError:
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


class WazuhAccessLoggerMiddleware(BaseHTTPMiddleware):
    """Middleware to log custom Access messages."""

    def custom_logging(self, user, remote, method, path, query,
                       body, elapsed_time, status, hash_auth_context=''):
        """Provide the log entry structure depending on the logging format.

        Parameters
        ----------
        user : str
            User who perform the request.
        remote : str
            IP address of the request.
        method : str
            HTTP method used in the request.
        path : str
            Endpoint used in the request.
        query : dict
            Dictionary with the request parameters.
        body : dict
            Dictionary with the request body.
        elapsed_time : float
            Required time to compute the request.
        status : int
            Status code of the request.
        hash_auth_context : str, optional
            Hash representing the authorization context. Default: ''
        """
        json_info = {
            'user': user,
            'ip': remote,
            'http_method': method,
            'uri': f'{method} {path}',
            'parameters': query,
            'body': body,
            'time': f'{elapsed_time:.3f}s',
            'status_code': status
        }

        if not hash_auth_context:
            log_info = f'{user} {remote} "{method} {path}" '
        else:
            log_info = f'{user} ({hash_auth_context}) {remote} "{method} {path}" '
            json_info['hash_auth_context'] = hash_auth_context

        if path == '/events' and logger.level >= 20:
            # If log level is info simplify the messages for the /events requests.
            events = body.get('events', [])
            body = {'events': len(events)}
            json_info['body'] = body

        log_info += f'with parameters {json.dumps(query)} and body'\
             f' {json.dumps(body)} done in {elapsed_time:.3f}s: {status}'

        logger.info(log_info, extra={'log_type': 'log'})
        logger.info(json_info, extra={'log_type': 'json'})

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Log Wazuh access information.

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
        prev_time = time.time()
        response = await call_next(request)
        time_diff = time.time() - prev_time

        query = dict(request.query_params)
        body = request.get("body", dict())
        if 'password' in query:
            query['password'] = '****'
        if 'password' in body:
            body['password'] = '****'
        if 'key' in body and '/agents' in request.path:
            body['key'] = '****'

        # With permanent redirect, not found responses or any response with no token information,
        # decode the JWT token to get the username
        user = request.get('user', '')
        if not user:
            try:
                auth_type, encoded_credentials = request.headers["authorization"].split()
                if auth_type == 'Basic':
                    user = base64.b64decode(encoded_credentials).decode("utf-8").split(':')[1]
                elif auth_type == 'Bearer':
                    user = get_unverified_claims(encoded_credentials)['sub']
                else:
                    user = UNKNOWN_USER_STRING    
            except (KeyError, IndexError, binascii.Error):
                user = UNKNOWN_USER_STRING

        # Get or create authorization context hash
        hash_auth_context = ''
        # Get hash from token information
        if 'token_info' in request:
            hash_auth_context = request['token_info'].get('hash_auth_context', '')
        # Create hash if run_as login
        if not hash_auth_context and request.scope['path'] == RUN_AS_LOGIN_ENDPOINT:
            hash_auth_context = hashlib.blake2b(json.dumps(body).encode(),
                                                digest_size=16).hexdigest()

        self.custom_logging(user, request.client.host, request.method,
                            request.scope['path'], query, body, time_diff, response.status_code,
                            hash_auth_context=hash_auth_context)
        return response

@contextlib.asynccontextmanager
async def lifespan_handler(_: ConnexionMiddleware):
    """Lifespan handler to start tasks at startup."""

    # Log the initial server startup message.
    msg = f'Listening on {configuration.api_conf["host"]}:{configuration.api_conf["port"]}.'
    logger.info(msg)
    yield
    logger.info('Shutdown wazuh-apid server.')
