# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import logging
import hashlib
import time
import contextlib

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.exceptions import HTTPException
from connexion import ConnexionMiddleware
from connexion.exceptions import OAuthProblem, ProblemException, Unauthorized
from connexion.problem import problem as connexion_problem
from connexion.lifecycle import ConnexionRequest
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


ip_stats = dict()
ip_block = set()
general_request_counter = 0
general_current_time = None
events_request_counter = 0
events_current_time = None


async def unlock_ip(request: Request, block_time: int):
    """This function blocks/unblocks the IPs that are requesting an API token.

    Parameters
    ----------
    request : Request
        API request.
    block_time : int
        Block time used to decide if the IP is going to be unlocked.
    """
    global ip_block, ip_stats
    try:
        if get_utc_now().timestamp() - block_time >= ip_stats[request.client.host]['timestamp']:
            del ip_stats[request.client.host]
            ip_block.remove(request.client.host)
    except (KeyError, ValueError):
        pass

    if request.client.host in ip_block:
        msg = f'IP blocked due to exceeded number of logins attempts: {request.client.host}'
        logger.warning(msg)
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
    global ip_stats, ip_block
    if request.path in {'/security/user/authenticate', '/security/user/authenticate/run_as'} and \
            request.method in {'GET', 'POST'}:
        if request.client.host not in ip_stats.keys():
            ip_stats[request.client.host] = dict()
            ip_stats[request.client.host]['attempts'] = 1
            ip_stats[request.client.host]['timestamp'] = get_utc_now().timestamp()
        else:
            ip_stats[request.client.host]['attempts'] += 1

        if ip_stats[request.client.host]['attempts'] >= attempts:
            ip_block.add(request.client.host)


async def check_rate_limit(
    request: Request,
    request_counter_key: str,
    current_time_key: str,
    max_requests: int
) -> None:
    """This function checks that the maximum number of requests per minute
    passed in `max_requests` is not exceeded.

    Parameters
    ----------
    request : Request
        HTTP request.
    request_counter_key : str
        Key of the request counter variable to get from globals() dict.
    current_time_key : str
        Key of the current time variable to get from globals() dict.
    max_requests : int, optional
        Maximum number of requests per minute permitted.
    """

    error_code_mapping = {
        'general_request_counter': {'code': 6001},
        'events_request_counter': {
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
                'general_request_counter',
                'general_current_time',
                max_request_per_minute
            )

            if request.url.path == '/events':
                await check_rate_limit(
                    request,
                    'events_request_counter',
                    'events_current_time',
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

        problem = None

        try:
            return await call_next(request)
        except (OAuthProblem, Unauthorized) as auth_exception:
            problem = {
                "status": 401, 
                "title": "Unauthorized",
                "type": "about:blank",
            }

            if request.path in {'/security/user/authenticate',
                                '/security/user/authenticate/run_as'} and \
                request.method in {'GET', 'POST'}:
                await prevent_bruteforce_attack(
                    request=request,
                    attempts=configuration.api_conf['access']['max_login_attempts']
                )
                problem["detail"] = "Invalid credentials"
            elif isinstance(auth_exception, OAuthProblem):
                problem["detail"] = "No authorization token provided"
            else:
                problem["detail"] = "Invalid token"
        except ProblemException as exc:
            problem = {
                "status": exc.__dict__['status'],
                "title": exc.__dict__['title'] if exc.__dict__.get('title') else 'Bad Request',
                "type": exc.__dict__.get('type', 'about:blank'),
                "detail": _cleanup_detail_field(exc.__dict__['detail']) \
                                if 'detail' in exc.__dict__ \
                                else ''
            }
            if exc.__dict__.get('ext'):
                problem.update(exc.__dict__.get('ext', {}))

        except HTTPException as exc:
            problem = {
                "status": exc.status_code, 
                "title": 'HTTPException',
                "type": "about:blank",
                "detail": exc.detail if exc.detail else ''
            }

        finally:
            if problem:
                # clean fields from the details
                status = problem.pop('status')
                if type(problem['detail']) == dict:
                    for field in ['status', 'type']:
                        problem['detail'].pop(field)
                elif problem['detail'] == '':
                    del problem['detail']
                if 'code' in problem:
                    problem['error'] = problem.pop('code')

                response = Response(content=json.dumps(problem),
                                    status_code=status,
                                    media_type='"application/problem+json"')

        return response


class WazuhAccessLoggerMiddleware(BaseHTTPMiddleware):
    """Middleware to log custom Access messages."""

    def custom_logging(self, user, remote, method, path, query,
                       body, elapsed_time, status, hash_auth_context='',
                       headers: dict = None):
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
        headers: dict
            Optional dictionary of request headers.
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
        logger.debug2(f'Receiving headers {headers}')

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
        body = await request.json() \
                    if 'json' in request.headers.get('content-type', '') and \
                    int(request.headers.get('content-length', '0')) > 0 \
                    else {}
        response = await call_next(request)
        req = ConnexionRequest.from_starlette_request(request)
        time_diff = time.time() - prev_time

        query = dict(req.query_params)
        if 'password' in query:
            query['password'] = '****'
        if 'password' in body:
            body['password'] = '****'
        if 'key' in body and '/agents' in req.scope['path']:
            body['key'] = '****'

        # With permanent redirect, not found responses or any response with no token information,
        # decode the JWT token to get the username
        user = req.context.get('user', UNKNOWN_USER_STRING)

        # Get or create authorization context hash
        hash_auth_context = req.context.get('token_info', {}).get('hash_auth_context', '')
        # Create hash if run_as login
        if not hash_auth_context and req.scope['path'] == RUN_AS_LOGIN_ENDPOINT:
            hash_auth_context = hashlib.blake2b(json.dumps(body).encode(),
                                                digest_size=16).hexdigest()

        self.custom_logging(user, req.client.host, req.method,
                            req.scope['path'], query, body, time_diff, response.status_code,
                            hash_auth_context=hash_auth_context, headers=req.headers)
        return response


@contextlib.asynccontextmanager
async def lifespan_handler(_: ConnexionMiddleware):
    """Lifespan handler to start tasks at startup."""

    # Log the initial server startup message.
    msg = f'Listening on {configuration.api_conf["host"]}:{configuration.api_conf["port"]}.'
    logger.info(msg)
    yield
    logger.info('Shutdown wazuh-apid server.')
