#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import signal
import sys
import asyncio
import logging
import ssl

import connexion
from connexion.options import SwaggerUIOptions
import uvicorn

from starlette.middleware.cors import CORSMiddleware
from content_size_limit_asgi import ContentSizeLimitMiddleware

from api.constants import API_LOG_PATH
from api.api_exception import APIError
from api import alogging, configuration
from api.configuration import api_conf, read_yaml_config
from api import __path__ as api_path
from api.constants import CONFIG_FILE_PATH
from api.middlewares import security_middleware, response_postprocessing, \
    request_logging, set_secure_headers
# from api.signals import modify_response_headers
from api.util import APILoggerSize, to_relative_path

from wazuh.rbac.orm import check_database_integrity
from wazuh.core.wlogging import TimeBasedFileRotatingHandler, SizeBasedFileRotatingHandler
from wazuh.core import pyDaemonModule, common, utils
from wazuh.core.cluster import __version__, __author__, __wazuh_name__, __licence__

API_MAIN_PROCESS = 'wazuh-apid'
API_LOCAL_REQUEST_PROCESS = 'wazuh-apid_exec'
API_AUTHENTICATION_PROCESS = 'wazuh-apid_auth'
API_SECURITY_EVENTS_PROCESS = 'wazuh-apid_events'

def spawn_process_pool():
    """Spawn general process pool child."""

    exec_pid = os.getpid()
    pyDaemonModule.create_pid(API_LOCAL_REQUEST_PROCESS, exec_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_events_pool():
    """Spawn events process pool child."""

    events_pid = os.getpid()
    pyDaemonModule.create_pid(API_SECURITY_EVENTS_PROCESS, events_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_authentication_pool():
    """Spawn authentication process pool child."""

    auth_pid = os.getpid()
    pyDaemonModule.create_pid(API_AUTHENTICATION_PROCESS, auth_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def start(params):
    """Run the Wazuh API.

    If another Wazuh API is running, this function fails.
    This function exits with 0 if successful or 1 if failed because the API was already running.
    """
    try:
        check_database_integrity()
    except Exception as db_integrity_exc:
        raise APIError(2012, details=str(db_integrity_exc)) from db_integrity_exc

    # Spawn child processes with their own needed imports
    if 'thread_pool' not in common.mp_pools.get():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            asyncio.wait([loop.run_in_executor(pool,
                                               getattr(sys.modules[__name__], f'spawn_{name}'))
                          for name, pool in common.mp_pools.get().items()]))

    # Set up API
    # asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    app = connexion.AsyncApp(
        __name__,
        specification_dir=os.path.join(api_path[0], 'spec'),
        swagger_ui_options=SwaggerUIOptions(swagger_ui=False)
    )
    app.add_api('spec.yaml',
                arguments={
                    'title': 'Wazuh API',
                    'protocol': 'https' if api_conf['https']['enabled'] else 'http',
                    'host': params['host'],
                    'port': params['port']},
                strict_validation=True,
                validate_responses=False
    )

    # Maximum body size that the API can accept (bytes)
    app.add_middleware(ContentSizeLimitMiddleware,
                       max_content_size=api_conf['max_upload_size'])
    # app.add_middleware(response_postprocessing)
    # app.add_middleware(security_middleware)
    # app.add_middleware(request_logging)
    # app.add_middleware(set_secure_headers)

    # Enable CORS
    if api_conf['cors']['enabled']:
        app.add_middleware(
            CORSMiddleware(app=app,
                           allow_origins=api_conf['cors']['source_route'],
                           expose_headers=api_conf['cors']['expose_headers'],
                           allow_headers=api_conf['cors']['allow_headers'],
                           allow_credentials=api_conf['cors']['allow_credentials'])
        )

    # Enable cache plugin
    # if api_conf['cache']['enabled']:
    #     setup_cache(app.app)

    # HAY QUE HACER: AGREGAR MIDDLEWARE PARA MODIFICAR LOS RESPONSE HEADERS
    # Add application signals
    # app.on_response_prepare.append(modify_response_headers)


    # API configuration logging
    logger.debug(f'Loaded API configuration: {api_conf}')
    logger.debug(f'Loaded security API configuration: {security_conf}')

    # Start uvicorn server

    try:
        uvicorn.run(app,**params)

    except OSError as exc:
        if exc.errno == 98:
            error = APIError(2010)
            logger.error(error)
            raise error
        else:
            logger.error(exc)
            raise exc


def print_version():
    print("\n{} {} - {}\n\n{}".format(__wazuh_name__, __version__, __author__, __licence__))


def test_config(config_file: str):
    """Make an attempt to read the API config file. Exits with 0 code if successful, 1 otherwise.

    Arguments
    ---------
    config_file : str
        Path of the file
    """
    try:
        read_yaml_config(config_file=config_file)
    except Exception as exc:
        print(f"Configuration not valid. ERROR: {exc}")
        sys.exit(1)
    sys.exit(0)


def version():
    """Print API version and exits with 0 code. """
    print_version()
    sys.exit(0)


def exit_handler(signum, frame):
    """Try to kill API child processes and remove their PID files."""
    api_pid = os.getpid()
    pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, api_pid, logger)
    pyDaemonModule.delete_pid(API_MAIN_PROCESS, api_pid)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    ####################################################################################################################
    parser.add_argument('-f', help="Run in foreground", action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version", action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration", action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root", action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use", type=str, metavar='config', dest='config_file')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", action='count',
                        dest='debug_level')
    args = parser.parse_args()

    if args.version:
        version()
        sys.exit(0)

    elif args.test_config:
        test_config(args.config_file)
        sys.exit(0)


    def set_logging(log_path=f'{API_LOG_PATH}.log', foreground_mode=False, debug_mode='info'):
        """Set up logging for the API.
        
        Parameters
        ----------
        log_path : str
            Path of the log file.
        foreground_mode : bool
            If True, the log will be printed to stdout.
        debug_mode : str
            Debug level. Possible values: disabled, info, warning, error, debug, debug2.
        """
        if not api_conf['logs']['max_size']['enabled']:
            custom_handler = TimeBasedFileRotatingHandler(filename=log_path, when='midnight')
        else:
            max_size = APILoggerSize(api_conf['logs']['max_size']['size']).size
            custom_handler = SizeBasedFileRotatingHandler(filename=log_path,
                                                          maxBytes=max_size,
                                                          backupCount=1)

        for logger_name in ('connexion.aiohttp_app', 'connexion.apis.aiohttp_api', 'wazuh-api'):
            api_logger = alogging.APILogger(
                log_path=log_path, foreground_mode=foreground_mode, logger_name=logger_name,
                debug_level='info' \
                    if logger_name != 'wazuh-api' and debug_mode != 'debug2' else debug_mode
            )
            api_logger.setup_logger(custom_handler)
        if os.path.exists(log_path):
            os.chown(log_path, common.wazuh_uid(), common.wazuh_gid())
            os.chmod(log_path, 0o660)

    try:
        if args.config_file is not None:
            api_conf.update(configuration.read_yaml_config(config_file=args.config_file))
        security_conf = configuration.security_conf
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)

    params = dict()
    # Set up logger
    try:
        plain_log = 'plain' in api_conf['logs']['format']
        json_log = 'json' in api_conf['logs']['format']

        if plain_log:
            set_logging(log_path=f'{API_LOG_PATH}.log', debug_mode=api_conf['logs']['level'],
                        foreground_mode=args.foreground)
        if json_log:
            set_logging(log_path=f'{API_LOG_PATH}.json', debug_mode=api_conf['logs']['level'],
                        foreground_mode=args.foreground and not plain_log)
    except APIError as api_log_error:
        print(f"Error when trying to start the Wazuh API. {api_log_error}")
        sys.exit(1)

    logger = logging.getLogger('wazuh-api')

    # from aiohttp_cache import setup_cache

    # Check deprecated options. To delete after expected versions
    if 'use_only_authd' in api_conf:
        del api_conf['use_only_authd']
        logger.warning(
            "'use_only_authd' option was deprecated on v4.3.0. Wazuh Authd will always be used")

    if 'path' in api_conf['logs']:
        del api_conf['logs']['path']
        logger.warning(
            "Log 'path' option was deprecated on v4.3.0. Default path will always be used: "
                       f"{API_LOG_PATH}.<log_format>")

    # Configure https
    if api_conf['https']['enabled']:
        try:
            # Generate SSL if it does not exist and HTTPS is enabled
            if not os.path.exists(api_conf['https']['key']) \
                or not os.path.exists(api_conf['https']['cert']):
                logger.info('HTTPS is enabled but cannot find the private key and/or certificate. '
                            'Attempting to generate them')
                private_key = configuration.generate_private_key(api_conf['https']['key'])
                logger.info(
                    f"Generated private key file in WAZUH_PATH/{to_relative_path(api_conf['https']['key'])}")
                configuration.generate_self_signed_certificate(private_key, api_conf['https']['cert'])
                logger.info(
                    f"Generated certificate file in WAZUH_PATH/{to_relative_path(api_conf['https']['cert'])}")

            # Load SSL context
            allowed_ssl_protocols = {
                'tls': ssl.PROTOCOL_TLS,
                'tlsv1': ssl.PROTOCOL_TLSv1,
                'tlsv1.1': ssl.PROTOCOL_TLSv1_1,
                'tlsv1.2': ssl.PROTOCOL_TLSv1_2
            }
            ssl_protocol = allowed_ssl_protocols[api_conf['https']['ssl_protocol'].lower()]
            ssl_context = ssl.SSLContext(protocol=ssl_protocol)
            ssl_context.load_cert_chain(certfile=api_conf['https']['cert'], keyfile=api_conf['https']['key'])

            params['ssl_version'] = allowed_ssl_protocols[api_conf['https']['ssl_protocol'].lower()]

            if api_conf['https']['use_ca']:
                params['ssl_cert_reqs'] = ssl.CERT_REQUIRED
                params['ssl_ca_certs'] = api_conf['https']['ca']

            params['ssl_certfile'] = api_conf['https']['cert']
            params['ssl_keyfile'] = api_conf['https']['key']

            # Load SSL ciphers if any has been specified
            if api_conf['https']['ssl_ciphers']:
                params['ssl_ciphers'] = api_conf['https']['ssl_ciphers'].upper()

        except ssl.SSLError as exc:
            error = APIError(2003, details='Private key does not match with the certificate')
            logger.error(error)
            raise error from exc
        except IOError as exc:
            if exc.errno == 22:
                error = APIError(2003, details='PEM phrase is not correct')
                logger.error(error)
                raise error from exc
            elif exc.errno == 13:
                error = APIError(2003, 
                                 details='Ensure the certificates have the correct permissions')
                logger.error(error)
                raise error from exc
            else:
                msg = f'Wazuh API SSL ERROR. Please, ensure ' \
                      f'if path to certificates is correct in the configuration ' \
                      f'file WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)}'
                print(msg)
                logger.error(msg)
                raise exc from exc

    # Check for unused PID files
    utils.clean_pid_files(API_MAIN_PROCESS)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()
    else:
        print('Starting API in foreground')

    # Drop privileges to wazuh
    if not args.root:
        if api_conf['drop_privileges']:
            os.setgid(common.wazuh_gid())
            os.setuid(common.wazuh_uid())
    else:
        print('Starting API as root')

    pid = os.getpid()
    pyDaemonModule.create_pid(API_MAIN_PROCESS, pid)

    signal.signal(signal.SIGTERM, exit_handler)
    params['host']=api_conf['host']
    params['port']=api_conf['port']
    params['loop']='uvloop'
    try:
        start(params)
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)
    except Exception as e:
        print(f'Internal error when trying to start the Wazuh API. {e}')
        sys.exit(1)
    finally:
        pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(API_MAIN_PROCESS, pid)
