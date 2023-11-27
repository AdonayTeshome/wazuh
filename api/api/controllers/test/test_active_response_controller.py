import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from starlette.responses import Response
import api.controllers.test.utils as utils
from api.controllers.active_response_controller import run_command

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh import active_response
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@patch('api.controllers.active_response_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.active_response_controller.remove_nones_to_dict')
@patch('api.controllers.active_response_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.active_response_controller.raise_if_exc', return_value=utils.CustomAffectedItems())
async def test_run_command(mock_exc, mock_dapi, mock_remove, mock_dfunc, token_info):
    """Verify 'run_command' endpoint is working as expected."""
    with patch('api.controllers.active_response_controller.Body'):
        with patch('api.controllers.active_response_controller.ActiveResponseModel.get_kwargs',
                   return_value=AsyncMock()) as mock_getkwargs:
            result = await run_command(token_info)
            mock_dapi.assert_called_once_with(f=active_response.run_command,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='distributed_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              broadcasting=True,
                                              rbac_permissions=token_info['rbac_policies']
                                              )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, Response)
