import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from starlette.responses import Response
from connexion.testing import TestContext

from api.controllers.test.utils import CustomAffectedItems, token_info

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.event import send_event_to_analysisd
        from wazuh.tests.util import RBAC_bypasser

        from api.controllers.event_controller import forward_event

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']

@pytest.fixture
def mock_request():
    """fixture to wrap functions with request"""
    operation = MagicMock(name="operation")
    operation.method = "post"
    with TestContext(operation=operation):
        with patch('api.controllers.decoder_controller.request') as m_req:
            m_req.query.get = MagicMock(return_value='')
            yield m_req


@pytest.mark.asyncio
@patch('api.configuration.api_conf')
@patch('api.controllers.event_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.event_controller.remove_nones_to_dict')
@patch('api.controllers.event_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.event_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_forward_event(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_exp,
                             mock_request, token_info):
    """Verify 'forward_event' endpoint is working as expected."""
    with patch('api.controllers.event_controller.Body.validate_content_type'):
        with patch(
            'api.controllers.event_controller.EventIngestModel.get_kwargs', return_value=AsyncMock()
        ) as mock_getkwargs:

            result = await forward_event(token_info, body={})
            mock_dapi.assert_called_once_with(
                f=send_event_to_analysisd,
                f_kwargs=mock_remove.return_value,
                request_type='local_any',
                is_async=False,
                wait_for_complete=False,
                logger=ANY,
                rbac_permissions=token_info['rbac_policies']
            )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(mock_getkwargs.return_value)
            assert isinstance(result, Response)
