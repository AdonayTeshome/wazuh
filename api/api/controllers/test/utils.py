from unittest.mock import MagicMock, patch
import pytest
from connexion.testing import TestContext

from wazuh.core.results import AffectedItemsWazuhResult


@pytest.fixture
def token_info():
    """token_info fixture."""
    return {
        "token": "1234567890",
        "sub": "wazuh",
        'rbac_policies': {}
    }

@pytest.yield_fixture(scope="session", autouse=True)
def test_context():
    """TestContext to run test with connexion."""
    operation = MagicMock(name="operation")
    operation.method = "post"
    return TestContext(operation=operation)

class CustomAffectedItems(AffectedItemsWazuhResult):
    """Mock custom values that are needed in controller tests"""

    def __init__(self, empty: bool = False):
        if not empty:
            super().__init__(dikt={'dikt_key': 'dikt_value'},
                             affected_items=[{'id': '001'}])
        else:
            super().__init__()

    def __getitem__(self, key):
        return self.render()[key]
