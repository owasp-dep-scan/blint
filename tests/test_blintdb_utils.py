import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from requests.exceptions import ConnectionError as RequestConnectionError

from blint.lib.utils import blintdb_setup

def test_blintdb_setup_skip_when_use_blintdb_not_set(monkeypatch):
    
    # Arrange
    monkeypatch.delenv("USE_BLINTDB", raising=False)
    args = MagicMock(use_blintdb=False)
    
    # Act
    with patch('blint.lib.utils.LOG') as mock_log:
        blintdb_setup(args)
    
    # Assert
    mock_log.debug.assert_called_once()

@pytest.mark.parametrize("use_blintdb_env,use_blintdb_arg", [
    ("true", False),
    (None, True),
    ("1", False)
])
def test_blintdb_setup_download_success(use_blintdb_env, use_blintdb_arg, monkeypatch, tmp_path):
    
    # Arrange
    if use_blintdb_env:
        monkeypatch.setenv("USE_BLINTDB", use_blintdb_env)
    monkeypatch.setattr('blint.lib.utils.BLINTDB_HOME', str(tmp_path))
    args = MagicMock(use_blintdb=use_blintdb_arg)
    
    # Act
    with patch('oras.client.OrasClient') as mock_oras_client:
        blintdb_setup(args)
    
    # Assert
    assert os.path.exists(str(tmp_path))
    mock_oras_client.return_value.pull.assert_called_once()

def test_blintdb_setup_connection_error(monkeypatch, tmp_path):
    
    # Arrange
    monkeypatch.setenv("USE_BLINTDB", "true")
    monkeypatch.setattr('blint.lib.utils.BLINTDB_HOME', str(tmp_path))
    args = MagicMock(use_blintdb=True)
    
    # Act
    with patch('oras.client.OrasClient') as mock_oras_client, \
         patch('blint.lib.utils.LOG') as mock_log:
        mock_oras_client.return_value.pull.side_effect = RequestConnectionError()
        blintdb_setup(args)
    
    # Assert
    mock_log.error.assert_called()

def test_blintdb_setup_database_not_installed(monkeypatch, tmp_path):
    
    # Arrange
    monkeypatch.setenv("USE_BLINTDB", "true")
    monkeypatch.setattr('blint.lib.utils.BLINTDB_HOME', str(tmp_path))
    monkeypatch.setattr('blint.lib.utils.BLINTDB_LOC', str(tmp_path / 'nonexistent'))
    args = MagicMock(use_blintdb=True)
    
    # Act
    with patch('oras.client.OrasClient'):
        blintdb_setup(args)
    
    # Assert
    assert os.getenv("USE_BLINTDB") == "false"
