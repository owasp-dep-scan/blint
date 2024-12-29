import pytest
import os
import sqlite3
import concurrent.futures
from unittest.mock import patch, MagicMock, Mock
from blint.db import return_batch_binaries_detected, get_bid_using_ename_batch, get_bname, detect_binaries_utilized

# BLINTDB_LOC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_blintdb.db")
# os.environ["BLINTDB_LOC"] = BLINTDB_LOC

@pytest.mark.parametrize("symbols_list, mock_output, expected_result", [
    # Happy path: single symbol with single binary
    (
        ["symbol1"], 
        [("eid1", "bid1")], 
        {"binary1": 1.0}
    ),
    # Happy path: multiple symbols with multiple binaries
    (
        ["symbol1", "symbol2"], 
        [("eid1", "bid1"), ("eid2", "bid2,bid3")], 
        {"binary1": 1.0, "binary2": 0.5, "binary3": 0.5}
    ),
    # Edge case: empty symbols list
    (
        [], 
        [], 
        {}
    )
])
def test_return_batch_binaries_detected(symbols_list, mock_output, expected_result):
    
    # Arrange
    with patch('blint.db.get_bid_using_ename_batch', return_value=mock_output), \
         patch('blint.db.get_bname', side_effect=lambda bid: f"binary{bid[-1]}"):
        
        # Act
        result = return_batch_binaries_detected(symbols_list)
        
        # Assert
        assert result == expected_result

@pytest.mark.parametrize("symbols_list", [
    # Error case: None input
    None,
    # Error case: Non-list input
    "not a list"
])
def test_return_batch_binaries_detected_invalid_input(symbols_list):
    
    # Act & Assert
    with pytest.raises((TypeError, AttributeError)):
        return_batch_binaries_detected(symbols_list)



@pytest.mark.parametrize("test_id, batch_export_name, mock_cursor_execute, expected_result", [
    # Happy path: single export name with single binary
    ("single_export_single_binary", 
     ["export1"], 
     [(1, "binary1")], 
     [(1, "binary1")]),
    
    # Happy path: multiple export names with multiple binaries
    ("multiple_exports_multiple_binaries", 
     ["export1", "export2"], 
     [(1, "binary1,binary2"), (2, "binary3,binary4")], 
     [(1, "binary1,binary2"), (2, "binary3,binary4")]),
    
    # Edge case: empty export names list
    ("empty_export_names", 
     [], 
     [], 
     []),
    
    # Edge case: single export name with multiple binaries
    ("single_export_multiple_binaries", 
     ["export1"], 
     [(1, "binary1,binary2,binary3")], 
     [(1, "binary1,binary2,binary3")])
])
def test_get_bid_using_ename_batch(test_id, batch_export_name, mock_cursor_execute, expected_result):
    with patch.dict(os.environ, {"BLINTDB_LOC": "/mock/db/path"}), \
         patch('sqlite3.connect') as mock_connect:

        mock_connection = MagicMock(currentarg="mock_connection")
        mock_connect.return_value = mock_connection
        
        mock_cursor = MagicMock(currentarg="mock_cursor")
        mock_cursor.fetchall.return_value = mock_cursor_execute
        mock_connection.cursor.return_value = mock_cursor

        result = get_bid_using_ename_batch(batch_export_name)
        assert result == expected_result

@pytest.mark.parametrize("test_id, batch_export_name", [
    # Error case: None input
    ("none_input", None),
    
    # Error case: Non-list input
    ("non_list_input", "not a list")
])
def test_get_bid_using_ename_batch_invalid_input(test_id, batch_export_name):
    
    # Act & Assert
    with pytest.raises((TypeError, AttributeError)):
        get_bid_using_ename_batch(batch_export_name)

def test_get_bid_using_ename_batch_db_error():
    
    # Arrange
    with patch.dict(os.environ, {"BLINTDB_LOC": "/mock/db/path"}), \
         patch('sqlite3.connect', side_effect=sqlite3.Error):
        
        # Act & Assert
        with pytest.raises(sqlite3.Error):
            get_bid_using_ename_batch(["export1"])


@pytest.mark.parametrize("test_id, bid, mock_cursor_execute, expected_result", [
    # Happy path: existing binary ID
    ("existing_binary_id", 
     1, 
     [("binary1",)], 
     "binary1"),
    
    # Edge case: non-existent binary ID
    ("non_existent_binary_id", 
     999, 
     [], 
     None),
    
    # Edge case: zero binary ID
    ("zero_binary_id", 
     0, 
     [], 
     None)
])
def test_get_bname(test_id, bid, mock_cursor_execute, expected_result):
    
    # Arrange
    with patch.dict(os.environ, {"BLINTDB_LOC": "/mock/db/path"}), \
         patch('sqlite3.connect') as mock_connect:
        
        mock_connection = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_connection
        mock_connection.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = mock_cursor_execute
        
        # Act
        result = get_bname(bid)
        
        # Assert
        assert result == expected_result
        mock_cursor.execute.assert_called_once_with("SELECT bname from Binaries where bid=?", (bid,))

@pytest.mark.parametrize("test_id, bid", [
    # Error case: None input
    ("none_input", None),
    
    # Error case: non-integer input
    ("non_integer_input", "not an integer")
])
def test_get_bname_invalid_input(test_id, bid):
    
    # Act & Assert
    with pytest.raises((TypeError, AttributeError)):
        get_bname(bid)

def test_get_bname_db_error():
    
    # Arrange
    with patch.dict(os.environ, {"BLINTDB_LOC": "/mock/db/path"}), \
         patch('sqlite3.connect', side_effect=sqlite3.Error):
        
        # Act & Assert
        with pytest.raises(sqlite3.Error):
            get_bname(1)

import pytest
from unittest.mock import patch, MagicMock
import concurrent.futures

from blint.db import detect_binaries_utilized

@pytest.mark.parametrize("test_id, symbols_list, mock_batch_results, expected_result", [
    # Happy path: single symbol with multiple detections
    ("single_symbol_multiple_detections", 
     [{"name": "symbol1"}], 
     [{"lib1": 1.5, "lib2": 2.0}], 
     {"lib2"}),
    
    # Happy path: multiple symbols with mixed detections
    ("multiple_symbols_mixed_detections", 
     [{"name": "symbol1"}, {"name": "symbol2"}], 
     [{"lib1": 1.5}, {"lib2": 2.5, "lib3": 0.5}], 
     {"lib1", "lib2"}),
    
    # Edge case: empty symbols list
    ("empty_symbols_list", 
     [], 
     [], 
     set()),
    
    # Edge case: symbols with low scores
    ("low_score_symbols", 
     [{"name": "symbol1"}, {"name": "symbol2"}], 
     [{"lib1": 0.5}, {"lib2": 0.7}], 
     set())
])
def test_detect_binaries_utilized(test_id, symbols_list, mock_batch_results, expected_result):
    
    # Arrange
    with patch('blint.db.return_batch_binaries_detected', side_effect=mock_batch_results), \
         patch('concurrent.futures.ProcessPoolExecutor') as mock_executor:
        
        # Mock the executor and futures
        mock_future = MagicMock()
        mock_future.result.return_value = mock_batch_results
        mock_executor.submit.return_value = mock_future
        
        # Act
        result = detect_binaries_utilized(symbols_list)
        
        # Assert
        assert result == expected_result

@pytest.mark.parametrize("test_id, symbols_list", [
    # Error case: None input
    ("none_input", None),
    
    # Error case: Non-list input
    ("non_list_input", "not a list")
])
def test_detect_binaries_utilized_invalid_input(test_id, symbols_list):
    
    # Act & Assert
    with pytest.raises((TypeError, AttributeError)):
        detect_binaries_utilized(symbols_list)

def test_detect_binaries_utilized_executor_error():
    
    # Arrange
    symbols_list = [{"name": "symbol1"}]
    
    # Act & Assert
    with patch('concurrent.futures.ProcessPoolExecutor', side_effect=concurrent.futures.BrokenExecutor):
        with pytest.raises(concurrent.futures.BrokenExecutor):
            detect_binaries_utilized(symbols_list)
