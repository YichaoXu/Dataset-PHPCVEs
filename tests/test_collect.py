"""
Tests for the collect command module.
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.commands.collect import collect
from src.core.processor import CVEProcessor
from src.utils.github import GitHubAPI

@pytest.fixture
def setup_dirs(tmp_path):
    """Set up temporary directories for testing."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return {"output_dir": output_dir}

@patch("src.core.processor.CVEProcessor.process_year")
@patch("src.core.processor.CVEProcessor.save_records")
@patch("src.core.processor.CVEProcessor.combine_yearly_data")
def test_collect_single_year(mock_combine, mock_save, mock_process, setup_dirs):
    """Test collecting CVEs for a single year."""
    # Mock process_year to return some records
    mock_records = [{"cve_id": "CVE-2022-1234", "cwe_id": "CWE-79"}]
    mock_process.return_value = mock_records
    
    # Call collect command
    result = collect(
        output_dir=setup_dirs["output_dir"],
        year=2022,
        cache=True,
        force=False,
        limit=None,
        verbose=False
    )
    
    # Verify process_year was called with correct arguments
    mock_process.assert_called_once_with(2022, limit=None, force=False)
    
    # Verify save_records was called
    mock_save.assert_called_once()
    
    # Verify combine_yearly_data was called
    mock_combine.assert_called_once()
    
    # Verify result
    assert result == 1  # One record

@patch("src.core.processor.CVEProcessor.process_year")
def test_collect_multiple_years(mock_process, setup_dirs):
    """Test collecting CVEs for multiple years."""
    # Mock process_year to return some records
    mock_process.return_value = [{"cve_id": f"CVE-{year}-1234", "cwe_id": "CWE-79"} for year in range(2020, 2023)]
    
    # Call collect command
    result = collect(
        output_dir=setup_dirs["output_dir"],
        years=[2020, 2021, 2022],
        cache=True,
        force=False,
        limit=None,
        verbose=False
    )
    
    # Verify process_year was called for each year
    assert mock_process.call_count == 3
    
    # Verify result
    assert result == 9  # 3 records per year, 3 years 