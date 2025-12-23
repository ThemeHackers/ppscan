import pytest
from unittest.mock import AsyncMock, patch
from ppscan.scanner import Scanner

@pytest.mark.asyncio
async def test_scanner_init():
    scanner = Scanner(concurrency=5, timeout=10)
    assert scanner.concurrency == 5
    assert scanner.timeout == 10
    assert scanner.semaphore._value == 5

@pytest.mark.asyncio
async def test_scan_empty():
    scanner = Scanner()
    # Mock async_playwright to prevent actual browser launch
    with patch("ppscan.scanner.async_playwright") as mock_playwright:
        mock_context_manager = AsyncMock()
        mock_playwright.return_value = mock_context_manager
        
        mock_browser = AsyncMock()
        mock_context_manager.__aenter__.return_value = mock_browser
        mock_browser.chromium.launch.return_value = AsyncMock()
        
        results = await scanner.scan([])
        assert results == []

@pytest.mark.asyncio
async def test_clean_url():
    scanner = Scanner()
    # Should remove payload params
    url = "http://example.com/?q=1&__proto__.ppfuzz=reserved"
    clean = scanner._clean_url(url)
    assert "__proto__.ppfuzz" not in clean
    assert "q=1" in clean
    
    # Should keep other params
    url2 = "http://example.com/?a=b&constructor.prototype.ppfuzz=reserved"
    clean2 = scanner._clean_url(url2)
    assert "constructor" not in clean2
    assert "a=b" in clean2
