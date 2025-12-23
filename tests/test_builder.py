from ppscan import builder

def test_build_queries_simple():
    url = "http://example.com/?q=test"
    fuzzed = builder.build_queries(url)
    assert len(fuzzed) > 0
    assert any("__proto__" in f for f in fuzzed)

def test_build_queries_multiple_params():
    url = "http://example.com/?a=1&b=2"
    fuzzed = builder.build_queries(url)
    assert any("__proto__" in f for f in fuzzed)
    assert any("ordered" in f or "reserved" in f for f in fuzzed)
    
    
    sample = fuzzed[0]
    assert "reserved" in sample

def test_build_queries_no_query():
    url = "http://example.com/"
    fuzzed = builder.build_queries(url)
    assert len(fuzzed) > 0
    assert "reserved" in fuzzed[0]
