from ppscan import payloads

def test_get_object_payloads():
    p = payloads.get_object_payloads()
    assert len(p) > 0
    assert "__proto__.ppfuzz" in p

def test_get_pointer_payloads():
    p = payloads.get_pointer_payloads()
    assert len(p) > 0
    assert "constructor.prototype.ppfuzz" in p

def test_get_payloads():
    all_p = payloads.get_payloads()
    obj_p = payloads.get_object_payloads()
    ptr_p = payloads.get_pointer_payloads()
    assert len(all_p) == len(obj_p) + len(ptr_p)
