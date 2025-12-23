from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from . import payloads

def build_queries(url: str) -> list[str]:
    fuzzed_urls = []
    payload_list = payloads.get_payloads()
    
    def append_param(original_url, key, value):
        parsed = urlparse(original_url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        
        if key in query:
             query[key].append(value)
        else:
             query[key] = [value]
             
        new_query = urlencode(query, doseq=True)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)

    for payload in payload_list:
        fuzzed_url = append_param(url, payload, "reserved")
        fuzzed_urls.append(fuzzed_url)

    return fuzzed_urls
