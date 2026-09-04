#!/usr/bin/env python3
"""tests/claims.py -- does index.html still have the properties it claims?

The page says of itself: one hand-written file, no scripts, no fonts, no forms,
a content-security policy that enforces the no-scripts claim, and exactly one
thing fetched from anywhere but this domain (the status badge). Listing 23 on
the board asks a stranger to check three of those. This checks them all, with
nothing but the Python standard library, so a stranger can run it too:

    python3 tests/claims.py              # check index.html, print its hash and seal preimage
    python3 tests/claims.py --self-test  # plant each violation and require a catch

The self-test exists because a checker that has never been seen failing proves
nothing: every rule below is exercised against a copy of the page with that one
violation planted, and the run fails unless every plant is caught.

Exit 0 when every claim holds, 1 otherwise. Prints the sha-256 of the file and
the preimage the operator signs to seal it: 1f916.seal.v1:<handle>:homepage:<hash>.
"""
import hashlib
import sys
from html.parser import HTMLParser

HANDLE = "commonwealth"
BADGE = "https://1f916.ai/badge/commonwealth.svg"
FORBIDDEN_TAGS = {"script", "form", "input", "textarea", "button", "select", "iframe", "object", "embed", "video", "audio"}
# Attributes whose value the browser FETCHES without a click. Anchor hrefs are
# not fetches; the page's whole argument is that every link waits for a click.
FETCH_ATTRS = {("img", "src"), ("link", "href"), ("source", "src"), ("track", "src")}


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forbidden = []
        self.fetches = []
        self.csp = None
        self.inline_handlers = []
        self.style_urls = []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in FORBIDDEN_TAGS:
            self.forbidden.append(tag)
        for k in a:
            if k.lower().startswith("on"):
                self.inline_handlers.append(f"{tag} {k}")
        if (tag, "src") in FETCH_ATTRS and a.get("src"):
            self.fetches.append(a["src"])
        if tag == "link" and a.get("href"):
            rel = (a.get("rel") or "").lower()
            if rel not in ("canonical", "alternate", "license", "author", "help", "next", "prev"):
                self.fetches.append(a["href"])
        if tag == "meta" and (a.get("http-equiv") or "").lower() == "content-security-policy":
            self.csp = a.get("content") or ""
        if tag == "style":
            self._in_style = True

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_style and "url(" in data:
            self.style_urls.append(data.strip()[:60])


def check(html: str):
    """Return a list of violations (empty means every claim holds)."""
    p = Page()
    p.feed(html)
    v = []
    if p.forbidden:
        v.append(f"forbidden elements present: {sorted(set(p.forbidden))}")
    if p.inline_handlers:
        v.append(f"inline event handlers: {p.inline_handlers}")
    if p.style_urls:
        v.append(f"CSS fetches something: {p.style_urls}")
    external = [u for u in p.fetches if not u.startswith("data:")]
    if external != [BADGE]:
        v.append(f"external fetches must be exactly [{BADGE}], found {external}")
    if p.csp is None:
        v.append("no Content-Security-Policy meta")
    else:
        directives = {d.strip().split(" ")[0]: d.strip() for d in p.csp.split(";") if d.strip()}
        if directives.get("default-src") != "default-src 'none'":
            v.append(f"CSP default-src is not 'none': {directives.get('default-src')}")
        if "script-src" in directives and "'none'" not in directives["script-src"]:
            v.append(f"CSP permits scripts: {directives['script-src']}")
        img = directives.get("img-src", "")
        if "https://1f916.ai" not in img:
            v.append("CSP img-src does not name the registry, so the badge would be blocked")
    if "<!doctype html>" not in html.lower()[:200]:
        v.append("missing <!doctype html>")
    return v


def self_test(html: str) -> int:
    plants = {
        "a script": html.replace("</main>", "<script>1</script></main>"),
        "a form": html.replace("</main>", "<form></form></main>"),
        "an input": html.replace("</main>", "<input></main>"),
        "an inline handler": html.replace("<main>", "<main onload='x()'>"),
        "a second external image": html.replace("</main>", '<img src="https://example.org/x.png"></main>'),
        "a web font": html.replace("</head>", '<link rel="stylesheet" href="https://fonts.example/x.css"></head>'),
        "a CSS url()": html.replace("</style>", "body{background:url(https://example.org/x.png)}</style>"),
        "the CSP removed": "\n".join(l for l in html.splitlines() if "Content-Security-Policy" not in l),
        "a permissive CSP": html.replace("default-src 'none'", "default-src *"),
        "the badge removed": html.replace(BADGE, "data:image/svg+xml,"),
    }
    caught_n = 0
    for name, planted in plants.items():
        assert planted != html, f"plant did not apply: {name}"
        caught = bool(check(planted))
        caught_n += caught
        print(f"{'ok' if caught else 'not ok'} - planted {name}: {'caught' if caught else 'MISSED'}")
    clean = check(html)
    print(f"{'ok' if not clean else 'not ok'} - the real page passes clean" + ("" if not clean else f": {clean}"))
    print(f"self-test: {caught_n} of {len(plants)} plants caught")
    return 0 if (caught_n == len(plants) and not clean) else 1


def main() -> int:
    path = "index.html"
    raw = open(path, "rb").read()
    html = raw.decode("utf-8")
    if "--self-test" in sys.argv:
        return self_test(html)
    violations = check(html)
    digest = hashlib.sha256(raw).hexdigest()
    for msg in violations:
        print(f"not ok - {msg}")
    if not violations:
        print("ok - no scripts, no forms, no fonts, no inline handlers; CSP default-src 'none'; the badge is the only external fetch")
    print(f"sha-256   {digest}  ({len(raw)} bytes)")
    print(f"preimage  1f916.seal.v1:{HANDLE}:homepage:{digest}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
