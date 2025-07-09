HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (R-AScan/1.0)",
    "Authorization": "Bearer <token>",
    "Cookie": "Cookie"
}

DEFAULT_TIMEOUT = 5
COMMON_ENDPOINTS = "rascan/resources/common_endpoints.txt"
DIRECTORIES = "rascan/resources/directories.txt"
SENSITIVE_FILES = "rascan/resources/sensitive_files.txt"
HTTP_SMUGGLING_PAYLOAD = "rascan/resources/http_smuggling_payloads.json"

PARAMS = {
    "SQLi": ["id", "page", "dir", "search", "category", "file", "class", "url", "news", "item", "menu", "lang", "name", "ref", "title", "view", "topic", "thread", "type", "date", "form", "join", "main", "nav", "region"],
    "LFI": ["cat", "dir", "action", "board", "date", "detail", "file", "download", "path", "folder", "prefix", "include", "page", "inc", "locate", "show", "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf"],
    "OpenRedirect": ["next", "url", "target", "rurl", "dest", "destination", "redir", "redirect_uri", "redirect_url", "redirect", "image_url", "go", "return", "returnTo", "return_to", "checkout_url", "continue", "return_path"],
    "RCE": ["cmd", "exec", "command", "execute", "ping", "query", "jump", "code", "reg", "do", "func", "arg", "option", "load", "process", "step", "read", "function", "req", "feature", "exe", "module", "payload", "run", "print"],
    "SSRF": ["dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir"],
    "XSS": ["q", "s", "search", "id", "lang", "keyword", "query", "page", "keywords", "year", "view", "email", "type", "name", "p", "month", "image", "list_type", "url", "terms", "categoryid", "key", "login", "begindate", "enddate"]
}
