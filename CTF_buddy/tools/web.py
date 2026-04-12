from strands import tool


@tool
def web_inspect(url: str) -> dict:
    """
    General inspection of a web target. Always call this first on any web challenge.
    Fetches the page and returns status, headers, cookies, server info, and page content hints.

    Args:
        url: The URL to inspect (include http:// or https://)

    Returns:
        Full overview: status, headers, cookies, interesting content, and recommended next steps
    """
    import requests
    import re

    result = {
        "url": url,
        "status_code": None,
        "server": None,
        "headers": {},
        "cookies": {},
        "interesting_headers": [],
        "page_title": None,
        "content_hints": [],
        "forms_found": [],
        "comments_found": [],
        "recommended_next_steps": [],
        "error": None,
    }

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False,
                            headers={"User-Agent": "Mozilla/5.0"})

        result["status_code"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["server"] = resp.headers.get("Server", "not disclosed")

        # Cookies
        for name, value in resp.cookies.items():
            result["cookies"][name] = value

        # Interesting headers
        interesting = ["X-Flag", "X-CTF", "X-Secret", "X-Debug", "X-Powered-By",
                       "X-Auth", "Authorization", "WWW-Authenticate", "Set-Cookie"]
        for h in interesting:
            if h.lower() in {k.lower() for k in resp.headers}:
                result["interesting_headers"].append(f"{h}: {resp.headers.get(h)}")

        body = resp.text

        # Page title
        title = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if title:
            result["page_title"] = title.group(1).strip()

        # HTML comments
        comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        result["comments_found"] = [c.strip() for c in comments if c.strip()]

        # Forms
        forms = re.findall(r"<form[^>]*>(.*?)</form>", body, re.IGNORECASE | re.DOTALL)
        for form in forms:
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form, re.IGNORECASE)
            action = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
            result["forms_found"].append({
                "action": action.group(1) if action else "self",
                "inputs": inputs,
            })

        # Content hints
        if "flag{" in body.lower() or "ctf{" in body.lower():
            result["content_hints"].append("FLAG PATTERN FOUND IN PAGE BODY")
        if "password" in body.lower():
            result["content_hints"].append("word 'password' in page body")
        if "admin" in body.lower():
            result["content_hints"].append("word 'admin' in page body")
        if "sql" in body.lower() or "mysql" in body.lower():
            result["content_hints"].append("SQL references in page body")
        if "error" in body.lower() or "exception" in body.lower():
            result["content_hints"].append("error/exception text in page body")

        # Recommended next steps
        if result["forms_found"]:
            result["recommended_next_steps"].append("forms found — try web_fuzz_form() for SQLi/XSS")
        if result["cookies"]:
            result["recommended_next_steps"].append("cookies present — try web_inspect_cookie() to analyse")
        if result["comments_found"]:
            result["recommended_next_steps"].append("HTML comments found — inspect for credentials or hints")
        if resp.headers.get("WWW-Authenticate"):
            result["recommended_next_steps"].append("auth required — check auth type in WWW-Authenticate header")
        result["recommended_next_steps"].append("try web_get_paths() to discover hidden directories/files")

    except requests.exceptions.SSLError:
        result["error"] = "SSL error — try with http:// instead"
    except requests.exceptions.ConnectionError:
        result["error"] = "connection refused — target may be down or wrong port"
    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def web_get_paths(url: str, wordlist: str = "common") -> dict:
    """
    Discover hidden paths and directories on a web target.
    Use after web_inspect() to find admin panels, config files, backups, etc.

    Args:
        url: Base URL to probe (e.g. http://10.0.0.1)
        wordlist: 'common' for built-in list, or a path to a custom wordlist file

    Returns:
        Found paths with status codes
    """
    import requests

    COMMON_PATHS = [
        "admin", "login", "dashboard", "panel", "config", "backup",
        "robots.txt", ".htaccess", ".git/HEAD", "index.php", "index.html",
        "api", "api/v1", "api/v2", "flag", "secret", "hidden", "upload",
        "uploads", "files", "static", "js", "css", "images", "img",
        "wp-admin", "wp-login.php", "phpmyadmin", "shell.php", "cmd.php",
        ".env", "web.config", "sitemap.xml", "crossdomain.xml",
        "info.php", "phpinfo.php", "test.php", "debug.php",
    ]

    result = {"base_url": url, "found": [], "error": None}

    try:
        paths = COMMON_PATHS
        if wordlist != "common":
            with open(wordlist) as f:
                paths = [line.strip() for line in f if line.strip()]

        base = url.rstrip("/")
        for path in paths:
            try:
                resp = requests.get(f"{base}/{path}", timeout=5, allow_redirects=False,
                                    verify=False, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code not in (404, 400):
                    result["found"].append({
                        "path": f"/{path}",
                        "status": resp.status_code,
                        "size": len(resp.content),
                    })
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def web_fuzz_param(url: str, param: str, payload_type: str = "sqli") -> dict:
    """
    Test a specific URL parameter with common CTF payloads.
    Use after web_inspect() identifies a form or parameter.

    Args:
        url: Full URL with the parameter (e.g. http://site.com/page?id=1)
        param: The parameter name to fuzz (e.g. 'id', 'username')
        payload_type: 'sqli' for SQL injection, 'xss' for cross-site scripting, 'lfi' for local file inclusion

    Returns:
        Which payloads triggered interesting responses
    """
    import requests
    import re

    PAYLOADS = {
        "sqli": [
            "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
            "' OR 1=1#", "admin'--", "' UNION SELECT NULL--",
            "1' ORDER BY 1--", "1' ORDER BY 2--", "1' ORDER BY 3--",
        ],
        "xss": [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>", "<svg onload=alert(1)>",
        ],
        "lfi": [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "....//....//etc/passwd", "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
    }

    result = {
        "url": url, "param": param, "payload_type": payload_type,
        "interesting_responses": [], "error": None,
    }

    try:
        payloads = PAYLOADS.get(payload_type, PAYLOADS["sqli"])
        base_resp = requests.get(url, timeout=5, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        base_len = len(base_resp.text)

        for payload in payloads:
            try:
                resp = requests.get(url, params={param: payload}, timeout=5,
                                    verify=False, headers={"User-Agent": "Mozilla/5.0"})
                body = resp.text
                interesting = False
                reason = []

                if abs(len(body) - base_len) > 100:
                    reason.append("response length changed significantly")
                    interesting = True
                if any(err in body.lower() for err in ["sql", "mysql", "syntax error", "warning:", "fatal error"]):
                    reason.append("SQL/PHP error in response")
                    interesting = True
                if "flag{" in body.lower() or "ctf{" in body.lower():
                    reason.append("FLAG FOUND IN RESPONSE")
                    interesting = True
                if payload_type == "xss" and payload in body:
                    reason.append("payload reflected in response")
                    interesting = True
                if payload_type == "lfi" and "root:" in body:
                    reason.append("/etc/passwd content found")
                    interesting = True

                if interesting:
                    result["interesting_responses"].append({
                        "payload": payload,
                        "status": resp.status_code,
                        "reasons": reason,
                        "response_preview": body[:300],
                    })
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def web_inspect_cookie(cookie_value: str) -> dict:
    """
    Analyse a cookie value for encoding, signing, or known formats (JWT, Flask session, etc.)
    Use after web_inspect() finds cookies.

    Args:
        cookie_value: The raw cookie value to analyse

    Returns:
        Detected format, decoded content, and security observations
    """
    import base64
    import json

    result = {
        "input": cookie_value,
        "format": "unknown",
        "decoded": None,
        "observations": [],
        "error": None,
    }

    try:
        # JWT detection (three base64 parts separated by dots)
        parts = cookie_value.split(".")
        if len(parts) == 3:
            result["format"] = "JWT"
            try:
                header = json.loads(base64.b64decode(parts[0] + "==").decode())
                payload = json.loads(base64.b64decode(parts[1] + "==").decode())
                result["decoded"] = {"header": header, "payload": payload, "signature": parts[2]}
                result["observations"].append(f"algorithm: {header.get('alg', 'unknown')}")
                if header.get("alg") == "none":
                    result["observations"].append("CRITICAL: alg=none — try forging token without signature")
                if header.get("alg", "").startswith("HS"):
                    result["observations"].append("HMAC-signed — try jwt_tool or hashcat to crack secret")
            except Exception:
                result["observations"].append("JWT structure detected but could not decode")
            return result

        # Flask session cookie (starts with dot, base64 encoded)
        if cookie_value.startswith("."):
            result["format"] = "Flask session"
            try:
                data_part = cookie_value.split(".")[1]
                import zlib
                raw = base64.urlsafe_b64decode(data_part + "==")
                decoded = zlib.decompress(raw).decode()
                result["decoded"] = json.loads(decoded)
                result["observations"].append("Flask session — try flask-unsign to forge with known secret")
            except Exception:
                result["observations"].append("Flask session format detected — use flask-unsign to crack")
            return result

        # Plain base64
        try:
            raw = base64.b64decode(cookie_value + "==").decode("utf-8")
            result["format"] = "base64"
            result["decoded"] = raw
            result["observations"].append("base64 encoded — decoded value may contain role or user info")
            return result
        except Exception:
            pass

        # Plain text / numeric
        result["format"] = "plaintext"
        result["decoded"] = cookie_value
        if cookie_value.isdigit():
            result["observations"].append("numeric ID — try incrementing/decrementing for IDOR")
        if "admin" in cookie_value.lower() or "user" in cookie_value.lower():
            result["observations"].append("role hint in cookie — try changing value to 'admin'")

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def web_solve_image_captcha(url: str, form_field: str = None) -> dict:
    """
    Solve an image-based CAPTCHA challenge on a web page.

    General use: call with just the URL — auto-detects the captcha image,
    OCRs the text locally using easyocr (no external API), finds the form field, and submits.

    Specific use: provide form_field if auto-detection picks the wrong input.

    Workflow (what a human would do):
      1. GET the page
      2. Find the captcha image (inline base64 or linked src)
      3. Read the text using local OCR
      4. POST the answer using the same session cookie

    Args:
        url: The challenge URL
        form_field: Name of the form input field to submit the answer (auto-detected if not given)

    Returns:
        OCR result, submitted value, server response, and flag if found
    """
    import re
    import base64
    import io
    import requests
    from PIL import Image, ImageFilter, ImageEnhance

    result = {
        "url": url,
        "captcha_text_read": None,
        "submitted_value": None,
        "server_response": None,
        "flag_found": None,
        "error": None,
    }

    try:
        try:
            import easyocr
        except ImportError:
            result["error"] = "easyocr not installed — run: pip install easyocr"
            return result

        reader = easyocr.Reader(["en"], gpu=False, verbose=False)

        # GET page — keep session cookie
        session = requests.Session()
        r = session.get(url, timeout=10)

        # Find captcha image — inline base64 first, then linked src
        b64_match = re.search(r'data:image/(?:png|jpeg|gif);base64,([^"\'>\s]+)', r.text)
        img_src_match = re.search(r'<img[^>]+src=["\']([^"\']+)["\']', r.text, re.IGNORECASE)

        raw_image = None
        if b64_match:
            raw_image = base64.b64decode(b64_match.group(1))
        elif img_src_match:
            img_url = img_src_match.group(1)
            if not img_url.startswith("http"):
                from urllib.parse import urljoin
                img_url = urljoin(url, img_url)
            raw_image = session.get(img_url, timeout=10).content

        if not raw_image:
            result["error"] = "no captcha image found on the page"
            return result

        # Preprocess for better OCR accuracy
        img = Image.open(io.BytesIO(raw_image)).convert("L")
        img = ImageEnhance.Contrast(img).enhance(2.5)
        img = img.filter(ImageFilter.SHARPEN)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)

        ocr_results = reader.readtext(
            buf.read(), detail=0,
            allowlist="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        )
        captcha_text = "".join(ocr_results).strip()
        result["captcha_text_read"] = captcha_text

        if not captcha_text:
            result["error"] = "OCR returned empty — image may need different preprocessing"
            return result

        # Auto-detect form field name
        if not form_field:
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', r.text, re.IGNORECASE)
            text_inputs = [n for n in inputs if not any(s in n.lower() for s in ["submit", "button", "csrf"])]
            form_field = text_inputs[0] if text_inputs else "captcha"

        # POST answer with same session
        resp = session.post(url, data={form_field: captcha_text}, timeout=10)
        clean = re.sub(r"<[^>]+>", " ", resp.text)
        result["server_response"] = re.sub(r"\s+", " ", clean).strip()[:600]

        flag_match = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", resp.text)
        if flag_match:
            result["flag_found"] = flag_match.group(0)

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def web_fetch_challenge(url: str) -> dict:
    """
    Fetch a web challenge page and return its clean text and raw HTML for analysis.
    Call this FIRST on any programmation/math challenge to see exactly what the page contains,
    then decide which solver to call based on what you read.

    Args:
        url: The challenge URL

    Returns:
        clean_text: HTML tags stripped — read this to understand the challenge
        raw_html: Full raw HTML — use this to understand the page structure for parsing
        links: All URLs found on the page (submission endpoints, resources)
        forms: Any forms and their fields
        cookies: Session cookies set by the server
    """
    import re
    import requests

    result = {
        "url": url,
        "clean_text": None,
        "raw_html": None,
        "links": [],
        "forms": [],
        "cookies": {},
        "error": None,
    }

    try:
        session = requests.Session()
        r = session.get(url, timeout=10)
        result["cookies"] = dict(session.cookies)
        result["raw_html"] = r.text

        clean = re.sub(r"<[^>]+>", " ", r.text)
        result["clean_text"] = re.sub(r"\s+", " ", clean).strip()

        result["links"] = re.findall(r'https?://[^\s"\'<>]+', r.text)

        forms = re.findall(r"<form[^>]*>.*?</form>", r.text, re.DOTALL | re.IGNORECASE)
        for form in forms:
            inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', form, re.IGNORECASE)
            action = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
            result["forms"].append({
                "action": action.group(1) if action else "self",
                "inputs": inputs,
            })

    except Exception as e:
        result["error"] = str(e)

    return result


@tool
def web_solve_sequence(
    url: str,
    u0: int,
    target_n: int,
    formula_expr: str,
    submit_url_template: str,
    recurrence_type: str = "iterative",
) -> dict:
    """
    Solve a math sequence challenge and submit the answer.

    Workflow:
      1. Call web_fetch_challenge(url) to read the page
      2. Read the clean_text to understand the formula, U0, and target N
      3. Call this tool with the parsed values — YOU write formula_expr based on what you read

    Args:
        url: The challenge URL (used for session cookies)
        u0: The initial value U(0) parsed from the page
        target_n: The target index N to compute U(N)
        formula_expr: Python expression for one step — use 'u' for current value, 'n' for current index.
                      Examples:
                        'u + 7*n - 22'              (linear: U(n+1) = U(n) + 7n - 22)
                        '2*u + 5'                   (geometric: U(n+1) = 2*U(n) + 5)
                        'u + prev'                  (fibonacci-like, needs prev)
                        'u * n % 1000000007'        (modular)
        submit_url_template: URL to submit to, with {answer} placeholder.
                      Example: 'http://challenge01.root-me.org/programmation/ch1/ep1_v.php?result={answer}'
        recurrence_type: 'iterative' (default, works for all), 'linear_closed_form' (fastest for U(n+1)=U(n)+B*n+A)

    Returns:
        computed_answer, server_response, flag_found
    """
    import re
    import requests

    result = {
        "u0": u0,
        "target_n": target_n,
        "formula_expr": formula_expr,
        "recurrence_type": recurrence_type,
        "computed_answer": None,
        "server_response": None,
        "flag_found": None,
        "error": None,
    }

    try:
        # ── Compute answer ─────────────────────────────────────────────────
        if recurrence_type == "linear_closed_form":
            # U(n+1) = U(n) + B*n + A  →  U(N) = U(0) + A*N + B*N*(N-1)/2
            # Agent must pass formula_expr as 'A={a},B={b}' for this mode
            parts = dict(p.split("=") for p in formula_expr.split(","))
            A, B = int(parts["A"]), int(parts["B"])
            answer = u0 + A * target_n + B * target_n * (target_n - 1) // 2

        elif "prev" in formula_expr:
            # Fibonacci-like: needs two previous values
            prev, u = u0, u0
            for n in range(1, target_n + 1):
                prev, u = u, eval(formula_expr, {"u": u, "prev": prev, "n": n})
            answer = u

        else:
            # General iterative: works for any single-step recurrence
            u = u0
            for n in range(target_n):
                u = eval(formula_expr, {"u": u, "n": n, "__builtins__": {}})
            answer = u

        result["computed_answer"] = answer

        # ── Submit ─────────────────────────────────────────────────────────
        session = requests.Session()
        session.get(url, timeout=5)  # establish session cookie

        submit_url = submit_url_template.format(answer=answer)
        resp = session.get(submit_url, timeout=10)

        clean = re.sub(r"<[^>]+>", " ", resp.text)
        result["server_response"] = re.sub(r"\s+", " ", clean).strip()[:400]

        # Detect flag — standard format or plain text
        flag_match = re.search(r"[A-Za-z0-9_]+\{[^}]+\}", resp.text)
        if flag_match:
            result["flag_found"] = flag_match.group(0)
        elif "congratz" in resp.text.lower() or "flag is" in resp.text.lower():
            plain = re.search(r"flag is\s*[:\-]?\s*([A-Za-z0-9@!_\-]+)", resp.text, re.IGNORECASE)
            if plain:
                result["flag_found"] = plain.group(1)

    except Exception as e:
        result["error"] = str(e)

    return result
