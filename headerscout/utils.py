from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("URL must not be empty.")

    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL. Example: https://example.com")

    return url


def header_get(headers: dict, name: str):
    """
    Case-insensitive header lookup.
    """
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None
