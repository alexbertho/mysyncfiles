"""Use the administrator's configured origin in published documentation."""

import os


def on_page_markdown(markdown, **_kwargs):
    origin = os.environ.get("MYSYNC_PUBLIC_URL")
    if origin:
        return markdown.replace("https://sync.example.org", origin)
    return markdown
