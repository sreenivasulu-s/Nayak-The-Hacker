from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from playwright.async_api import async_playwright

ACADEMY_SUFFIX = ".web-security-academy.net"
app = FastAPI(title="Nayak Browser Gateway")


class NavigateRequest(BaseModel):
    url: HttpUrl


def allowed(url: str) -> bool:
    p = urlparse(url)
    return p.scheme == "https" and bool(p.hostname) and p.hostname.lower().endswith(ACADEMY_SUFFIX)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/navigate")
async def navigate(request: NavigateRequest) -> dict:
    target = str(request.url)
    if not allowed(target):
        raise HTTPException(status_code=403, detail="Only PortSwigger Academy HTTPS lab hosts are allowed")

    timeout_ms = int(os.getenv("BROWSER_TIMEOUT_MS", "30000"))
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            response = await page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
            return {
                "url": page.url,
                "status": response.status if response else None,
                "title": await page.title(),
                "body_excerpt": (await page.locator("body").inner_text())[:4000],
            }
        finally:
            await browser.close()
