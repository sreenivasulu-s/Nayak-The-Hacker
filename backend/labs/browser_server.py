from __future__ import annotations

import os
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
from playwright.async_api import async_playwright

ACADEMY_SUFFIX = ".web-security-academy.net"
app = FastAPI(title="Nayak Browser Gateway")

_playwright = None
_browser = None
_context = None
_page = None


class NavigateRequest(BaseModel):
    url: HttpUrl


def allowed(url: str) -> bool:
    p = urlparse(url)
    return (
        p.scheme == "https"
        and bool(p.hostname)
        and p.hostname.lower().endswith(ACADEMY_SUFFIX)
    )


async def get_page():
    global _playwright, _browser, _context, _page

    if _page is None:
        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(headless=True)
        _context = await _browser.new_context()
        _page = await _context.new_page()

    return _page


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}



class LoginRequest(BaseModel):
    url: HttpUrl
    username: str
    password: str


@app.post("/login")
async def login(request: LoginRequest) -> dict:
    target = str(request.url)

    if not allowed(target):
        raise HTTPException(
            status_code=403,
            detail="Only PortSwigger Academy HTTPS lab hosts are allowed",
        )

    timeout_ms = int(os.getenv("BROWSER_TIMEOUT_MS", "30000"))
    page = await get_page()

    await page.goto(
        target,
        wait_until="domcontentloaded",
        timeout=timeout_ms,
    )

    form = page.locator("form").first
    if await form.count() == 0:
        raise HTTPException(status_code=400, detail="No login form found")

    username = form.locator('input[name="username"]')
    password = form.locator('input[name="password"]')

    if await username.count() == 0 or await password.count() == 0:
        raise HTTPException(status_code=400, detail="Login fields not found")

    await username.fill(request.username)
    await password.fill(request.password)

    await form.locator('button[type="submit"], input[type="submit"]').first.click()

    await page.wait_for_load_state(
        "domcontentloaded",
        timeout=timeout_ms,
    )

    return {
        "url": page.url,
        "status": 200,
        "title": await page.title(),
        "body_excerpt": (await page.locator("body").inner_text())[:4000],
    }


@app.post("/navigate")
async def navigate(request: NavigateRequest) -> dict:
    target = str(request.url)

    if not allowed(target):
        raise HTTPException(
            status_code=403,
            detail="Only PortSwigger Academy HTTPS lab hosts are allowed",
        )

    timeout_ms = int(os.getenv("BROWSER_TIMEOUT_MS", "30000"))
    page = await get_page()

    response = await page.goto(
        target,
        wait_until="domcontentloaded",
        timeout=timeout_ms,
    )

    forms = await page.locator("form").evaluate_all("""
        forms => forms.map(form => ({
            action: form.action,
            method: (form.method || "GET").toUpperCase(),
            inputs: Array.from(form.elements).map(el => ({
                name: el.name || "",
                type: el.type || "",
                value: el.value || ""
            }))
        }))
    """)

    links = await page.locator("a").evaluate_all("""
        links => links.slice(0, 50).map(a => ({
            text: (a.innerText || "").trim(),
            href: a.href
        }))
    """)

    return {
        "url": page.url,
        "status": response.status if response else None,
        "title": await page.title(),
        "body_excerpt": (await page.locator("body").inner_text())[:4000],
        "forms": forms,
        "links": links,
    }
