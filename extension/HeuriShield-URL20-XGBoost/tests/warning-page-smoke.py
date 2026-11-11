"""Render saved warning contexts locally and verify navigation and responsive layout."""
import argparse
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.sync_api import sync_playwright

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--screenshots-dir", type=Path)
args = parser.parse_args()
extension = Path(__file__).resolve().parents[1]

with TemporaryDirectory(prefix="hs-warning-") as profile, sync_playwright() as p:
    context = p.chromium.launch_persistent_context(
        profile, headless=True, channel="chromium",
        args=[f"--disable-extensions-except={extension}", f"--load-extension={extension}"],
        viewport={"width": 1366, "height": 1000},
    )
    worker = context.service_workers[0] if context.service_workers else context.wait_for_event("serviceworker")
    root_url = worker.url.removesuffix("src/background/service-worker.js")
    site = "https://simak.un-sultra.ac.id/login"
    analysis = {
        "url": site, "final_url": site, "verdict": "DANGEROUS",
        "model_result": {"model_family": "XGBoost", "verdict": "DANGEROUS", "ready": True},
        "decision_policy": {"source": "url_model"},
        "brand_features": {"claimed_brand_status": "unknown"},
        "dom_features": {"observed_frame_count": 1, "has_password_field": True,
                         "has_sensitive_input": False, "form_cross_domain": False,
                         "forms": [{"relevant": True, "cross_domain": False}]},
    }
    worker.evaluate("""async ({analysis, site}) => chrome.storage.local.set({
        heurishieldEnabled:false,
        heurishieldBlacklist:['simak.un-sultra.ac.id'],
        warningContexts:{'ui-test':{originalUrl:site,analysis,verdict:'DANGEROUS'}}
    })""", {"analysis": analysis, "site": site})
    context.route("https://example.test/**", lambda r: r.fulfill(
        status=200, content_type="text/html", body="<h1>Local navigation fixture</h1>"))
    context.route("https://simak.un-sultra.ac.id/**", lambda r: r.fulfill(
        status=200, content_type="text/html", body="<h1>Local destination fixture</h1>"))
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    page.goto("https://example.test/before")
    warning_url = root_url + "src/warning/warning.html?id=ui-test"
    page.goto(warning_url)
    page.locator("#domain").filter(has_text="simak.un-sultra.ac.id").wait_for()
    assert page.locator(".reason-label").all_text_contents() == ["Analisis alamat URL", "Formulir"]
    assert page.locator("#reasonList").evaluate("el => getComputedStyle(el).listStyleType") == "disc"
    assert "ditemukan formulir yang mengarah ke domain halaman ini (simak.un-sultra.ac.id)" in page.locator("#reasonList").inner_text()
    assert page.locator("#continueButton").is_enabled()
    assert page.evaluate("""() => [...document.querySelectorAll('*')].every(el =>
        !getComputedStyle(el).backgroundImage.includes('gradient'))""")
    text_colors = page.evaluate("""() => [...document.querySelectorAll('body *')]
      .filter(el => el.getBoundingClientRect().height && [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()))
      .map(el => {
        let parent = el;
        let background = 'rgb(255, 255, 255)';
        while (parent) {
          const color = getComputedStyle(parent).backgroundColor;
          if (color.startsWith('rgb(')) { background = color; break; }
          parent = parent.parentElement;
        }
        return {text: el.textContent.trim().slice(0, 60), color: getComputedStyle(el).color, background};
      })""")
    import re
    def luminance(color):
        channels = [int(value) / 255 for value in re.findall(r"\d+", color)[:3]]
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
        return sum(a * b for a, b in zip(linear, [0.2126, 0.7152, 0.0722]))
    for sample in text_colors:
        values = sorted([luminance(sample['color']), luminance(sample['background'])])
        contrast = (values[1] + 0.05) / (values[0] + 0.05)
        assert contrast >= 4.5, (sample, contrast)
    if args.screenshots_dir:
        args.screenshots_dir.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(args.screenshots_dir / "warning-desktop.png"), full_page=True)
    for width in [375, 768, 1024, 1440]:
        page.set_viewport_size({"width": width, "height": 900})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth"), width
        for selector in ["#backButton", "#continueButton", ".settings-link"]:
            box = page.locator(selector).bounding_box()
            assert box["width"] >= 44 and box["height"] >= 44, (width, selector, box)
    page.locator("#backButton").focus()
    assert page.locator("#backButton").evaluate("el => getComputedStyle(el).outlineStyle") != "none"
    page.keyboard.press("Tab")
    assert page.locator("#continueButton").evaluate("el => el === document.activeElement")
    page.emulate_media(reduced_motion="reduce")
    assert page.locator("#backButton").evaluate("el => getComputedStyle(el).transitionDuration") == "0s"
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    if args.screenshots_dir:
        page.screenshot(path=str(args.screenshots_dir / "warning-mobile.png"), full_page=True)
    page.locator("#domain").evaluate("el => el.textContent = 'subdomain-'.repeat(20) + 'example.com'")
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.locator("#backButton").click()
    page.wait_for_url("https://example.test/before")
    page.goto(warning_url)
    page.evaluate("""() => {
        window.originalStorageSet = chrome.storage.local.set;
        chrome.storage.local.set = async () => { throw new Error('Simulated storage failure'); };
    }""")
    page.locator("#continueButton").click()
    page.locator("#actionError").wait_for(state="visible")
    assert page.url == warning_url
    assert page.locator("#continueButton").is_enabled()
    page.evaluate("() => { chrome.storage.local.set = window.originalStorageSet; }")
    page.locator("#continueButton").click()
    page.wait_for_url(site)
    lists = worker.evaluate("async () => chrome.storage.local.get(['heurishieldAllowlist','heurishieldBlacklist'])")
    assert 'simak.un-sultra.ac.id' in lists['heurishieldAllowlist'], lists
    assert 'simak.un-sultra.ac.id' not in lists['heurishieldBlacklist'], lists
    worker.evaluate("async () => chrome.storage.local.set({heurishieldEnabled:true})")
    page.reload()
    assert page.url == site
    control = context.new_page()
    control.goto(root_url + "src/options/options.html")
    outcome = control.evaluate("""async (url) => {
        const [tab] = await chrome.tabs.query({url});
        return chrome.runtime.sendMessage({type:'ANALYZE_ACTIVE_TAB',tabId:tab.id,url});
    }""", site)
    assert outcome['ok'] and outcome['analysis']['decision_policy']['source'] == 'manual_allowlist', outcome
    assert outcome['analysis']['verdict'] == 'SAFE'
    control.close()
    worker.evaluate('''async () => chrome.storage.local.set({warningContexts:{'only-url':{
      originalUrl:'https://shoopee.co.id/',analysis:{url:'https://shoopee.co.id/',verdict:'DANGEROUS',
        model_result:{model_family:'XGBoost',verdict:'DANGEROUS'},decision_policy:{source:'url_model'},
        brand_features:{claimed_brand_status:'ambiguous'},dom_features:{observed_frame_count:1,
          has_password_field:true,password_fields:[{visible:false}],forms:[]}}}}})''')
    page.goto(root_url + 'src/warning/warning.html?id=only-url')
    page.locator('#domain').filter(has_text='shoopee.co.id').wait_for()
    assert page.locator('.reason-label').all_text_contents() == ['Analisis alamat URL']
    assert page.locator('#reasonList li').count() == 1
    page.goto(root_url + "src/warning/warning.html?id=missing")
    page.locator("#domain").filter(has_text="Tidak tersedia").wait_for()
    assert page.locator("#continueButton").is_disabled()
    assert not errors, errors
    print("Warning page passed: reasons, contrast, responsive layout, keyboard, back, persistent allow list, blacklist removal, reopen and missing context.")
    context.close()
