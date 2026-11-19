#!/usr/bin/env python3
"""builds the burner brand folder: svg masters, favicon set, social images.

everything comes from mark.py's geometry and the outlined wordmark, so a change
to the mark is a re-run, not a redraw. usage: build.py OUT_DIR
"""
import asyncio, json, os, sys
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from mark import CHAR, PAPER, EMBER, DEEP, ASH, TERM, mark, small, fav16, tile

FONTS = os.path.join(HERE, "fonts")  # jetbrains mono + inter, OFL
OUT = os.path.abspath(sys.argv[1])

# ---------- wordmark as outlines (JetBrains Mono Medium, -0.04em tracking) ----------
def wordmark_path(text="burner", size=42.0, x0=0.0, baseline=38.0, track=-0.04):
    font = TTFont(os.path.join(FONTS, "JetBrainsMono-Medium.ttf"))
    gs, cmap, upm = font.getGlyphSet(), font.getBestCmap(), font["head"].unitsPerEm
    k = size / upm
    x, parts = x0, []
    for ch in text:
        name = cmap[ord(ch)]
        pen = SVGPathPen(gs)
        gs[name].draw(TransformPen(pen, (k, 0, 0, -k, x, baseline)))
        parts.append(pen.getCommands())
        x += (font["hmtx"][name][0] + track * upm) * k
    return " ".join(parts), x - x0

GAP = 14
WM_D, WM_W = wordmark_path(x0=48 + GAP)
LOCK_W = round(48 + GAP + WM_W + 2)

def svg_doc(body, w, h, label):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{label}">'
            f'<title>{label}</title>{body}</svg>\n')

def lockup_body(fg, accent, wm):
    return mark(fg, accent) + f'<path d="{WM_D}" fill="{wm}"></path>'

def write(rel, text):
    p = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(text)
    return p

# ---------- svg masters ----------
SVGS = {
    "svg/mark-on-dark.svg": (mark(PAPER, EMBER), 48, 48),
    "svg/mark-on-light.svg": (mark(CHAR, DEEP), 48, 48),
    "svg/mark-mono-charcoal.svg": (mark(CHAR, CHAR), 48, 48),
    "svg/mark-mono-paper.svg": (mark(PAPER, PAPER), 48, 48),
    "svg/mark-small-on-dark.svg": (small(PAPER, EMBER), 48, 48),
    "svg/mark-small-on-light.svg": (small(CHAR, DEEP), 48, 48),
    "svg/tile.svg": (tile(CHAR, PAPER, EMBER), 48, 48),
    "svg/lockup-on-dark.svg": (lockup_body(PAPER, EMBER, PAPER), LOCK_W, 48),
    "svg/lockup-on-light.svg": (lockup_body(CHAR, DEEP, CHAR), LOCK_W, 48),
    "svg/lockup-mono-charcoal.svg": (lockup_body(CHAR, CHAR, CHAR), LOCK_W, 48),
    "svg/lockup-mono-paper.svg": (lockup_body(PAPER, PAPER, PAPER), LOCK_W, 48),
}

def inline(rel, size_w=None, size_h=None):
    body, w, h = SVGS[rel]
    sw, sh = size_w or w, size_h or h
    return f'<svg viewBox="0 0 {w} {h}" width="{sw}" height="{sh}" style="display:block">{body}</svg>'

# ---------- html compositions for raster output ----------
FACES = f'''<style>
@font-face{{font-family:"JBM";src:url("file://{FONTS}/JetBrainsMono-Regular.ttf")}}
@font-face{{font-family:"Inter";src:url("file://{FONTS}/InterVariable.ttf");font-weight:100 900}}
html,body{{margin:0;padding:0}}
</style>'''

def page(w, h, inner, bg="transparent"):
    return (f'<!doctype html><html><head><meta charset="utf-8">{FACES}</head>'
            f'<body style="width:{w}px;height:{h}px;background:{bg};overflow:hidden">{inner}</body></html>')

def centered(w, h, inner, bg):
    return page(w, h, f'<div style="width:{w}px;height:{h}px;display:flex;align-items:center;justify-content:center">{inner}</div>', bg)

def avatar(n, bg, fg, ac):
    s = round(n * 0.56)  # mark box; content stays inside the circle crop
    return centered(n, n, f'<svg viewBox="0 0 48 48" width="{s}" height="{s}" style="display:block">{mark(fg, ac)}</svg>', bg)

def banner(w, h, lock_h, tag_px, show_cmd=True, safe=None):
    lw = round(LOCK_W * lock_h / 48)
    cmd = (f'<div style="font-family:JBM;font-size:{round(tag_px*0.86)}px;color:{ASH};margin-top:{round(tag_px*0.5)}px">'
           f'<span style="color:{EMBER}">$</span> sudo burner shell</div>') if show_cmd else ""
    inner = (f'<div style="display:flex;flex-direction:column;align-items:center">'
             f'{inline("svg/lockup-on-dark.svg", lw, lock_h)}'
             f'<div style="font-family:Inter;font-weight:500;font-size:{tag_px}px;letter-spacing:-0.02em;color:{PAPER};margin-top:{round(lock_h*0.42)}px">throwaway linux vms on your own hardware.</div>'
             f'{cmd}</div>')
    return centered(w, h, inner, CHAR)

def card(w, h):
    # og / github social preview: left-aligned, same as the canvas og card
    lock_h = round(h * 0.19)
    lw = round(LOCK_W * lock_h / 48)
    pad_x, pad_y = round(w * 0.067), round(h * 0.114)
    inner = (f'<div style="box-sizing:border-box;width:{w}px;height:{h}px;padding:{pad_y}px {pad_x}px;display:flex;flex-direction:column;justify-content:space-between">'
             f'{inline("svg/lockup-on-dark.svg", lw, lock_h)}'
             f'<div><div style="font-family:Inter;font-weight:500;font-size:{round(h*0.07)}px;line-height:1.18;letter-spacing:-0.02em;color:{PAPER}">throwaway linux vms on your own hardware.</div>'
             f'<div style="font-family:JBM;font-size:{round(h*0.048)}px;color:{ASH};margin-top:{round(h*0.035)}px"><span style="color:{EMBER}">$</span> sudo burner shell</div></div>'
             f'<div style="display:flex;justify-content:space-between;font-family:JBM;font-size:{round(h*0.035)}px;color:{ASH}"><span>burnervm.dev</span><span>firecracker microvms · mit or apache-2.0</span></div></div>')
    return page(w, h, inner, CHAR)

def icon_png(n, inner_svg, bg):
    return centered(n, n, inner_svg, bg)

RASTERS = []  # (rel path, w, h, html, transparent)
def raster(rel, w, h, html, transparent=False):
    RASTERS.append((rel, w, h, html, transparent))

# favicon pngs (for .ico) and app icons
raster("favicon/_16.png", 16, 16, page(16, 16, f'<svg viewBox="0 0 16 16" width="16" height="16" style="display:block">{fav16(CHAR, PAPER, EMBER)}</svg>'), True)
raster("favicon/_32.png", 32, 32, page(32, 32, f'<svg viewBox="0 0 48 48" width="32" height="32" style="display:block">{tile(CHAR, PAPER, EMBER, tiny=True)}</svg>'), True)
raster("favicon/_48.png", 48, 48, page(48, 48, f'<svg viewBox="0 0 48 48" width="48" height="48" style="display:block">{tile(CHAR, PAPER, EMBER)}</svg>'), True)
raster("favicon/apple-touch-icon.png", 180, 180, icon_png(180, f'<svg viewBox="0 0 48 48" width="132" height="132" style="display:block">{mark(PAPER, EMBER)}</svg>', CHAR))
raster("favicon/icon-192.png", 192, 192, page(192, 192, f'<svg viewBox="0 0 48 48" width="192" height="192" style="display:block">{tile(CHAR, PAPER, EMBER)}</svg>'), True)
raster("favicon/icon-512.png", 512, 512, page(512, 512, f'<svg viewBox="0 0 48 48" width="512" height="512" style="display:block">{tile(CHAR, PAPER, EMBER)}</svg>'), True)
raster("favicon/icon-maskable-512.png", 512, 512, icon_png(512, f'<svg viewBox="0 0 48 48" width="300" height="300" style="display:block">{mark(PAPER, EMBER)}</svg>', CHAR))

# transparent marks for places that want a raster
for n in (256, 512, 1024):
    raster(f"png/mark-on-dark-{n}.png", n, n, page(n, n, f'<svg viewBox="0 0 48 48" width="{n}" height="{n}" style="display:block">{mark(PAPER, EMBER)}</svg>'), True)
    raster(f"png/mark-on-light-{n}.png", n, n, page(n, n, f'<svg viewBox="0 0 48 48" width="{n}" height="{n}" style="display:block">{mark(CHAR, DEEP)}</svg>'), True)
for theme, args in (("dark", (PAPER, EMBER, PAPER)), ("light", (CHAR, DEEP, CHAR))):
    h = 240; w = round(LOCK_W * h / 48)
    raster(f"png/lockup-on-{theme}-{w}x{h}.png", w, h, page(w, h, f'<svg viewBox="0 0 {LOCK_W} 48" width="{w}" height="{h}" style="display:block">{lockup_body(*args)}</svg>'), True)

# social: avatars (square, circle-safe)
for n in (400, 512, 800, 1000):
    raster(f"social/avatar-dark-{n}.png", n, n, avatar(n, CHAR, PAPER, EMBER))
raster("social/avatar-light-1000.png", 1000, 1000, avatar(1000, PAPER, CHAR, DEEP))

# social: banners and cards
raster("social/banner-3x1-3000x1000.png", 3000, 1000, banner(3000, 1000, 150, 64))
raster("social/banner-3x1-1500x500.png", 1500, 500, banner(1500, 500, 76, 32))
raster("social/linkedin-banner-1584x396.png", 1584, 396, banner(1584, 396, 64, 26, show_cmd=False))
raster("social/youtube-banner-2560x1440.png", 2560, 1440, banner(2560, 1440, 120, 44))  # content fits the 1546x423 safe area
raster("social/discord-banner-960x540.png", 960, 540, banner(960, 540, 64, 26))
raster("social/og-1200x630.png", 1200, 630, card(1200, 630))
raster("social/github-social-preview-1280x640.png", 1280, 640, card(1280, 640))

async def render_all():
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path=os.environ.get("CHROME") or None, args=["--no-sandbox", "--allow-file-access-from-files"])
        for rel, w, h, html, transparent in RASTERS:
            pg = await b.new_page(viewport={"width": w, "height": h}, device_scale_factor=1)
            tmp = os.path.join(HERE, "_render.html")
            open(tmp, "w", encoding="utf-8").write(html)
            await pg.goto("file://" + tmp)
            await pg.evaluate("document.fonts.ready")
            out = os.path.join(OUT, rel)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            await pg.screenshot(path=out, omit_background=transparent, clip={"x": 0, "y": 0, "width": w, "height": h})
            await pg.close()
        await b.close()

def main():
    for rel, (body, w, h) in SVGS.items():
        label = "burner " + os.path.basename(rel)[:-4].replace("-", " ")
        write(rel, svg_doc(body, w, h, label))
    # svg favicon: the hand-placed 16 px drawing, scales up cleanly
    write("favicon/favicon.svg", '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">' + fav16(CHAR, PAPER, EMBER) + "</svg>\n")
    asyncio.run(render_all())
    ico = [Image.open(os.path.join(OUT, f"favicon/_{n}.png")).convert("RGBA") for n in (16, 32, 48)]
    ico[2].save(os.path.join(OUT, "favicon/favicon.ico"), sizes=[(16, 16), (32, 32), (48, 48)], append_images=ico[:2])
    for n in (16, 32, 48):
        os.remove(os.path.join(OUT, f"favicon/_{n}.png"))
    write("favicon/site.webmanifest", json.dumps({
        "name": "burner", "short_name": "burner",
        "icons": [
            {"src": "/brand/favicon/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/brand/favicon/icon-512.png", "sizes": "512x512", "type": "image/png"},
            {"src": "/brand/favicon/icon-maskable-512.png", "sizes": "512x512", "type": "image/png", "purpose": "maskable"},
        ],
        "theme_color": CHAR, "background_color": CHAR, "display": "browser",
    }, indent=2) + "\n")
    os.remove(os.path.join(HERE, "_render.html"))
    print("built", len(SVGS) + 2, "svg/text files and", len(RASTERS) - 3 + 1, "images into", OUT)

if __name__ == "__main__":
    main()
