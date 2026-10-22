#!/usr/bin/env python3
"""Montage README : tableau de bord, onglet Sécurité, vue simple et popup, sur un fond sombre."""
import sys
from PIL import Image, ImageDraw, ImageFilter
S = sys.argv[1]; OUT = sys.argv[2]
W, H = 1600, 1000
bg = Image.new("RGB", (W, H))
px = bg.load()
for y in range(H):
    t = y / (H - 1)
    for x in range(W):
        u = x / (W - 1)
        r = int(9 + 10 * t + 4 * u); g = int(13 + 12 * t + 3 * u); b = int(24 + 22 * t + 6 * u)
        px[x, y] = (r, g, b)
glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
gd = ImageDraw.Draw(glow)
gd.ellipse((900, -200, 1700, 500), fill=(34, 197, 94, 38))
gd.ellipse((-300, 500, 500, 1200), fill=(59, 130, 246, 30))
glow = glow.filter(ImageFilter.GaussianBlur(160))
canvas = Image.alpha_composite(bg.convert("RGBA"), glow)

def rounded(im, radius):
    mask = Image.new("L", im.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, im.size[0] - 1, im.size[1] - 1), radius=radius, fill=255)
    out = im.convert("RGBA"); out.putalpha(mask); return out

def place(canvas, path, width, pos, radius=18, shadow=28, alpha_mask=True):
    im = Image.open(path).convert("RGBA")
    h = round(im.size[1] * width / im.size[0])
    im = im.resize((width, h), Image.LANCZOS)
    if alpha_mask:
        im = rounded(im, radius)
    sh = Image.new("RGBA", (width + shadow * 4, h + shadow * 4), (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle((shadow * 2, shadow * 2 + 10, shadow * 2 + width, shadow * 2 + h + 10), radius=radius, fill=(0, 0, 0, 170))
    sh = sh.filter(ImageFilter.GaussianBlur(shadow))
    canvas.alpha_composite(sh, (pos[0] - shadow * 2, pos[1] - shadow * 2))
    canvas.alpha_composite(im, pos)
    return canvas

canvas = place(canvas, f"{S}/dash.png", 1040, (40, 30))
canvas = place(canvas, f"{S}/security.png", 820, (750, 190))
canvas = place(canvas, f"{S}/simple.png", 700, (30, 350))
canvas = place(canvas, f"{S}/popup2x.png", 380, (1180, 812), radius=14, shadow=22, alpha_mask=False)
canvas.convert("RGB").save(OUT, optimize=True)
print("ok", OUT, canvas.size)
