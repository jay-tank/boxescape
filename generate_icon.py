#!/usr/bin/env python3
"""Generate icon.png (128x128) for the BoxEscape VS Code extension.

Rounded-square dark teal to cyan gradient drawn at 4x and downscaled with LANCZOS. Glyph: a white
open box (isometric, lid open) with a bold arrow escaping upward out of it.
"""

from PIL import Image, ImageDraw

SIZE = 128
SCALE = 4
BIG = SIZE * SCALE

TOP_COLOR = (6, 54, 61)      # dark teal
BOTTOM_COLOR = (0, 196, 224)  # cyan
WHITE = (255, 255, 255, 255)


def rounded_gradient_bg(size, top_color, bottom_color, radius_ratio=0.22):
    gradient = Image.new("RGB", (size, size))
    gdraw = ImageDraw.Draw(gradient)
    for d in range(2 * size - 1):
        t = d / (2 * size - 2)
        c = tuple(int(top_color[i] + (bottom_color[i] - top_color[i]) * t) for i in range(3))
        gdraw.line([(d, 0), (0, d)], fill=c, width=2)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([(0, 0), (size - 1, size - 1)], radius=int(size * radius_ratio), fill=255)
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    img.paste(gradient, (0, 0))
    img.putalpha(mask)
    return img


def poly(draw, pts, width):
    draw.line(pts + [pts[0]], fill=WHITE, width=width, joint="curve")


def draw_glyph(img):
    s = img.size[0]
    d = ImageDraw.Draw(img)
    w = int(s * 0.05)
    cx = s * 0.5
    top = s * 0.56     # rim of the open box (front corner y)
    dx = s * 0.27      # half width
    dy = s * 0.12      # isometric depth
    h = s * 0.25       # box height
    left = (cx - dx, top - dy)
    right = (cx + dx, top - dy)
    front = (cx, top)
    back = (cx, top - 2 * dy)
    # Body: front faces filled white, with a teal seam down the front edge.
    body = [left, front, right, (right[0], right[1] + h), (cx, top + h), (left[0], left[1] + h)]
    d.polygon(body, fill=WHITE)
    d.line([front, (cx, top + h)], fill=(6, 90, 104, 255), width=int(s * 0.022))
    # Open rim (back edges) as an outline.
    poly(d, [left, back, right, front], w)
    # Open flaps.
    d.line([left, (left[0] - s * 0.09, left[1] - s * 0.12)], fill=WHITE, width=w)
    d.line([right, (right[0] + s * 0.09, right[1] - s * 0.12)], fill=WHITE, width=w)
    # Arrow escaping upward out of the box.
    shaft_w = int(s * 0.075)
    tip_y = s * 0.11
    d.line([(cx, top - dy * 0.9), (cx, tip_y + s * 0.12)], fill=WHITE, width=shaft_w)
    head = s * 0.13
    d.polygon([(cx, tip_y), (cx - head, tip_y + head * 1.05), (cx + head, tip_y + head * 1.05)], fill=WHITE)


def main():
    big = rounded_gradient_bg(BIG, TOP_COLOR, BOTTOM_COLOR)
    draw_glyph(big)
    final = big.resize((SIZE, SIZE), Image.LANCZOS)
    final.save("icon.png")
    print("Wrote icon.png (%dx%d)" % (SIZE, SIZE))


if __name__ == "__main__":
    main()
