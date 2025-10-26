from typing import List, Tuple
from PIL import Image, ImageDraw, ImageFont

def load_rgb_bytes(path: str) -> tuple[bytes, int, int, int]:
    """
    Load an image file and return (raw_bytes, width, height, channels=3).
    :param path:
    :return:
    """
    img = Image.open(path).convert("RGB")

    w, h = img.size
    raw = img.tobytes()

    return raw, w, h, 3

def save_rgb_bytes(path: str, raw: bytes, w: int, h: int) -> None:
    """
    Create PIL.Image.frombytes('RGB', (w,h), raw) and save as PNG.
    :param path:
    :param raw:
    :param w:
    :param h:
    :return:
    """
    if len(raw) != w * h * 3:
        raise ValueError("raw length does not match w*h*3")

    img = Image.frombytes("RGB", (w, h), raw)

    img.save(path, format="PNG")

def compose_side_by_side(out_path: str, images: list[tuple[bytes, int, int]], labels: list[str]) -> None:
    """
    Compose multiple RGB images horizontally with simple label overlay.
    :param out_path:
    :param images:
    :param labels:
    :return:
    """

    if not images:
        raise ValueError("no images to compose")

    (raw0, w, h) = images[0]

    for raw, wi, hi in images:

        if wi != w or hi != h:
            raise ValueError("all images must have same dimensions")

        if len(raw) != w * h * 3:
            raise ValueError("raw length mismatch for one image")

    n = len(images)
    canvas = Image.new("RGB", (w * n, h))

    for i, (raw, _, _) in enumerate(images):
        img = Image.frombytes("RGB", (w, h), raw)
        canvas.paste(img, (i * w, 0))

    if labels:
        draw = ImageDraw.Draw(canvas)
        # Use default font to keep text small and unobtrusive
        for i, label in enumerate(labels):
            draw.rectangle([i * w, 0, i * w + 110, 18], fill=(0, 0, 0))
            draw.text((i * w + 4, 2), label, fill=(255, 255, 255))

    canvas.save(out_path, format="PNG")
