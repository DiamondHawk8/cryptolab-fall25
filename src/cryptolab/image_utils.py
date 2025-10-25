def load_rgb_bytes(path: str) -> tuple[bytes, int, int, int]:
    """
    Load an image file and return (raw_bytes, width, height, channels=3).
    :param path:
    :return:
    """
    pass

def save_rgb_bytes(path: str, raw: bytes, w: int, h: int) -> None:
    """
    Create PIL.Image.frombytes('RGB', (w,h), raw) and save as PNG.
    :param path:
    :param raw:
    :param w:
    :param h:
    :return:
    """
    pass

def compose_side_by_side(out_path: str, images: list[tuple[bytes, int, int]], labels: list[str]) -> None:
    """
    Compose multiple RGB images horizontally with simple label overlay.
    :param out_path:
    :param images:
    :param labels:
    :return:
    """
    pass