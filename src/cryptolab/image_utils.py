def load_rgb_bytes(path: str) -> tuple[bytes, int, int, int]:
    """
    Load an image file and return (raw_bytes, width, height, channels=3).
    :param path:
    :return:
    """
    pass

def save_rgb_bytes(path: str, raw: bytes, w: int, h: int) -> None:
    """
    Purpose: Save raw RGB bytes (len == w*h*3) as a PNG.
    :param path:
    :param raw:
    :param w:
    :param h:
    :return:
    """
    pass

def side_by_side(out_path: str, images: list[tuple[bytes, int, int]], labels: list[str]) -> None:
    """
    Purpose: Compose multiple RGB images horizontally with simple label overlay.
    :param out_path:
    :param images:
    :param labels:
    :return:
    """
    pass