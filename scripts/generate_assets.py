"""
Script for creating unified assets
"""
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

ASSETS = Path("assets")
ASSETS.mkdir(exist_ok=True)

# 256x256 checkerboard (16x16 tiles of 16 px)
size = 256
tiles = 16
tile_size = size // tiles

board = np.indices((size, size)).sum(axis=0) // tile_size
board = (board % 2) * 255

plt.imshow(board, cmap="gray", vmin=0, vmax=255)
plt.axis("off")
plt.savefig(ASSETS / "checkerboard_256.png", bbox_inches="tight", pad_inches=0)

# Nonce reuse plaintexts
(ASSETS / "nonce_reuse_1.txt").write_text("Attack at dawn. Send 10 units.\n")
(ASSETS / "nonce_reuse_2.txt").write_text("Retreat at dusk. Send 12 units.\n")

print("Assets written to ./assets")
