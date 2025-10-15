import json
import logging
import os
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime, timezone


def ensure_logger(log_dir: str, log_file: str, level: str = "INFO") -> logging.Logger:
    """
    Ensure provided logging directory and file exists at specified level.
    :param log_dir:
    :param log_file:
    :param level:
    :return:
    """
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("cryptolab.metrics")

    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    path = os.path.join(log_dir, log_file)

    handler = TimedRotatingFileHandler(path, when="D", interval=1, backupCount=14, encoding="utf-8")
    formatter = logging.Formatter("%(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def emit_json(logger: logging.Logger, payload: dict) -> None:
    """
    Helper, ignoer
    :param logger:
    :param payload:
    :return:
    """
    payload.setdefault("ts", datetime.now(timezone.utc).isoformat())
    logger.info(json.dumps(payload, separators=(",", ":")))
