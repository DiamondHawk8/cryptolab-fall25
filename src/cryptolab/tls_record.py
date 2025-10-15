from dataclasses import dataclass

# Legacy toggle, may be unused
TLS_CONTENT_CHANGE_CIPHER_SPEC = 20

TLS_CONTENT_ALERT = 21
TLS_CONTENT_HANDSHAKE = 22
TLS_CONTENT_APP_DATA = 23


@dataclass
class TLSInspector:
    """
    TLS record counter (no decryption).
    Counts bytes in handshake phase until the first TLS_CONTENT_APP_DATA (23) is seen.
    Will be used to log how expensive the handshake was
    """
    handshake_bytes: int = 0
    app_seen: bool = False  # If true, new bytes are not counted as handshake
    _buf: bytearray = bytearray()
    include_headers: bool = True  # If False, count only payload bytes

    def feed(self, data: bytes) -> None:
        """
        Feed raw TCP bytes from one direction so that we can parse record frames to count handshake bytes.
        :param data: data to be appended to buffer.
        :return: None
        """

        if not data:
            return

        self._buf.extend(data)

        # TLS record format:
        # content_type (1 byte) | version (2 bytes) | length (2 bytes)

        while len(self._buf) >= 5:

            rtype = self._buf[0]
            length = int.from_bytes(self._buf[3:5], "big")
            rec_len = 5 + length

            if len(self._buf) < rec_len:
                # If full record has not been accounted for yet, wait for more bytes
                break

            if not self.app_seen:
                if rtype != TLS_CONTENT_APP_DATA:
                    # If we have not got to app data yet, treat it as handshake phase and add the entire size
                    self.handshake_bytes += rec_len if self.include_headers else length
                else:
                    # Mark as post handshake otherwise
                    self.app_seen = True

            # Reset for next data
            del self._buf[:rec_len]
