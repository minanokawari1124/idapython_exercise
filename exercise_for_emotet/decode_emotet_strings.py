from dataclasses import dataclass
import idc

SAMPLE_STRING_ADDR = 0x10001610


@dataclass
class EmotetString:
    """
    Emotet string object (202201)

      offset       structure
       0x0    |  key                             |
       0x4    |  size (xored by key)             |
       0x8    |  encrypted data (xored by key)   |

      @param head_addr: the start address of strings
    """

    xor_key: bytes
    size: int
    encrypted_text: bytes

    def __init__(self, head_addr: int):
        # extracts each data based on Emotet strings format.
        self.xor_key: bytes = idc.get_bytes(head_addr, 4)
        self.size: int = self.__calc_size(idc.get_bytes(head_addr + 4, 4))
        self.encrypted_text: bytes = idc.get_bytes(head_addr + 8, self.size)

    def __calc_size(self, encrypted_size: bytes) -> int:
        int_xor_key: int = int.from_bytes(self.xor_key, "little")
        int_enc_size: int = int.from_bytes(encrypted_size, "little")
        # calc the string size using 4bytes key
        return int_xor_key ^ int_enc_size

    def decode_string(self) -> str:
        dec_string: list[int] = []
        for i, enc in enumerate(self.encrypted_text):
            key: int = self.xor_key[i % 4]
            dec_string.append(key ^ enc)
        return bytearray(dec_string).decode()


if __name__ == "__main__":
    string = EmotetString(SAMPLE_STRING_ADDR)
    decoded_string: str = string.decode_string()

    # rename the address for decoded strings
    idc.set_name(SAMPLE_STRING_ADDR, decoded_string, idc.SN_NOCHECK)

    # furthermore, adds the repeatable comments for decoded string
    idc.set_cmt(
        SAMPLE_STRING_ADDR,
        f"size: {string.size}, string: {decoded_string}",
        True,
    )
    print(f"[{hex(SAMPLE_STRING_ADDR)}]: {decoded_string}")
