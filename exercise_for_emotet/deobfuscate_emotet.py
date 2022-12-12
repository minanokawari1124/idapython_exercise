from dataclasses import dataclass
from typing import Iterator, Optional
import idc
import idautils
import ida_funcs
import re


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

    addr: int
    xor_key: bytes
    size: int
    encrypted_text: bytes
    decoded_text: str

    def __init__(self, head_addr: int):
        # extracts each data based on Emotet strings format.
        self.addr = head_addr
        self.xor_key = idc.get_bytes(head_addr, 4)
        self.size = self.__calc_size(idc.get_bytes(head_addr + 4, 4))
        self.encrypted_text = idc.get_bytes(head_addr + 8, self.size)
        self.decoded_text = self.__decode_string()

    def __calc_size(self, encrypted_size: bytes) -> int:
        int_xor_key: int = int.from_bytes(self.xor_key, "little")
        int_enc_size: int = int.from_bytes(encrypted_size, "little")
        # calc the string size using 4bytes key
        return int_xor_key ^ int_enc_size

    def __decode_string(self) -> str:
        dec_string: list[int] = []
        for i, enc in enumerate(self.encrypted_text):
            key: int = self.xor_key[i % 4]
            dec_string.append(key ^ enc)
        return bytearray(dec_string).decode()

    def get_decoded_string(self) -> str:
        return self.decoded_text


@dataclass
class EmotetAnalyzer:
    """
    Analyzer for all of Emotet binary (202201)
    """

    STR_FUNC_PATTERN: bytes = rb"\xc1.\x08.{3,10}\xc1.\x10.{3,10}\xc1.\x08"

    def get_dec_string_func_addr(self) -> list[int]:
        # get the all of function address for decode strings
        mem: dict[int, bytes] = self.__get_text_segment_bytes()
        return self.__search_pattern(mem)

    def get_xref_addresses(self, addr: int) -> list[int]:
        # get the all of xrefs address for `addr`.
        return [ref.frm for ref in idautils.XrefsTo(addr)]

    def __get_text_segment_bytes(self) -> dict[int, bytes]:
        # extracts all of ".text" segment bytes and start address
        mem: dict[int, bytes] = {}
        for segment in idautils.Segments():
            segment_name: str = idc.get_segm_name(segment)
            if segment_name != ".text":
                continue
            segment_start: int = idc.get_segm_start(segment)
            segment_end: int = idc.get_segm_end(segment)
            segment_data = idc.get_bytes(
                segment_start,
                segment_end - segment_start,
            )
            # save the bytes like `{0x10001000: b"\xde\xad\xbe\xef......."}`
            mem[segment_start] = segment_data
        return mem

    def __search_pattern(self, mem: dict[int, bytes]) -> list[int]:
        addresses: list[int] = []
        # search the all of STR_FUNC_PATTERN pattern address from value
        for base_addr, raw_mem in mem.items():
            match: Iterator[re.Match[bytes]] = re.finditer(
                self.STR_FUNC_PATTERN,
                raw_mem,
            )
            if not match:
                continue
            for m in match:
                # if pattern was found, calc the RVA
                # and the address of the function where the pattern exists
                func_start_addr: int = ida_funcs.get_func(
                    base_addr + m.start()
                ).start_ea
                addresses.append(func_start_addr)
        return addresses

    def get_string_addr_from_args(self, addr: int) -> Optional[int]:
        push_cnt: int = 0
        # back to 30 previous instructions to search target strings address
        for _ in range(30):
            addr = idc.prev_head(addr)
            mnem: str = idc.print_insn_mnem(addr)
            ope_1st: str = idc.print_operand(addr, 0)
            ope_type: int = idc.get_operand_type(addr, 1)

            # the string was used at 2nd arguments,
            # such as "move   edx, offset_0x100016A0" instruction.
            if mnem == "mov" and ope_1st == "edx" and ope_type == idc.o_imm:
                return idc.get_operand_value(addr, 1)
            # the string was used at 4th arguments,
            # such as "push   offset_0x100016A0" instruction.
            elif mnem == "push" and push_cnt == 1:
                return idc.get_operand_value(addr, 0)
            # count up "push" instruction to search 2nd "push" instruction.
            elif mnem == "push":
                push_cnt += 1

        return None

    def set_cmt_and_rename(self, estring: EmotetString) -> None:
        # rename the address for decoded strings
        idc.set_name(
            estring.addr,
            estring.decoded_text,
            idc.SN_NOCHECK + idc.SN_NOWARN,
        )

        # furthermore, adds the repeatable comments for decoded string
        idc.set_cmt(
            estring.addr,
            f"size: {estring.size}, string: {estring.decoded_text}",
            True,
        )
        print(f"[{hex(estring.addr)}]: {estring.decoded_text}")


if __name__ == "__main__":
    helper = EmotetAnalyzer()
    string_func_addresses: list[int] = helper.get_dec_string_func_addr()
    caller_addresses: list[int] = []
    for func_addr in string_func_addresses:
        caller_addresses.extend(helper.get_xref_addresses(func_addr))

    # get strings address and build EmotetString
    for caller_addr in caller_addresses:
        try:
            string_addr: Optional[int] = helper.get_string_addr_from_args(caller_addr)
            if not string_addr:
                print(f"[!] Could not found strings @{hex(caller_addr)}")
                continue
            estring = EmotetString(string_addr)
            helper.set_cmt_and_rename(estring)
        except Exception as e:
            print(f"[{hex(caller_addr)}]: {e}")
