import idc

HEAD = 0x401025


def solve(start_ea: int) -> bytearray:
    answer: list[int] = []
    while 1:
        mnem: str = idc.print_insn_mnem(start_ea)
        value: int = idc.get_operand_value(start_ea, 1)
        # calc the flag byte while the address of instruction mnemonic is "mov"
        # and the 2nd operand value is 0, such as "mov   [ebp+xxx], FFh"
        if mnem != "mov" or value == 0:
            break
        answer.append(0xC3 - value)
        # move the address to next instruction
        start_ea = idc.next_head(start_ea)
    return bytearray(answer)


if __name__ == "__main__":
    answer: bytearray = solve(HEAD)
    print(f"FLAG is `{answer.decode()}`")
