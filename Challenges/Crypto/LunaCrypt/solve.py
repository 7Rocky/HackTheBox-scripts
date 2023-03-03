def decrypt_character(char: int, flag: int) -> int:
    if flag & 0b0001_0000:
        char ^= 0b0011_1110
    if flag & 0b0000_1000:
        char ^= 0b0110_1011
    if flag & 0b0000_0010:
        char = 255 - char
    if flag & 0b0100_0000:
        THIS_MSB = (char >> 4) & 0b1111
        THIS_LSB = char & 0b1111
        char = ((THIS_LSB << 4) ^ 0b1101_0000) | (THIS_MSB ^ 0b1011)

    return char


def main():
    with open('output.txt') as f:
        numbers = list(map(int, f.read().split()))

        for i in range(0, len(numbers), 2):
            flag = numbers[i + 1] ^ 0x4a
            print(chr(decrypt_character(numbers[i], flag)), end='')


if __name__ == '__main__':
    main()
