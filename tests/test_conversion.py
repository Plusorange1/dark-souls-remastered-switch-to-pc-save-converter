"""Small end-to-end test for the DSR Switch -> PC converter.

It builds a synthetic Switch save and a synthetic PC template in the same
container formats the real tool expects, runs a conversion, then reads the
output back and checks the character body and roster fields.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import dsr_switch_to_pc as tool  # noqa: E402


def build_bnd4(slots: list[bytes], names: list[str]) -> bytes:
    assert len(slots) == 11 and len(names) == 11
    header = bytearray(0x2C0)
    header[:4] = b"BND4"
    struct.pack_into("<I", header, 0x0C, 11)
    struct.pack_into("<I", header, 0x10, 0x40)

    name_offset = 0x1A0
    data_offset = 0x2C0
    for i, (name, slot) in enumerate(zip(names, slots)):
        base = 0x40 + i * 0x20
        struct.pack_into("<I", header, base + 0x00, 0x50)
        struct.pack_into("<I", header, base + 0x04, 0xFFFFFFFF)
        struct.pack_into("<I", header, base + 0x08, len(slot))
        struct.pack_into("<I", header, base + 0x10, data_offset)
        struct.pack_into("<I", header, base + 0x14, name_offset)
        encoded = name.encode("utf-16-le") + b"\x00\x00"
        header[name_offset:name_offset + len(encoded)] = encoded
        name_offset += len(encoded)
        data_offset += len(slot)

    out = bytearray(header)
    for slot in slots:
        out += slot
    return bytes(out)


def make_character_body(version: int, name: str, level: int, play_ms: int) -> bytes:
    body = bytearray(0x60000)
    struct.pack_into("<I", body, 0x00, version)
    struct.pack_into("<I", body, 0x08, play_ms)
    struct.pack_into("<H", body, 0xDC, level)
    encoded = name.encode("utf-16-le")
    body[0xF4:0xF4 + len(encoded)] = encoded
    return bytes(body)


def make_switch_slot(body: bytes) -> bytes:
    return hashlib.md5(body).digest() + body


def make_pc_slot(body: bytes) -> bytes:
    plaintext = struct.pack("<I", 0x60000) + body + b"\x0c" * 12
    iv = b"\x11" * 16
    ciphertext = tool.aes_cbc_encrypt(tool.AES_KEY, iv, plaintext)
    return hashlib.md5(iv + ciphertext).digest() + iv + ciphertext


class ConversionTest(unittest.TestCase):
    def test_convert_character_body_shift(self) -> None:
        body = bytearray(0x60000)
        struct.pack_into("<I", body, 0x00, 65)
        name_bytes = "SwitchGuy".encode("utf-16-le")
        body[0xF4:0xF4 + len(name_bytes)] = name_bytes
        struct.pack_into("<H", body, 0xDC, 178)
        struct.pack_into("<I", body, 0x08, 55_469_000)
        body[0x1D0:0x1D4] = b"MARK"

        version_block = b"\x00\x00\x00\x00" + b"1.03" + b"\x00" * 8
        converted = tool.convert_character_body(bytes(body), version_block, 71)

        self.assertEqual(len(converted), 0x60000)
        self.assertEqual(struct.unpack_from("<I", converted, 0)[0], 71)
        self.assertEqual(converted[0xF4:0xF4 + len(name_bytes)], name_bytes)
        self.assertEqual(struct.unpack_from("<H", converted, 0xDC)[0], 178)
        self.assertEqual(converted[0x1A0:0x1B0], version_block)
        # The extra Switch block at 0x1C0 is removed; data from 0x1D0 moves down.
        self.assertEqual(converted[0x1C0:0x1C4], b"MARK")

    def test_parse_slots(self) -> None:
        self.assertEqual(tool.parse_slots("0, 2,0x3"), [0, 2, 3])
        with self.assertRaises(Exception):
            tool.parse_slots("11")

    def test_full_conversion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            switch_bodies = [bytes(0x60000) for _ in range(10)]
            switch_bodies[0] = make_character_body(65, "SwitchGuy", 178, 55_469_000)
            switch_bodies[1] = make_character_body(65, "SecondGuy", 42, 3_600_000)
            switch_slots = [make_switch_slot(body) for body in switch_bodies]
            switch_slots.append(make_switch_slot(bytes(0x60000)))
            switch_names = [f"USER_DATA{i:03d}" for i in range(11)]
            switch_path = tmp_path / "switch.sl2"
            switch_path.write_bytes(build_bnd4(switch_slots, switch_names))

            pc_bodies = [bytes(0x60000) for _ in range(10)]
            pc_bodies[0] = make_character_body(71, "PCGuy", 4, 278_000)
            pc_bodies[0] = (
                pc_bodies[0][:0x1A0]
                + b"\x00\x00\x00\x00" + b"1.03" + b"\x00" * 8
                + pc_bodies[0][0x1B0:]
            )
            system_body = bytearray(0x60000)
            struct.pack_into("<I", system_body, 0, 30)
            system_body[0xB0] = 1
            entry0 = 0x98
            struct.pack_into("<I", system_body, entry0 + 0x4C, 4)
            struct.pack_into("<I", system_body, entry0 + 0x50, 278)
            pc_name = "PCGuy".encode("utf-16-le")
            system_body[entry0 + 0x28:entry0 + 0x28 + len(pc_name)] = pc_name

            pc_slots = [make_pc_slot(body) for body in pc_bodies]
            pc_slots.append(make_pc_slot(bytes(system_body)))
            pc_names = [f"USER_DATA{i:03d}" for i in range(11)]
            template_path = tmp_path / "pc.sl2"
            template_path.write_bytes(build_bnd4(pc_slots, pc_names))

            output_path = tmp_path / "out.sl2"
            result = tool.convert(
                switch_path, template_path, output_path, mode="replace", slots=[0, 1]
            )

            self.assertEqual(result.size, 0x4204D0)
            out = tool.read_pc_save(output_path)
            self.assertEqual(struct.unpack_from("<I", out.bodies[0], 0)[0], 71)
            self.assertEqual(
                tool.read_utf16(out.bodies[0], tool.OFF_NAME, 34), "SwitchGuy"
            )
            self.assertEqual(struct.unpack_from("<H", out.bodies[0], 0xDC)[0], 178)
            self.assertEqual(
                tool.read_utf16(out.bodies[1], tool.OFF_NAME, 34), "SecondGuy"
            )
            self.assertEqual(out.system_body[0xB0:0xB0 + 3], bytes([1, 1, 0]))
            self.assertEqual(
                tool.read_utf16(out.system_body, 0x98 + 0x28, 34), "SwitchGuy"
            )
            self.assertEqual(
                struct.unpack_from("<I", out.system_body, 0x98 + 0x4C)[0], 178
            )


if __name__ == "__main__":
    unittest.main()
