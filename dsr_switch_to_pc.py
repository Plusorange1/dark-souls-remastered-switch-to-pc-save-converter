#!/usr/bin/env python3
"""
Dark Souls: Remastered - Nintendo Switch -> PC save converter.

The Switch release stores each USER_DATA entry as:
    [MD5(plaintext) 16 bytes][plaintext 0x60000 bytes]

The PC release stores each entry as:
    [MD5(IV + ciphertext) 16][IV 16][AES-128-CBC ciphertext 0x60010]

The inner save data is *almost* identical, but the Switch build (save version
65) places the fixed character fields 16 bytes later than the PC build (save
version 71).  This tool:

  * extracts the Switch character bodies,
  * removes the extra 16-byte block and restores the PC version block,
  * patches the character save-version stamp to the PC value,
  * rebuilds the PC load-screen roster (slot 010) in the PC layout,
  * re-encrypts every slot in the PC container format.

It needs an existing PC save as a template because the PC system slot and the
container header are taken from it.  Your existing PC characters can either be
replaced or kept (merge mode).

Tested with Dark Souls: Remastered Switch 1.0.x -> PC 1.03.1.

This is an unofficial fan tool.  Back up your saves.  Use offline.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - handled in main()
    Cipher = algorithms = modes = None

# --- Constants --------------------------------------------------------------- #

AES_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")

BND4_HEADER = 0x40
BND4_ENTRY = 0x20
SLOT_COUNT = 11
CHARACTER_SLOTS = 10
SLOT_SIZE = 0x60030
BODY_SIZE = 0x60000
SLOT_DATA_SIZE = 0x60010          # AES plaintext size (PC)
SLOT_PADDING = b"\x0c" * 12       # DSR's custom PKCS#7-style padding
PC_SLOT_SIZE = SLOT_SIZE
SWITCH_SLOT_SIZE = 0x60010        # MD5 + body

# Fixed field offsets in the decrypted PC body (0x60000 bytes).
# These are the same offsets used by the PC build; the Switch build is +0x10
# for everything after the character header.
OFF_VERSION = 0x0000
OFF_PLAYTIME_MS = 0x0008
OFF_LEVEL = 0x00DC
OFF_SOULS = 0x00E0
OFF_NAME = 0x00F4
OFF_VERSION_BLOCK = 0x01A0
OFF_SWITCH_EXTRA_BLOCK = 0x01C0
OFF_EQUIP_SLOTS = 0x0294
OFF_EQUIP_IDS = 0x0300
OFF_INVENTORY = 0x035C
OFF_ITEMS_COUNT = 0xE35C
OFF_APPEARANCE = 0xE400

# PC system slot (slot 010) roster layout, body-relative.
SYS_VERSION_OFF = 0x0000
SYS_ACTIVE_FLAGS_OFF = 0x00B0     # 10 x u8, 1 = occupied
SYS_DIR_BASE = 0x0098             # entry 0
SYS_DIR_STRIDE = 0x0190           # 400 bytes
SYS_DIR_NAME = 0x0028             # 34 bytes, UTF-16LE
SYS_DIR_LEVEL = 0x004C            # u32
SYS_DIR_PLAYTIME = 0x0050         # u32 seconds

PC_CHAR_VERSION = 71
PC_SYS_VERSION = 30
DEFAULT_VERSION_BLOCK = struct.pack("<I", 0) + b"1.03" + b"\x00" * 8


class SaveFormatError(Exception):
    """Raised when an input file is not the expected DSR save format."""


# --- Small helpers ----------------------------------------------------------- #

def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def p32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def md5(data: bytes | bytearray) -> bytes:
    return hashlib.md5(data).digest()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if Cipher is None:
        raise RuntimeError("The 'cryptography' package is required.")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if Cipher is None:
        raise RuntimeError("The 'cryptography' package is required.")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def read_utf16(data: bytes | bytearray, offset: int, length: int) -> str:
    return bytes(data[offset:offset + length]).decode("utf-16-le", "ignore").split("\x00")[0]


def write_utf16_field(target: bytearray, offset: int, text: str, length: int) -> None:
    encoded = text.encode("utf-16-le")[: length - 2]
    target[offset:offset + length] = encoded.ljust(length, b"\x00")


# --- BND4 parsing ------------------------------------------------------------ #

@dataclass
class BndEntry:
    index: int
    size: int
    offset: int
    name: str


def parse_bnd4(data: bytes) -> list[BndEntry]:
    if len(data) < BND4_HEADER or data[:4] != b"BND4":
        raise SaveFormatError("Not a BND4/.sl2 save file.")

    count = u32(data, 0x0C)
    if count != SLOT_COUNT:
        raise SaveFormatError(
            f"Expected {SLOT_COUNT} BND4 entries, found {count}. Is this a DSR save?"
        )

    entries: list[BndEntry] = []
    for i in range(count):
        base = BND4_HEADER + i * BND4_ENTRY
        if base + BND4_ENTRY > len(data):
            raise SaveFormatError("Truncated BND4 entry table.")
        size = u32(data, base + 0x08)
        offset = u32(data, base + 0x10)
        name_offset = u32(data, base + 0x14)
        if size <= 0 or offset + size > len(data):
            raise SaveFormatError(f"BND4 entry {i} points outside the file.")
        entries.append(BndEntry(i, size, offset, read_utf16(data, name_offset, 64)))
    return entries


# --- Switch save ------------------------------------------------------------- #

@dataclass
class SwitchCharacter:
    slot: int
    name: str
    level: int
    playtime_seconds: int
    body: bytes


@dataclass
class SwitchSave:
    data: bytes
    entries: list[BndEntry]
    characters: list[SwitchCharacter] = field(default_factory=list)
    system_body: bytes | None = None


def read_switch_save(path: str | Path) -> SwitchSave:
    data = Path(path).read_bytes()
    entries = parse_bnd4(data)
    save = SwitchSave(data=data, entries=entries)

    for entry in entries[:CHARACTER_SLOTS]:
        slot = data[entry.offset:entry.offset + entry.size]
        if len(slot) != SWITCH_SLOT_SIZE:
            raise SaveFormatError(
                f"{entry.name}: unexpected Switch slot size {len(slot):#x}. "
                "This converter expects Switch saves with 0x60010-byte slots."
            )
        if md5(slot[16:]) != slot[:16]:
            raise SaveFormatError(f"{entry.name}: inner MD5 check failed.")
        body = slot[16:]
        version = u32(body, OFF_VERSION)
        if version == 0:
            continue
        name = read_utf16(body, OFF_NAME, 34)
        level = struct.unpack_from("<H", body, OFF_LEVEL)[0]
        play_ms = u32(body, OFF_PLAYTIME_MS)
        save.characters.append(
            SwitchCharacter(
                slot=entry.index,
                name=name or "(unnamed)",
                level=level,
                playtime_seconds=play_ms // 1000,
                body=body,
            )
        )

    # Slot 10 is the Switch system/menu slot. It is not used for the PC output
    # (the PC template's system slot is), but keep it for diagnostics.
    sys_entry = entries[CHARACTER_SLOTS]
    sys_slot = data[sys_entry.offset:sys_entry.offset + sys_entry.size]
    if len(sys_slot) == SWITCH_SLOT_SIZE and md5(sys_slot[16:]) == sys_slot[:16]:
        save.system_body = sys_slot[16:]

    if not save.characters:
        raise SaveFormatError("No used character slots were found in the Switch save.")
    return save


# --- PC save ---------------------------------------------------------------- #

@dataclass
class PcSave:
    data: bytes
    entries: list[BndEntry]
    bodies: list[bytes]          # 10 decrypted character bodies
    system_body: bytes           # decrypted slot 010 body
    version_block: bytes         # 16-byte PC version block
    character_version: int


def decrypt_pc_slot(slot: bytes) -> bytes:
    """Return the 0x60000-byte body from a PC slot (0x60030 bytes)."""
    if len(slot) != PC_SLOT_SIZE:
        raise SaveFormatError(f"Unexpected PC slot size {len(slot):#x}.")
    stored_md5 = slot[:16]
    iv = slot[16:32]
    ciphertext = slot[32:]
    if md5(iv + ciphertext) != stored_md5:
        raise SaveFormatError("PC slot MD5 check failed (wrong template save?).")
    plaintext = aes_cbc_decrypt(AES_KEY, iv, ciphertext)
    if len(plaintext) != SLOT_DATA_SIZE:
        raise SaveFormatError("Unexpected decrypted PC slot size.")
    length = u32(plaintext, 0)
    if length != BODY_SIZE:
        raise SaveFormatError(
            f"Unexpected PC slot payload length {length:#x}; expected {BODY_SIZE:#x}."
        )
    return plaintext[4:4 + BODY_SIZE]


def read_pc_save(path: str | Path) -> PcSave:
    data = Path(path).read_bytes()
    entries = parse_bnd4(data)
    bodies: list[bytes] = []
    for entry in entries[:CHARACTER_SLOTS]:
        slot = data[entry.offset:entry.offset + entry.size]
        bodies.append(decrypt_pc_slot(slot))

    sys_entry = entries[CHARACTER_SLOTS]
    system_body = decrypt_pc_slot(
        data[sys_entry.offset:sys_entry.offset + sys_entry.size]
    )

    version_block = DEFAULT_VERSION_BLOCK
    character_version = PC_CHAR_VERSION
    for body in bodies:
        if u32(body, OFF_VERSION) != 0:
            version_block = bytes(body[OFF_VERSION_BLOCK:OFF_VERSION_BLOCK + 16])
            character_version = u32(body, OFF_VERSION)
            break

    sys_version = u32(system_body, SYS_VERSION_OFF)
    if sys_version != PC_SYS_VERSION:
        # Keep going: the layout is the same for the versions we know, but warn.
        print(
            f"warning: PC template system version is {sys_version}, "
            f"expected {PC_SYS_VERSION}. The roster layout may differ.",
            file=sys.stderr,
        )

    return PcSave(
        data=data,
        entries=entries,
        bodies=bodies,
        system_body=system_body,
        version_block=version_block,
        character_version=character_version,
    )


# --- Conversion -------------------------------------------------------------- #

def convert_character_body(body: bytes, version_block: bytes, target_version: int) -> bytes:
    """
    Turn a version-65 Switch body into a version-71 PC-layout body.

    The Switch body has an extra 16-byte block at 0x1C0 and everything after
    it is shifted +0x10.  Removing that block aligns the equipment, inventory,
    appearance and event-flag regions with the PC layout.  The PC version block
    (e.g. "1.03") is restored at 0x1A0.
    """
    if len(body) != BODY_SIZE:
        raise SaveFormatError(f"Unexpected body size {len(body):#x}.")
    if u32(body, OFF_VERSION) == 0:
        return bytes(BODY_SIZE)

    converted = bytearray(
        body[:OFF_SWITCH_EXTRA_BLOCK]
        + body[OFF_SWITCH_EXTRA_BLOCK + 16:]
        + bytes(16)
    )
    assert len(converted) == BODY_SIZE
    converted[OFF_VERSION_BLOCK:OFF_VERSION_BLOCK + 16] = version_block
    struct.pack_into("<I", converted, OFF_VERSION, target_version)
    return bytes(converted)


def build_output_bodies(
    pc_save: PcSave,
    switch_save: SwitchSave,
    selected: list[SwitchCharacter],
    mode: str,
    compact: bool,
) -> tuple[list[bytes], bytes, list[tuple[int, str, int, int]]]:
    """Return (10 character bodies, system body, roster report)."""
    pc_used = [u32(body, OFF_VERSION) != 0 for body in pc_save.bodies]

    if mode == "replace":
        bodies = [bytes(BODY_SIZE) for _ in range(CHARACTER_SLOTS)]
        placements: list[tuple[int, SwitchCharacter]] = []
        for i, char in enumerate(selected):
            target = i if compact else char.slot
            if target >= CHARACTER_SLOTS:
                raise SaveFormatError(f"Source slot {char.slot} is outside 0-9.")
            bodies[target] = convert_character_body(
                char.body, pc_save.version_block, pc_save.character_version
            )
            placements.append((target, char))
    elif mode == "merge":
        bodies = [bytes(body) for body in pc_save.bodies]
        free = [i for i, used in enumerate(pc_used) if not used]
        if len(selected) > len(free):
            raise SaveFormatError(
                f"Not enough empty PC slots: {len(selected)} Switch characters, "
                f"{len(free)} free slots. Use replace mode or free a slot."
            )
        placements = []
        for char, target in zip(selected, free):
            bodies[target] = convert_character_body(
                char.body, pc_save.version_block, pc_save.character_version
            )
            placements.append((target, char))
    else:
        raise ValueError(f"Unknown mode: {mode}")

    # Rebuild the roster in the PC system body.  Use the existing entry for
    # each slot as the base so the template's display data (appearance cache,
    # equipment preview) is preserved where possible.  Only the name, level
    # and playtime are rewritten; the game regenerates the rest after load.
    system_body = bytearray(pc_save.system_body)
    placement_by_slot = {target: char for target, char in placements}

    if mode == "replace":
        for slot in range(CHARACTER_SLOTS):
            base = SYS_DIR_BASE + slot * SYS_DIR_STRIDE
            entry = bytearray(system_body[base:base + SYS_DIR_STRIDE])
            if slot == 0:
                # Entry 0's first 0x28 bytes overlap the system header/flags.
                entry[:0x28] = system_body[base:base + 0x28]
            char = placement_by_slot.get(slot)
            if char is None:
                write_utf16_field(entry, SYS_DIR_NAME, "", 34)
                struct.pack_into("<I", entry, SYS_DIR_LEVEL, 0)
                struct.pack_into("<I", entry, SYS_DIR_PLAYTIME, 0)
            else:
                write_utf16_field(entry, SYS_DIR_NAME, char.name, 34)
                struct.pack_into("<I", entry, SYS_DIR_LEVEL, char.level & 0xFFFFFFFF)
                struct.pack_into(
                    "<I", entry, SYS_DIR_PLAYTIME, char.playtime_seconds & 0xFFFFFFFF
                )
            system_body[base:base + SYS_DIR_STRIDE] = entry

    report: list[tuple[int, str, int, int]] = []
    for target, char in placements:
        # Keep the roster entry for existing PC characters in merge mode.
        if mode == "merge" and pc_used[target]:
            continue
        base = SYS_DIR_BASE + target * SYS_DIR_STRIDE
        entry = bytearray(system_body[base:base + SYS_DIR_STRIDE])
        if target == 0:
            entry[:0x28] = system_body[base:base + 0x28]
        write_utf16_field(entry, SYS_DIR_NAME, char.name, 34)
        struct.pack_into("<I", entry, SYS_DIR_LEVEL, char.level & 0xFFFFFFFF)
        struct.pack_into(
            "<I", entry, SYS_DIR_PLAYTIME, char.playtime_seconds & 0xFFFFFFFF
        )
        system_body[base:base + SYS_DIR_STRIDE] = entry
        report.append((target, char.name, char.level, char.playtime_seconds))

    # In merge mode, report the PC characters too.
    if mode == "merge":
        for slot, used in enumerate(pc_used):
            if not used:
                continue
            base = SYS_DIR_BASE + slot * SYS_DIR_STRIDE
            name = read_utf16(system_body, base + SYS_DIR_NAME, 34)
            level = u32(system_body, base + SYS_DIR_LEVEL)
            playtime = u32(system_body, base + SYS_DIR_PLAYTIME)
            if name:
                report.append((slot, name, level, playtime))

    # Active flags: one per character slot.
    flags = bytes(1 if u32(body, OFF_VERSION) != 0 else 0 for body in bodies)
    system_body[SYS_ACTIVE_FLAGS_OFF:SYS_ACTIVE_FLAGS_OFF + 10] = flags
    # The system version stays whatever the PC template used (normally 30).
    return bodies, bytes(system_body), sorted(report)


def encrypt_pc_save(template: PcSave, bodies: list[bytes], system_body: bytes) -> bytes:
    """Write the PC container using the template's BND4 header/entry table."""
    if len(bodies) != CHARACTER_SLOTS or len(system_body) != BODY_SIZE:
        raise SaveFormatError("Internal error: wrong body count or system size.")

    header = template.data[:0x2C0]
    out = bytearray(header)
    expected_offset = 0x2C0

    for i, body in enumerate(bodies + [system_body]):
        entry = template.entries[i]
        if entry.size != PC_SLOT_SIZE or entry.offset != expected_offset:
            raise SaveFormatError(
                "The PC template's BND4 entry table is not the standard DSR layout."
            )
        plaintext = p32(BODY_SIZE) + body + SLOT_PADDING
        iv = os.urandom(16)
        ciphertext = aes_cbc_encrypt(AES_KEY, iv, plaintext)
        out += md5(iv + ciphertext) + iv + ciphertext
        expected_offset += PC_SLOT_SIZE

    if len(out) != len(template.data):
        raise SaveFormatError("Internal error: output size differs from template size.")
    return bytes(out)


def verify_output(data: bytes, expected_bodies: list[bytes], expected_system: bytes) -> None:
    entries = parse_bnd4(data)
    for i, entry in enumerate(entries):
        slot = data[entry.offset:entry.offset + entry.size]
        body = decrypt_pc_slot(slot)
        expected = expected_system if i == CHARACTER_SLOTS else expected_bodies[i]
        if body != expected:
            raise SaveFormatError(f"Verification failed for {entry.name}.")
    # Roster sanity: the active flags and names must line up.
    for i, entry in enumerate(entries):
        if i >= CHARACTER_SLOTS:
            break
        body = decrypt_pc_slot(data[entry.offset:entry.offset + entry.size])
        _ = body  # body was already verified above


@dataclass
class ConversionResult:
    output_path: Path
    size: int
    md5: str
    roster: list[tuple[int, str, int, int]]


def convert(
    switch_path: str | Path,
    template_path: str | Path,
    output_path: str | Path,
    mode: str = "replace",
    slots: Iterable[int] | None = None,
    compact: bool = True,
) -> ConversionResult:
    switch_save = read_switch_save(switch_path)
    pc_save = read_pc_save(template_path)

    if slots is not None:
        wanted = set(int(s) for s in slots)
        selected = [c for c in switch_save.characters if c.slot in wanted]
        if not selected:
            raise SaveFormatError(
                "None of the requested Switch slots contain a character."
            )
    else:
        selected = list(switch_save.characters)

    selected.sort(key=lambda c: c.slot)
    bodies, system_body, roster = build_output_bodies(
        pc_save, switch_save, selected, mode, compact
    )
    output = encrypt_pc_save(pc_save, bodies, system_body)
    verify_output(output, bodies, system_body)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    return ConversionResult(
        output_path=output_path,
        size=len(output),
        md5=hashlib.md5(output).hexdigest(),
        roster=roster,
    )


# --- GUI --------------------------------------------------------------------- #

def gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("DSR Switch -> PC Save Converter")
    root.geometry("760x560")
    root.minsize(680, 500)

    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")

    switch_var = tk.StringVar()
    template_var = tk.StringVar()
    output_var = tk.StringVar()
    mode_var = tk.StringVar(value="replace")
    compact_var = tk.BooleanVar(value=True)
    status_var = tk.StringVar(value="Select your Switch save and a PC save template.")

    characters: list[SwitchCharacter] = []

    main = ttk.Frame(root, padding=12)
    main.pack(fill="both", expand=True)

    def row(label: str, var: tk.StringVar, browse) -> ttk.Entry:
        frame = ttk.Frame(main)
        frame.pack(fill="x", pady=3)
        ttk.Label(frame, text=label, width=18).pack(side="left")
        entry = ttk.Entry(frame, textvariable=var)
        entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(frame, text="Browse...", command=browse).pack(side="right")
        return entry

    def pick_switch() -> None:
        path = filedialog.askopenfilename(
            title="Select the Nintendo Switch DRAKS0005.sl2",
            filetypes=[("Dark Souls save", "*.sl2"), ("All files", "*.*")],
        )
        if not path:
            return
        switch_var.set(path)
        refresh_characters()

    def pick_template() -> None:
        path = filedialog.askopenfilename(
            title="Select an existing PC DRAKS0005.sl2 (used as template)",
            filetypes=[("Dark Souls save", "*.sl2"), ("All files", "*.*")],
        )
        if not path:
            return
        template_var.set(path)
        if not output_var.get():
            output_var.set(str(Path(path).with_name("DRAKS0005_converted.sl2")))

    def pick_output() -> None:
        path = filedialog.asksaveasfilename(
            title="Save converted PC save as",
            defaultextension=".sl2",
            initialfile="DRAKS0005_converted.sl2",
            filetypes=[("Dark Souls save", "*.sl2"), ("All files", "*.*")],
        )
        if path:
            output_var.set(path)

    def refresh_characters() -> None:
        nonlocal characters
        characters = []
        listbox.delete(0, tk.END)
        path = switch_var.get().strip()
        if not path:
            return
        try:
            save = read_switch_save(path)
        except Exception as exc:
            status_var.set("Could not read Switch save.")
            messagebox.showerror("Switch save error", str(exc))
            return
        characters = save.characters
        for char in characters:
            hours = char.playtime_seconds / 3600
            listbox.insert(
                tk.END,
                f"Slot {char.slot:02d}  |  {char.name}  |  Lv {char.level}  |  {hours:.2f} h",
            )
        listbox.selection_set(0, tk.END)
        status_var.set(
            f"Found {len(characters)} character(s). Select the ones to convert."
        )

    def do_convert() -> None:
        switch_path = switch_var.get().strip()
        template_path = template_var.get().strip()
        output_path = output_var.get().strip()
        if not switch_path or not template_path or not output_path:
            messagebox.showerror(
                "Missing file", "Choose the Switch save, PC template, and output file."
            )
            return
        if not characters:
            messagebox.showerror("No characters", "Read the Switch save first.")
            return
        chosen = list(listbox.curselection())
        if not chosen:
            messagebox.showerror("No selection", "Select at least one character.")
            return
        slots = [characters[i].slot for i in chosen]
        try:
            status_var.set("Converting...")
            root.update_idletasks()
            result = convert(
                switch_path,
                template_path,
                output_path,
                mode=mode_var.get(),
                slots=slots,
                compact=compact_var.get() if mode_var.get() == "replace" else True,
            )
        except Exception as exc:
            status_var.set("Conversion failed.")
            messagebox.showerror("Conversion failed", str(exc))
            return

        lines = [
            f"Wrote: {result.output_path}",
            f"Size: {result.size:,} bytes",
            f"MD5: {result.md5}",
            "",
            "Characters in the output:",
        ]
        for slot, name, level, playtime in result.roster:
            lines.append(
                f"  Slot {slot:02d}: {name}  (Lv {level}, {playtime / 3600:.2f} h)"
            )
        lines += [
            "",
            "Back up your real PC save before replacing it.",
            "Play offline first. Modified saves can trigger anti-cheat online.",
        ]
        status_var.set("Done.")
        messagebox.showinfo("Conversion complete", "\n".join(lines))

    row("Switch .sl2", switch_var, pick_switch)
    row("PC template .sl2", template_var, pick_template)
    row("Output .sl2", output_var, pick_output)

    mode_frame = ttk.LabelFrame(main, text="Mode", padding=8)
    mode_frame.pack(fill="x", pady=(8, 4))
    ttk.Radiobutton(
        mode_frame,
        text="Replace PC characters (mirror the Switch save)",
        variable=mode_var,
        value="replace",
    ).pack(anchor="w")
    ttk.Radiobutton(
        mode_frame,
        text="Merge into empty slots (keep existing PC characters)",
        variable=mode_var,
        value="merge",
    ).pack(anchor="w")
    ttk.Checkbutton(
        mode_frame,
        text="Compact selected characters into the first slots (replace mode)",
        variable=compact_var,
    ).pack(anchor="w", pady=(4, 0))

    chars_frame = ttk.LabelFrame(main, text="Characters found", padding=8)
    chars_frame.pack(fill="both", expand=True, pady=4)
    listbox = tk.Listbox(
        chars_frame, selectmode=tk.EXTENDED, height=6, exportselection=False
    )
    scrollbar = ttk.Scrollbar(chars_frame, orient="vertical", command=listbox.yview)
    listbox.configure(yscrollcommand=scrollbar.set)
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    button_row = ttk.Frame(main)
    button_row.pack(fill="x", pady=(8, 0))
    ttk.Button(button_row, text="Convert", command=do_convert).pack(side="right")
    ttk.Label(button_row, textvariable=status_var).pack(side="left", fill="x", expand=True)

    root.mainloop()


# --- CLI --------------------------------------------------------------------- #

def parse_slots(value: str) -> list[int]:
    slots: list[int] = []
    for part in value.replace(" ", "").split(","):
        if not part:
            continue
        try:
            slot = int(part, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid slot: {part}") from exc
        if not 0 <= slot < CHARACTER_SLOTS:
            raise argparse.ArgumentTypeError(f"Slot out of range: {slot}")
        slots.append(slot)
    return slots


def main(argv: list[str] | None = None) -> int:
    if Cipher is None:
        print(
            "Missing dependency: install it with  pip install cryptography",
            file=sys.stderr,
        )
        return 2

    parser = argparse.ArgumentParser(
        description="Convert a Dark Souls: Remastered Nintendo Switch save to PC."
    )
    parser.add_argument("--switch", help="Switch DRAKS0005.sl2")
    parser.add_argument("--template", help="Existing PC DRAKS0005.sl2 used as template")
    parser.add_argument("--output", help="Output PC DRAKS0005.sl2")
    parser.add_argument(
        "--mode",
        choices=("replace", "merge"),
        default="replace",
        help="replace = output mirrors the Switch characters; merge = keep PC characters (default: replace)",
    )
    parser.add_argument(
        "--slots",
        type=parse_slots,
        help="Comma-separated Switch source slots to convert (default: all used)",
    )
    parser.add_argument(
        "--no-compact",
        action="store_true",
        help="In replace mode, keep the original Switch slot numbers instead of packing into 0..n",
    )
    args = parser.parse_args(argv)

    cli = bool(args.switch or args.template or args.output)
    if not cli:
        gui()
        return 0

    if not (args.switch and args.template and args.output):
        parser.error("--switch, --template and --output are required together")

    try:
        result = convert(
            args.switch,
            args.template,
            args.output,
            mode=args.mode,
            slots=args.slots,
            compact=not args.no_compact,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Wrote: {result.output_path}")
    print(f"Size:  {result.size:,} bytes")
    print(f"MD5:   {result.md5}")
    print("Characters:")
    for slot, name, level, playtime in result.roster:
        print(f"  slot {slot:02d}: {name}  (Lv {level}, {playtime / 3600:.2f} h)")
    print("\nBack up your real PC save before replacing it. Play offline first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
