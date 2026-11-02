# DSR Switch → PC Save Converter

A small Windows tool that converts a **Dark Souls: Remastered** Nintendo Switch save
(`DRAKS0005.sl2`) into a PC save that the Steam/PC build can load.

It reads the Switch save, converts the character data layout and version stamps,
rebuilds the PC load-screen roster, and writes a normal PC-format `.sl2`.

> **Unofficial fan tool.** Not affiliated with FromSoftware, Bandai Namco, or Nintendo.
> Back up your saves. Use offline. Modified saves can trigger anti-cheat online.

---

## What it does

- Reads the Switch `.sl2` (BND4 container with plaintext entries).
- Extracts the character slots.
- Converts the Switch character layout (save version 65) to the PC layout
  (save version 71).
- Rebuilds the PC load-screen roster in slot `010` so the characters appear in
  the load menu.
- Re-encrypts every slot in the PC container format (AES-128-CBC + MD5).
- Writes a PC `.sl2` that is the same size as a normal PC save.

## Requirements

- Windows 10/11
- Python 3.9+ and the [`cryptography`](https://pypi.org/project/cryptography/) package
  **or** the prebuilt `.exe` from the Releases page.

## What you need

1. Your extracted Switch save: `DRAKS0005.sl2`.
2. An existing PC save to use as a **template**: `DRAKS0005.sl2`.
   - Launch Dark Souls: Remastered on PC once, create/use a character, and exit.
   - The tool uses the PC save's container header, system slot and version block.
   - Your existing PC characters can be kept with **Merge** mode.
3. A backup of both saves.

## Usage (GUI)

1. Run `DSR-Switch-to-PC.exe` (or `python dsr_switch_to_pc.py`).
2. Select the **Switch** save.
3. Select an existing **PC save** as the template.
4. Choose the output path.
5. Pick the characters to convert in the list (Ctrl-click to deselect).
6. Choose a mode:
   - **Replace PC characters** — the output mirrors the selected Switch characters.
     Slots are compacted into slot 0, 1, … so “Continue” loads the first one.
   - **Merge into empty slots** — keeps your existing PC characters and adds the
     Switch characters to free slots.
7. Click **Convert**.
8. Close Dark Souls, back up your real save, then copy the output over
   `%USERPROFILE%\Documents\NBGI\DARK SOULS REMASTERED\<SteamID>\DRAKS0005.sl2`.
9. Disable Steam Cloud for DSR while testing, and launch offline first.

## Usage (CLI)

```bat
python dsr_switch_to_pc.py ^
  --switch "DRAKS0005_switch.sl2" ^
  --template "DRAKS0005_pc.sl2" ^
  --output "DRAKS0005_converted.sl2" ^
  --mode replace ^
  --slots 1
```

Options:

| Option | Description |
|---|---|
| `--mode replace` | Output mirrors the selected Switch characters (default). |
| `--mode merge` | Keep existing PC characters, add Switch characters to empty slots. |
| `--slots 0,1` | Convert only these Switch source slots (default: all used). |
| `--no-compact` | In replace mode, keep original Switch slot numbers instead of packing into slots 0..n. |

## How it works

A Dark Souls: Remastered save is a BND4 archive with 11 entries:

- entries `000`–`009`: character slots
- entry `010`: system/menu data

**Switch entry**

```
[MD5 of plaintext 16][plaintext 0x60000]
```

**PC entry**

```
[MD5 of IV+ciphertext 16][IV 16][AES-128-CBC ciphertext 0x60010]
```

PC plaintext:

```
[u32 0x60000][body 0x60000][12 bytes of 0x0C padding]
```

The AES key is the known DSR key:

```
01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
```

The Switch build (save version **65**) places the fixed character fields
16 bytes later than the PC build (version **71**). The converter removes the
extra 16-byte block at body offset `0x1C0`, restores the PC version block at
`0x1A0`, and patches the version stamp.

The PC load-screen roster lives in slot `010`:

- active flags: `0xB0`, one byte per character slot
- 10 directory entries starting at `0x98`, stride `0x190`
- name at `+0x28` (UTF-16LE, 34 bytes)
- level at `+0x4C` (u32)
- playtime at `+0x50` (u32 seconds)

The tool uses the PC template's system slot as the base and rewrites only the
roster fields that need to change.

## Tested

Tested with a real Switch save (save version 65) and a PC save (version 71,
app 1.03.1). The converted level-178 character loaded in-game.

Other game versions/platform revisions may have different offsets. If the game
rejects a save, include the error and the version numbers in an issue.

## Warnings

- **Back up your saves.** The tool writes a new file, but you still have to
  replace your live save manually.
- **Play offline.** Dark Souls: Remastered uses Easy Anti-Cheat online.
  Modified saves can get an account soft-banned.
- **No account patching.** DSR saves do not store a Steam account ID, so none
  is needed.
- The Switch system/menu slot is not copied; the PC template's system slot is
  used. Character inventory, stats, appearance and world flags live in the
  character slot and are transferred.

## Build the Windows executable

```bat
build.bat
```

or manually:

```bat
py -m pip install -r requirements.txt pyinstaller
py -m PyInstaller --noconfirm --onefile --windowed ^
  --name DSR-Switch-to-PC dsr_switch_to_pc.py
```

The executable is written to `dist\DSR-Switch-to-PC.exe`.

## Credits

- The Dark Souls save-format community (BND4 / SL2 / AES layout).
- [Hapfel1/er-save-manager](https://github.com/Hapfel1/er-save-manager) for the
  documented DSR load-screen roster layout.
- [darthdemono/sl2-analyzer](https://github.com/darthdemono/sl2-analyzer) and
  [JKAnderson/SoulsFormats](https://github.com/JKAnderson/SoulsFormats) for
  format research.

## License

MIT. See [LICENSE](LICENSE). No game files or save data are included.
