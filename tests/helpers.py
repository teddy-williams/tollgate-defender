"""Builds tiny, harmless PE32 files in memory so tests need no real samples."""
import struct

CODE = 0x60000020   # code | execute | read
DATA = 0xC0000040   # initialized data | read | write
RWX = 0xE0000020    # code | execute | read | write


def build_pe(sections, entry_section=0, timestamp=0x5F000000, overlay=b""):
    """sections: list of (name, data_bytes, characteristics)."""
    file_align, sec_align, headers_size = 0x200, 0x1000, 0x200
    raw_ptr, va = headers_size, 0x1000
    hdrs, blobs, entries = b"", b"", []
    for name, data, chars in sections:
        raw_size = (len(data) + file_align - 1) // file_align * file_align if data else 0
        vsize = max(len(data), 0x1000 if not data else 1)
        hdrs += struct.pack(
            "<8sIIIIIIHHI", name.encode()[:8].ljust(8, b"\0"), vsize, va, raw_size,
            raw_ptr if raw_size else 0, 0, 0, 0, 0, chars)
        blobs += data.ljust(raw_size, b"\0")
        entries.append(va)
        raw_ptr += raw_size
        va += (vsize + sec_align - 1) // sec_align * sec_align
    opt = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, 0, 0, 0, entries[entry_section], 0x1000, 0, 0x400000, sec_align, file_align,
        4, 0, 0, 0, 4, 0, 0, va, headers_size, 0, 3, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    coff = struct.pack("<HHIIIHH", 0x14C, len(sections), timestamp, 0, 0, 0xE0, 0x0102)
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    header = dos + b"PE\0\0" + coff + opt + b"\0" * 128 + hdrs
    return header.ljust(headers_size, b"\0") + blobs + overlay


# ---------------------------------------------------------------- LNK builder (synthetic, harmless)
import uuid as _uuid

_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")


def _u16str(text):
    return struct.pack("<H", len(text)) + text.encode("utf-16le")


def build_lnk(target=None, args=None, icon=None, relative=None, workdir=None, name=None, show=1, machine=None,
              mac=None, trailing=b"", zero_times=False, unc=None, runas=False, env_target=None, idlist=None):
    """Build a structurally valid .lnk. `idlist` is a list like ['C:\\', 'Windows', 'cmd.exe']."""
    flags = 0x80                                              # IsUnicode
    parts = b""
    if idlist:
        flags |= 0x01
        items = b""
        for n, label in enumerate(idlist):
            if n == 0:
                item = b"\x2f" + label.encode() + b"\x00" * 19
            else:
                item = b"\x31\x00" + struct.pack("<IIH", 0, 0, 0x10) + label.encode() + b"\x00\x00"
            items += struct.pack("<H", len(item) + 2) + item
        parts += struct.pack("<H", len(items) + 2) + items + struct.pack("<H", 0)
    if target or unc:
        flags |= 0x02
        vol = struct.pack("<IIII", 0x11, 3, 0x12345678, 0x10) + b"\x00"
        if unc:
            netname = unc.rsplit("\\", 1)[0].encode() if unc.count("\\") > 3 else unc.encode()
            net = struct.pack("<IIIII", 0x14 + len(netname) + 1, 0, 0x14, 0, 0) + netname + b"\x00"
            suffix = unc[len(netname) + 1:].encode() if len(unc) > len(netname) else b""
            li_flags, vol_off, base_off, net_off = 2, 0, 0, 0x1C
            body = net + suffix + b"\x00"
            suffix_off = 0x1C + len(net)
        else:
            base = target.encode()
            li_flags, vol_off, base_off, net_off = 1, 0x1C, 0x1C + len(vol), 0
            body = vol + base + b"\x00" + b"\x00"
            suffix_off = base_off + len(base) + 1
        li = struct.pack("<IIIIIII", 0x1C + len(body), 0x1C, li_flags, vol_off, base_off, net_off, suffix_off) + body
        parts += li
    for bit, val in ((2, name), (3, relative), (4, workdir), (5, args), (6, icon)):
        if val is not None:
            flags |= 1 << bit
            parts += _u16str(val)
    if runas:
        flags |= 1 << 13
    extra = b""
    if env_target:
        ansi = env_target.encode().ljust(260, b"\x00")
        uni = env_target.encode("utf-16le").ljust(520, b"\x00")
        extra += struct.pack("<II", 0x314, 0xA0000001) + ansi + uni
    if machine or mac:
        node = int((mac or "aa:bb:cc:dd:ee:ff").replace(":", ""), 16)
        guid = _uuid.uuid1(node=node).bytes_le
        extra += struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + (machine or "WORKSTATION").encode().ljust(16, b"\x00") \
            + b"\x00" * 16 + guid + b"\x00" * 16 + guid
    extra += struct.pack("<I", 0)
    ft = 0 if zero_times else 133000000000000000
    header = struct.pack("<I16sIIQQQIiIH10s", 0x4C, _LNK_CLSID, flags, 0x20, ft, ft, ft, 0, 0, show, 0, b"\x00" * 10)
    return header + parts + extra + trailing


# ---------------------------------------------------------------- PDF builder (synthetic, harmless)
import zlib as _zlib


def pdf_stream(extra=b"", data=b"", flate=True, filters=None):
    """Return the body of a stream object."""
    if filters is None:
        filters = [b"/FlateDecode"] if flate else []
    payload = _zlib.compress(data) if flate else data
    flt = b" /Filter [" + b" ".join(filters) + b"]" if filters else b""
    return b"<< " + extra + flt + b" /Length " + str(len(payload)).encode() + b" >>\nstream\n" + payload + b"\nendstream"


def build_pdf(objects, header=b"%PDF-1.7\n", suffix=b"", eof=True, root=1):
    """objects: {num: body bytes}. Adds a trivial xref/trailer; no real offsets are needed by the analyzer."""
    out = bytearray(header)
    for num, body in objects.items():
        out += str(num).encode() + b" 0 obj\n" + body + b"\nendobj\n"
    out += b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Root " + str(root).encode() + b" 0 R /Size " + str(len(objects) + 1).encode() + b" >>\nstartxref\n0\n"
    if eof:
        out += b"%%EOF\n"
    return bytes(out) + suffix


def benign_pdf():
    return build_pdf({
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
        4: pdf_stream(data=b"BT /F1 12 Tf (Hello) Tj ET"),
        5: b"<< /Producer (Test Producer) /Title (Hello) >>",
    })
