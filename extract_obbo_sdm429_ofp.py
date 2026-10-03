import os
import sys
import hashlib
import xml.etree.ElementTree as ET
from struct import unpack
from Crypto.Cipher import AES
KEY_SETS = [
    ("V2.0.3",
     "E8AE288C0192C54BF10C5707E9C4705B",
     "D64FC385DCD52A3C9B5FBA8650F92EDA",
     "79051FD8D8B6297E2E4559E997F63B7F"),
    ("V2.1.x",
     "D4D2CD61D4D2CD61D4D2CD61D4D2CD61",
     "D4D2CD61D4D2CD61D4D2CD61D4D2CD61",
     "D4D2CD61D4D2CD61D4D2CD61D4D2CD61"),
    ("V1.4.17/1.4.27",
     "27827963787265EF89D126B69A495A21",
     "82C50203285A2CE7D8C3E198383CE94C",
     "422DD5399181E223813CD8ECDF2E4D72"),
    ("V1.6.17",
     "E11AA7BB558A436A8375FD15DDD4651F",
     "77DDF6A0696841F6B74782C097835169",
     "A739742384A44E8BA45207AD5C3700EA"),
    ("V1.5.13",
     "67657963787565E837D226B69A495D21",
     "F6C50203515A2CE7D8C3E1F938B7E94C",
     "42F2D5399137E2B2813CD8ECDF2F4D72"),
    ("V1.6.6+",
     "3C2D518D9BF2E4279DC758CD535147C3",
     "87C74A29709AC1BF2382276C4E8DF232",
     "598D92E967265E9BCABE2469FE4A915E"),
    ("V1.7.2",
     "8FB8FB261930260BE945B841AEFA9FD4",
     "E529E82B28F5A2F8831D860AE39E425D",
     "8A09DA60ED36F125D64709973372C1CF"),
]


def ROL(x, n, bits=8):
    n = bits - n
    mask = (2 ** n) - 1
    return (x >> n) | ((x & mask) << (bits - n))


def deobfuscate(data, mask):
    return bytes(ROL(b ^ m, 4, 8) for b, m in zip(data, mask))


def aes_cfb(data, key, iv):
    return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(data)


def find_key(filename):
    fsize = os.stat(filename).st_size
    with open(filename, "rb") as rf:
        pagesize = 0
        for x in (0x200, 0x1000):
            rf.seek(fsize - x + 0x10)
            if unpack("<I", rf.read(4))[0] == 0x7CEF:
                pagesize = x
                break
        if not pagesize:
            print("[!] 未找到 OFP 页表标记(0x7CEF)")
            return None, None, None, None, None
        xmloffset = fsize - pagesize
        rf.seek(xmloffset + 0x14)
        offset = unpack("<I", rf.read(4))[0] * pagesize
        length = unpack("<I", rf.read(4))[0]
        if length < 200:
            length = xmloffset - offset - 0x57
        rf.seek(offset)
        data = rf.read(length)
        for name, mc, uk, iv in KEY_SETS:
            mc_b = bytes.fromhex(mc)
            key = hashlib.md5(deobfuscate(bytes.fromhex(uk), mc_b)).hexdigest()[:16].encode()
            iv_b = hashlib.md5(deobfuscate(bytes.fromhex(iv), mc_b)).hexdigest()[:16].encode()
            dec = aes_cfb(data, key, iv_b)
            if b"<?xml" in dec:
                print(f"[+] key version {name} 匹配成功")
                return pagesize, key, iv_b, dec, fsize
    print("[!] unknow package！")
    return None, None, None, None, None


def copy_data(rf, wf, start, length):
    rf.seek(start)
    while length > 0:
        size = min(length, 0x100000)
        wf.write(rf.read(size))
        length -= size


def main():
    if len(sys.argv) < 2:
        print("用法: py ofp_extract.py <xxx.ofp> [输出目录]")
        return 1
    filename = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(filename)),
        "_" + os.path.splitext(os.path.basename(filename))[0])

    pagesize, key, iv, xml_data, fsize = find_key(filename)
    if pagesize is None:
        return 1

    xml_text = xml_data[:xml_data.rfind(b">") + 1].decode("utf-8")
    root = ET.fromstring(xml_text)

    os.makedirs(outdir, exist_ok=True)
    xml_path = os.path.join(outdir, "ProFile.xml")
    with open(xml_path, "w", encoding="utf-8") as fh:
        fh.write(xml_text)
    print(f"[+] ProFile.xml 已保存 -> {xml_path}")

    total_entries = 0
    done = set()

    def extract_item(item, tag, rf):
        nonlocal total_entries
        if "Path" in item.attrib:
            wfilename = item.attrib["Path"]
        elif "filename" in item.attrib:
            wfilename = item.attrib["filename"]
        else:
            return
        if not wfilename:
            return
        if "FileOffsetInSrc" in item.attrib:
            start = int(item.attrib["FileOffsetInSrc"]) * pagesize
        elif "SizeInSectorInSrc" in item.attrib:
            start = int(item.attrib["SizeInSectorInSrc"]) * pagesize
        else:
            return
        rlength = int(item.attrib.get("SizeInByteInSrc", "0") or "0")
        if rlength <= 0 or start + rlength > fsize:
            return
        if wfilename in done:
            return
        done.add(wfilename)
        total_entries += 1
        outpath = os.path.join(outdir, wfilename)
        decryptsize = 0x40000
        is_copy = tag in ("DigestsToSign", "ChainedTableOfDigests", "Firmware")
        if tag == "Sahara":
            decryptsize = rlength
        print(f"  [{tag}] {wfilename}  ({rlength} bytes)")
        with open(outpath, "wb") as wf:
            if is_copy:
                copy_data(rf, wf, start, rlength)
            else:
                size = min(decryptsize, rlength)
                rf.seek(start)
                data = rf.read(size)
                if size % 4:
                    data += b"\x00" * (4 - size % 4)
                wf.write(aes_cfb(data, key, iv)[:size])
                if rlength > size:
                    copy_data(rf, wf, start + size, rlength - size)

    with open(filename, "rb") as rf:
        for child in root:
            for item in child:
                if "Path" not in item.attrib and "filename" not in item.attrib:
                    for subitem in item:
                        extract_item(subitem, child.tag, rf)
                extract_item(item, child.tag, rf)

    print(f"\n[complete!] The ofp firmware have {total_entries} files -> {outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())