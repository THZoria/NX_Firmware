#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import hashlib
import warnings
from struct import unpack, pack
from binascii import hexlify
from glob import glob
from shutil import rmtree
from subprocess import run, PIPE
from os import makedirs, remove
from os.path import basename, exists, join, abspath, dirname, getsize
from configparser import ConfigParser
from sys import argv
from zipfile import ZipFile, ZIP_STORED, ZipInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import HTTPError

try:
    from anynet import tls
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from tqdm import tqdm
except ImportError:
    print("Module(s) missing. Install with: pip install anynet cryptography requests tqdm")
    sys.exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
VERSION = argv[1] if len(argv) > 1 else ""

BASE_DIR = dirname(abspath(__file__))
KEYS_DIR = join(BASE_DIR, "keys")

def input_with_timeout(prompt, timeout=30):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    if os.name == 'nt':
        import msvcrt
        start_time = time.time()
        response = ""
        while time.time() - start_time < timeout:
            if msvcrt.kbhit():
                c = msvcrt.getch()
                if c in (b'\r', b'\n'):
                    sys.stdout.write('\n')
                    sys.stdout.flush()
                    return response
                elif c == b'\x08':
                    if len(response) > 0:
                        response = response[:-1]
                        sys.stdout.write('\b \b')
                        sys.stdout.flush()
                else:
                    try:
                        char = c.decode('utf-8')
                        response += char
                        sys.stdout.write(char)
                        sys.stdout.flush()
                    except UnicodeDecodeError:
                        pass
            time.sleep(0.05)
        sys.stdout.write("\n[Timeout reached. Defaulting to 'n']\n")
        sys.stdout.flush()
        return "n"
    else:
        import select
        i, o, e = select.select([sys.stdin], [], [], timeout)
        if i:
            return sys.stdin.readline().strip()
        else:
            sys.stdout.write("\n[Timeout reached. Defaulting to 'n']\n")
            sys.stdout.flush()
            return "n"

def readdata(f, addr, size):
    f.seek(addr)
    return f.read(size)

def utf8(s):
    return s.decode("utf-8")

def sha256(s):
    return hashlib.sha256(s).digest()

def readint(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<I", f.read(4))[0]

def readshort(f, addr=None):
    if addr is not None:
        f.seek(addr)
    return unpack("<H", f.read(2))[0]

def hexify(s):
    return hexlify(s).decode("utf-8")

def ihexify(n, b):
    return hex(n)[2:].zfill(b * 2)

def dlfile(url, out, user_agent, session=None):
    req_session = session or requests.Session()
    headers = {"User-Agent": user_agent}
    
    dlded = 0
    if exists(out):
        dlded = getsize(out)
        headers["Range"] = f"bytes={dlded}-"
    
    try:
        resp = req_session.get(
            url,
            cert=(join(KEYS_DIR, "switch_client.crt"), join(KEYS_DIR, "switch_client.key")),
            headers=headers,
            stream=True, 
            verify=False
        )
        
        if resp.status_code == 416:
            return
            
        resp.raise_for_status()
        
        if resp.status_code == 206:
            total_size = dlded + int(resp.headers.get('Content-Length', 0))
            mode = "ab"
        else:
            total_size = int(resp.headers.get('Content-Length', 0))
            mode = "wb"
            dlded = 0
            
        name = basename(out)
        chunk_size = 1024 * 1024
        
        with open(out, mode) as f:
            with tqdm(total=total_size, initial=dlded, unit='B', unit_scale=True, desc=f"Downloading {name}", leave=False) as pbar:
                for chunk in resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))
                        
    except Exception as e:
        print(f"\n[!] Error downloading {basename(out)}: {e}")
        raise

def dlfiles(dltable, user_agent):
    dl_tmp_path = join(BASE_DIR, "dl.tmp")
    with open(dl_tmp_path, "w") as f:
        for url, dirc, fname, fhash in dltable:
            f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            f"--certificate={join(KEYS_DIR, 'switch_client.crt')}",
            f"--private-key={join(KEYS_DIR, 'switch_client.key')}",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            "-x", "16", "-s", "16", "-i", dl_tmp_path
        ], check=True)
    except FileNotFoundError:
        print("aria2c not found. Using parallel requests fallback.")
        with requests.Session() as global_session:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = []
                for url, dirc, fname, fhash in dltable:
                    out_dir = join(BASE_DIR, dirc)
                    makedirs(out_dir, exist_ok=True)
                    out = join(out_dir, fname)
                    futures.append(executor.submit(dlfile, url, out, user_agent, global_session))
                for future in as_completed(futures):
                    future.result() 
    finally:
        try:
            remove(dl_tmp_path)
        except FileNotFoundError:
            pass

def nin_request(method, url, user_agent, headers=None, session=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    req_session = session or requests
    resp = req_session.request(
        method, url,
        cert=(join(KEYS_DIR, "switch_client.crt"), join(KEYS_DIR, "switch_client.key")),
        headers=headers, verify=False
    )
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    
    hactool_bin = "hactool.exe" if os.name == "nt" else "./hactool" 
    hactool_path = join(BASE_DIR, hactool_bin)
    cnmt_temp_dir = join(BASE_DIR, f"cnmt_tmp_{ncaf}")
    
    try:
        run([hactool_path, "-k", join(BASE_DIR, "prod.keys"), nca, "--section0dir", cnmt_temp_dir], stdout=PIPE, stderr=PIPE)
    except FileNotFoundError:
        print(f"\n[!] CRITICAL ERROR: '{hactool_bin}' not found in {BASE_DIR}.")
        sys.exit(1)
    
    try:
        extracted_files = glob(join(cnmt_temp_dir, "*.cnmt"))
        if not extracted_files:
            raise FileNotFoundError(f"Failed to extract CNMT from {ncaf}. Check prod.keys.")
            
        cnmt_file = extracted_files[0]
        entries = []
        with open(cnmt_file, "rb") as c:
            c_type = readdata(c, 0xc, 1)
            if c_type[0] == 0x3:
                n_entries = readshort(c, 0x12)
                offset    = readshort(c, 0xe)
                base = 0x20 + offset
                for i in range(n_entries):
                    c.seek(base + i*0x10)
                    title_id = unpack("<Q", c.read(8))[0]
                    version  = unpack("<I", c.read(4))[0]
                    entries.append((ihexify(title_id, 8), version))
            else:
                n_entries = readshort(c, 0x10)
                offset    = readshort(c, 0xe)
                base = 0x20 + offset
                for i in range(n_entries):
                    c.seek(base + i*0x38)
                    h      = c.read(32)
                    nid    = hexify(c.read(16))
                    c.seek(base + i*0x38 + 0x36)
                    entry_type = unpack("<B", c.read(1))[0]
                    entries.append((nid, hexify(h), entry_type))
        return entries
    finally:
        if exists(cnmt_temp_dir):
            rmtree(cnmt_temp_dir)

def zipdir(src_dir, out_zip):
    src_dir_path = join(BASE_DIR, src_dir)
    out_zip_path = join(BASE_DIR, out_zip)
    total_files = sum(len(files) for _, _, files in os.walk(src_dir_path))
    
    with ZipFile(out_zip_path, "w", compression=ZIP_STORED) as zf:
        with tqdm(total=total_files, unit='files', desc="Compressing ZIP") as pbar:
            for root, dirs, files in os.walk(src_dir_path):
                dirs.sort()
                for name in sorted(files):
                    full = os.path.join(root, name)
                    rel  = os.path.relpath(full, start=src_dir_path) 
                    os.utime(full, (1780315200, 1780315200))
                    zinfo = ZipInfo.from_file(full, arcname=rel)
                    zinfo.date_time = (2026, 1, 1, 0, 0, 0)
                    zinfo.create_system = 0
                    zinfo.external_attr = 0 
                    zinfo.compress_type = ZIP_STORED
                    with open(full, 'rb') as f:
                        zf.writestr(zinfo, f.read())
                    pbar.update(1)

class NSPRepacker:
    def __init__(self, out_path, file_map):
        self.path = out_path
        self.file_map = file_map
        self.sorted_files = []
        self.expected_total_size = 0
        
    def _sort_pfs0_order(self):
        order_list = []
        order_keys = ["tik", "cert", "meta_nca", 1, 3, 5, 4, 2]
        for key in order_keys:
            if key in self.file_map:
                items = self.file_map[key]
                if isinstance(items, list) and items:
                    order_list.extend(sorted(items, key=lambda x: basename(x)))
        self.sorted_files = order_list

    def repack(self):
        self._sort_pfs0_order()
        hd = self._gen_header()
        self.expected_total_size = len(hd) + sum(getsize(file) for file in self.sorted_files)
        
        if exists(self.path) and getsize(self.path) == self.expected_total_size:
            return self.path
            
        with open(self.path, 'wb') as outf:
            outf.write(hd)
            with tqdm(total=sum(getsize(f) for f in self.sorted_files), unit='B', unit_scale=True, desc="Repacking NSP", leave=False) as pbar:
                for file in self.sorted_files:
                    with open(file, 'rb') as inf:
                        while True:
                            buf = inf.read(4096 * 1024)
                            if not buf:
                                break
                            outf.write(buf)
                            pbar.update(len(buf))
                            
        return self.path

    def verify_integrity(self):
        try:
            with open(self.path, "rb") as f:
                magic = f.read(4)
                if magic != b'PFS0':
                    return False
                file_count = unpack('<I', f.read(4))[0]
                if file_count != len(self.sorted_files):
                    return False
                string_table_size = unpack('<I', f.read(4))[0]
                f.read(4)
                header_size = 0x10 + (file_count * 0x18) + string_table_size
                remainder = 0x10 - (header_size % 0x10)
                if remainder == 0x10: remainder = 0
                header_size += remainder
                
                for i in range(file_count):
                    offset = unpack('<Q', f.read(8))[0]
                    size = unpack('<Q', f.read(8))[0]
                    f.read(4)
                    f.read(4)
                    if (header_size + offset + size) > self.expected_total_size:
                        return False
                        
                f.seek(0, 2)
                actual_size = f.tell()
                if actual_size != self.expected_total_size:
                    return False
                    
            return True
        except Exception:
            return False
            
    def _gen_header(self):
        files_nb = len(self.sorted_files)
        string_table = b'\x00'.join(basename(file).encode('utf-8') for file in self.sorted_files) + b'\x00'
        header_size = 0x10 + files_nb * 0x18 + len(string_table)
        remainder = 0x10 - (header_size % 0x10)
        if remainder == 0x10: remainder = 0
        header_size += remainder
        
        file_sizes = [getsize(file) for file in self.sorted_files]
        file_offsets = [sum(file_sizes[:n]) for n in range(files_nb)]
        file_names_lengths = [len(basename(file).encode('utf-8')) + 1 for file in self.sorted_files]
        string_table_offsets = [sum(file_names_lengths[:n]) for n in range(files_nb)]
        
        header = b'PFS0'
        header += pack('<I', files_nb)
        header += pack('<I', len(string_table) + remainder)
        header += b'\x00\x00\x00\x00'
        for n in range(files_nb):
            header += pack('<Q', file_offsets[n])
            header += pack('<Q', file_sizes[n])
            header += pack('<I', string_table_offsets[n])
            header += b'\x00\x00\x00\x00'
        header += string_table
        header += remainder * b'\x00'
        return header

class FirmwareDownloader:
    def __init__(self, device_id: str, ver_string_simple: str):
        self.device_id = device_id
        self.ver_string_simple = ver_string_simple
        self.user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{self.device_id}; eid:{ENV})"
        self.ver_dir = f"Firmware {self.ver_string_simple}"
        
        self.update_files = []
        self.update_dls = []
        self.sv_nca_fat = ""
        self.sv_nca_exfat = ""
        self.seen_titles = set()
        self.queued_ncas = set()
        self.session = requests.Session()
        self.pfs0_map = {
            "tik": [], "cert": [], "meta_nca": [], "meta_xml": [],
            1: [], 2: [], 3: [], 4: [], 5: [], 6: []
        }

    def dltitle(self, title_id: str, version: int, is_su: bool = False):
        key = (title_id, version, is_su)
        if key in self.seen_titles:
            return
        self.seen_titles.add(key)

        p = "s" if is_su else "a"
        try:
            cnmt_id = nin_request(
                "HEAD",
                f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={self.device_id}",
                self.user_agent,
                session=self.session
            ).headers["X-Nintendo-Content-ID"]
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                print(f"INFO: Title {title_id} version {version} not found (404).")
                if title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = ""
                return
            raise

        full_ver_dir = join(BASE_DIR, self.ver_dir)
        makedirs(full_ver_dir, exist_ok=True)

        cnmt_nca = join(full_ver_dir, f"{cnmt_id}.cnmt.nca")
        self.update_files.append(cnmt_nca)
        self.pfs0_map["meta_nca"].append(cnmt_nca)
        
        dlfile(
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={self.device_id}",
            cnmt_nca,
            self.user_agent,
            session=self.session
        )

        if is_su:
            for t_id, ver in parse_cnmt(cnmt_nca):
                self.dltitle(t_id, ver)
        else:
            for nca_id, nca_hash, entry_type in parse_cnmt(cnmt_nca):
                if title_id.lower() == "0100000000000809":
                    self.sv_nca_fat = f"{nca_id}.nca"
                elif title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = f"{nca_id}.nca"

                if nca_id not in self.queued_ncas:
                    self.queued_ncas.add(nca_id)
                    nca_path = join(full_ver_dir, f"{nca_id}.nca")
                    self.update_files.append(nca_path)
                    if entry_type in self.pfs0_map:
                        self.pfs0_map[entry_type].append(nca_path)
                        
                    self.update_dls.append((
                        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={self.device_id}",
                        self.ver_dir,
                        f"{nca_id}.nca",
                        nca_hash
                    ))

    def run_downloads(self):
        dlfiles(self.update_dls, self.user_agent)

if __name__ == "__main__":
    cert_path = join(BASE_DIR, "certificat.pem")
    if not exists(cert_path):
        print(f"File 'certificat.pem' not found in {BASE_DIR}.")
        sys.exit(1)
        
    with open(cert_path, "rb") as f:
        pem_data = f.read()
        
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs(KEYS_DIR, exist_ok=True)
    cert.save(join(KEYS_DIR, "switch_client.crt"), tls.TYPE_PEM)
    priv.save(join(KEYS_DIR, "switch_client.key"), tls.TYPE_PEM)

    prod_keys_path = join(BASE_DIR, "prod.keys")
    if not exists(prod_keys_path):
        print(f"File 'prod.keys' not found in {BASE_DIR}.")
        sys.exit(1)
        
    prod_keys = ConfigParser(strict=False)
    with open(prod_keys_path) as f:
        prod_keys.read_string("[keys]\n" + f.read())

    prodinfo_path = join(BASE_DIR, "PRODINFO.bin")
    if not exists(prodinfo_path):
        print(f"File 'PRODINFO.bin' not found in {BASE_DIR}.")
        sys.exit(1)
        
    with open(prodinfo_path, "rb") as pf:
        prod_data = pf.read()

    if prod_data[:4] == b"CAL0":
        decrypted_prod = prod_data
    else:
        bis_key_00_hex = prod_keys.get("keys", "bis_key_00", fallback=None)
        if not bis_key_00_hex:
            print("PRODINFO is encrypted but bis_key_00 is missing from prod.keys!")
            sys.exit(1)
            
        bis_key_00 = bytes.fromhex(bis_key_00_hex.strip())
        sector_size = 0x4000
        decrypted_prod = bytearray()
        backend = default_backend()

        for i in range(0, len(prod_data), sector_size):
            chunk = prod_data[i:i+sector_size]
            if len(chunk) < 16:
                decrypted_prod += chunk
                continue
                
            tweak = (i // sector_size).to_bytes(16, 'little')
            cipher = Cipher(algorithms.AES(bis_key_00), modes.XTS(tweak), backend=backend)
            decryptor = cipher.decryptor()
            decrypted_prod += decryptor.update(chunk)
            
        decrypted_prod = bytes(decrypted_prod)

    if decrypted_prod[:4] != b"CAL0":
        print("Invalid PRODINFO (Decryption failed or invalid header)!")
        sys.exit(1)
        
    device_id = decrypted_prod[0x2b56 : 0x2b56 + 0x10].decode("utf-8").strip('\x00')
    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"
    base_session = requests.Session()

    if VERSION == "":
        print("INFO: No version specified, searching for the latest version...")
        su_meta = nin_request(
            "GET",
            f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}",
            user_agent,
            session=base_session
        ).json()
        ver_raw = su_meta["system_update_metas"][0]["title_version"]
        ver_major = ver_raw // 0x4000000
        ver_minor = (ver_raw - ver_major*0x4000000) // 0x100000
        ver_sub1  = (ver_raw - ver_major*0x4000000 - ver_minor*0x100000) // 0x10000
        ver_string_simple = f"{ver_major}.{ver_minor}.{ver_sub1}"
    else:
        ver_string_simple = VERSION
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3: parts.append(0) 
        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]

    downloader = FirmwareDownloader(device_id, ver_string_simple)
    v_n = ver_raw // 65536
    print(f"Downloading firmware. Internal version: {ver_raw} (v{v_n}). Folder: {downloader.ver_dir}")
    
    downloader.dltitle("0100000000000816", ver_raw, is_su=True)
    downloader.run_downloads()

    if not downloader.sv_nca_exfat:
        print("INFO: exFAT not found via meta — direct attempt 010000000000081b...")
        downloader.dltitle("010000000000081b", ver_raw, is_su=False)
        if downloader.sv_nca_exfat:
            downloader.run_downloads()
        else:
            print("INFO: No separate SystemVersion exFAT found for this firmware version.")

    failed = False
    for fpath in downloader.update_files:
        if not exists(fpath):
            print(f"DOWNLOAD FAILED: {fpath} missing")
            failed = True
    if failed:
        sys.exit(1)

    print("\nINFO: Starting detailed verification of NCA hashes...")
    hash_failed = False
    for url, dirc, fname, expected_hash in downloader.update_dls:
        fpath = join(BASE_DIR, dirc, fname)
        if exists(fpath):
            h = hashlib.sha256()
            with open(fpath, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    h.update(chunk)
            actual_hash = h.hexdigest()
            if actual_hash == expected_hash:
                print(f"[OK] {fname}")
                print(f"     -> Verified Hash: {actual_hash}")
            else:
                print(f"[ERROR] {fname}")
                print(f"        Expected : {expected_hash}")
                print(f"        Actual   : {actual_hash}")
                hash_failed = True
        else:
            print(f"[MISSING] {fname}")
            hash_failed = True

    if hash_failed:
        print("\nCRITICAL: Hash verification failed for one or more files. Archive will not be created.")
        sys.exit(1)
    else:
        print("\nINFO: All files successfully verified against CNMT records.")

    is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    
    out_zip = f"{downloader.ver_dir}.zip"
    out_zip_path = join(BASE_DIR, out_zip)
    if exists(out_zip_path):
        remove(out_zip_path)
    zipdir(downloader.ver_dir, out_zip)
    
    h = hashlib.sha256()
    with open(out_zip_path, "rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    zip_sha256 = h.hexdigest()

    if is_ci:
        choix_nsp = "y"
    else:
        choix_nsp = input_with_timeout("\nDo you want to pack the raw files into an NSP? [y/N]: ", 30).strip().lower()
        
    out_nsp = f"{downloader.ver_dir}.nsp"
    nsp_sha256 = ""
    repacker_success = False
    if choix_nsp in ['y', 'yes', 'true']:
        out_nsp_path = join(BASE_DIR, out_nsp)
        if exists(out_nsp_path):
            remove(out_nsp_path)
            
        repacker = NSPRepacker(out_nsp_path, downloader.pfs0_map)
        repacker.repack()
        
        if repacker.verify_integrity():
            repacker_success = True
            h = hashlib.sha256()
            with open(out_nsp_path, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    h.update(chunk)
            nsp_sha256 = h.hexdigest()

    print("\nDOWNLOAD COMPLETE!")
    if zip_sha256:
        print(f"Archive created: {out_zip}")
        print(f"SHA256: {zip_sha256}\n")
    print(f"SystemVersion NCA FAT: {downloader.sv_nca_fat or 'Not Found'}")
    print(f"SystemVersion NCA exFAT: {downloader.sv_nca_exfat or 'Not Found'}\n")
    print("Verify hashes before installation!")
    
    if repacker_success:
        if is_ci:
            print("\n<details>\n<summary>Click to view NSP details </summary>\n")
            print(f"NSP created: {out_nsp}")
            print(f"SHA256: {nsp_sha256}\n</details>")
        else:
            print(f"\nNSP created: {out_nsp}")
            print(f"SHA256: {nsp_sha256}")
    elif choix_nsp in ['y', 'yes', 'true']:
        if is_ci:
            print("\n<details>\n<summary>Click to view NSP details</summary>\n")
            print("Note: NSP compilation failed. Only the ZIP archive is provided.\n</details>")
        else:
            print("\nNote: NSP compilation failed. Only the ZIP archive is provided.")
