#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import hashlib
import warnings
from struct import unpack
from binascii import hexlify
from glob import glob
from shutil import rmtree
from subprocess import run, PIPE
from os import makedirs, remove
from os.path import basename, exists, join
from configparser import ConfigParser
from sys import argv
from zipfile import ZipFile, ZIP_STORED, ZipInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Module(s) missing. Install with: pip install anynet cryptography requests")
    exit(1)

warnings.filterwarnings("ignore")

ENV     = "lp1"
VERSION = argv[1] if len(argv) > 1 else ""

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

def dlfile(url, out, user_agent):
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            f"--out={out}", "-c", url
        ], check=True, stdout=PIPE, stderr=PIPE)
    except FileNotFoundError:
        print(f"Downloading {basename(out)} via requests...")
        resp = request(
            "GET", url,
            cert=("keys/switch_client.crt", "keys/switch_client.key"),
            headers={"User-Agent": user_agent},
            stream=True, verify=False
        )
        resp.raise_for_status()
        with open(out, "wb") as f:
            for chunk in resp.iter_content(1024*1024):
                f.write(chunk)

def dlfiles(dltable, user_agent):
    with open("dl.tmp", "w") as f:
        for url, dirc, fname, fhash in dltable:
            f.write(f"{url}\n\tout={fname}\n\tdir={dirc}\n\tchecksum=sha-256={fhash}\n")
    try:
        run([
            "aria2c", "--no-conf", "--console-log-level=error",
            "--file-allocation=none", "--summary-interval=0",
            "--download-result=hide",
            "--certificate=keys/switch_client.crt",
            "--private-key=keys/switch_client.key",
            f"--header=User-Agent: {user_agent}",
            "--check-certificate=false",
            "-x", "16", "-s", "16", "-i", "dl.tmp"
        ], check=True)
    except FileNotFoundError:
        print("aria2c not found. Using parallel requests fallback (16 threads).")
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = []
            for url, dirc, fname, fhash in dltable:
                makedirs(dirc, exist_ok=True)
                out = join(dirc, fname)
                futures.append(executor.submit(dlfile, url, out, user_agent))
            
            for future in as_completed(futures):
                future.result() 
    finally:
        try:
            remove("dl.tmp")
        except FileNotFoundError:
            pass

def nin_request(method, url, user_agent, headers=None):
    if headers is None:
        headers = {}
    headers.update({"User-Agent": user_agent})
    resp = request(
        method, url,
        cert=("keys/switch_client.crt", "keys/switch_client.key"),
        headers=headers, verify=False
    )
    resp.raise_for_status()
    return resp

def parse_cnmt(nca):
    ncaf = basename(nca)
    
    hactool_bin = "hactool.exe" if os.name == "nt" else "./hactool" 
    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    
    try:
        run(
            [hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir],
            stdout=PIPE, stderr=PIPE
        )
    except FileNotFoundError:
        print(f"\n[!] CRITICAL ERROR: '{hactool_bin}' not found.")
        print("Please download hactool and place it in the same folder as this script.")
        exit(1)
    
    extracted_files = glob(f"{cnmt_temp_dir}/*.cnmt")
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
                entries.append((nid, hexify(h)))
    
    rmtree(cnmt_temp_dir)
    return entries

def zipdir(src_dir, out_zip):
    with ZipFile(out_zip, "w", compression=ZIP_STORED) as zf:
        for root, dirs, files in os.walk(src_dir):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                rel  = os.path.relpath(full, start=src_dir) 
                
                os.utime(full, (1780315200, 1780315200))
                
                zinfo = ZipInfo.from_file(full, arcname=rel)
                zinfo.date_time = (2026, 1, 1, 0, 0, 0)
                zinfo.create_system = 0
                zinfo.external_attr = 0 
                zinfo.compress_type = ZIP_STORED
                
                with open(full, 'rb') as f:
                    zf.writestr(zinfo, f.read())

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
                self.user_agent
            ).headers["X-Nintendo-Content-ID"]
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                print(f"INFO: Title {title_id} version {version} not found (404).")
                if title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = ""
                return
            raise

        makedirs(self.ver_dir, exist_ok=True)

        cnmt_nca = f"{self.ver_dir}/{cnmt_id}.cnmt.nca"
        self.update_files.append(cnmt_nca)
        dlfile(
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={self.device_id}",
            cnmt_nca,
            self.user_agent
        )

        if is_su:
            for t_id, ver in parse_cnmt(cnmt_nca):
                self.dltitle(t_id, ver)
        else:
            for nca_id, nca_hash in parse_cnmt(cnmt_nca):
                if title_id.lower() == "0100000000000809":
                    self.sv_nca_fat = f"{nca_id}.nca"
                elif title_id.lower() == "010000000000081b":
                    self.sv_nca_exfat = f"{nca_id}.nca"

                if nca_id not in self.queued_ncas:
                    self.queued_ncas.add(nca_id)
                    self.update_files.append(f"{self.ver_dir}/{nca_id}.nca")
                    self.update_dls.append((
                        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={self.device_id}",
                        self.ver_dir,
                        f"{nca_id}.nca",
                        nca_hash
                    ))

    def run_downloads(self):
        dlfiles(self.update_dls, self.user_agent)

if __name__ == "__main__":
    if not exists("certificat.pem"):
        print("File 'certificat.pem' not found in root directory.")
        exit(1)
        
    pem_data = open("certificat.pem", "rb").read()
    cert = tls.TLSCertificate.parse(pem_data, tls.TYPE_PEM)
    priv = tls.TLSPrivateKey.parse(pem_data, tls.TYPE_PEM)
    makedirs("keys", exist_ok=True)
    cert.save("keys/switch_client.crt", tls.TYPE_PEM)
    priv.save("keys/switch_client.key", tls.TYPE_PEM)

    if not exists("prod.keys"):
        print("File 'prod.keys' not found in root directory.")
        exit(1)
        
    prod_keys = ConfigParser(strict=False)
    with open("prod.keys") as f:
        prod_keys.read_string("[keys]\n" + f.read())

    if not exists("PRODINFO.bin"):
        print("File 'PRODINFO.bin' not found in root directory.")
        exit(1)
        
    with open("PRODINFO.bin", "rb") as pf:
        prod_data = pf.read()

    if prod_data[:4] == b"CAL0":
        decrypted_prod = prod_data
    else:
        bis_key_00_hex = prod_keys.get("keys", "bis_key_00", fallback=None)
        if not bis_key_00_hex:
            print("PRODINFO is encrypted but bis_key_00 is missing from prod.keys!")
            exit(1)
            
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
        exit(1)
        
    device_id = decrypted_prod[0x2b56 : 0x2b56 + 0x10].decode("utf-8").strip('\x00')
    print(f"Device ID: {device_id}")

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"

    if VERSION == "":
        print("INFO: No version specified, searching for the latest version...")
        su_meta = nin_request(
            "GET",
            f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}",
            user_agent
        ).json()
        ver_raw = su_meta["system_update_metas"][0]["title_version"]
        
        ver_major = ver_raw // 0x4000000
        ver_minor = (ver_raw - ver_major*0x4000000) // 0x100000
        ver_sub1  = (ver_raw - ver_major*0x4000000 - ver_minor*0x100000) // 0x10000
        ver_sub2  = ver_raw - ver_major*0x4000000 - ver_minor*0x100000 - ver_sub1*0x10000
        
        ver_string_raw = f"{ver_major}.{ver_minor}.{ver_sub1}.{str(ver_sub2).zfill(4)}"
        ver_string_simple = f"{ver_major}.{ver_minor}.{ver_sub1}"
    else:
        ver_string_simple = VERSION
        
        parts = list(map(int, VERSION.split(".")))
        if len(parts) == 3:
             parts.append(0) 

        ver_raw = parts[0]*0x4000000 + parts[1]*0x100000 + parts[2]*0x10000 + parts[3]
        ver_string_raw = f"{parts[0]}.{parts[1]}.{parts[2]}.{str(parts[3]).zfill(4)}"

    downloader = FirmwareDownloader(device_id, ver_string_simple)
    
    print(f"Downloading firmware. Internal version: {ver_string_raw}. Folder: {downloader.ver_dir}")

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
        exit(1)

    print("\nINFO: Starting detailed verification of NCA hashes...")
            
    hash_failed = False
    for url, dirc, fname, expected_hash in downloader.update_dls:
        fpath = join(dirc, fname)
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
        exit(1)
    else:
        print("\nINFO: All files successfully verified against CNMT records.")

    out_zip = f"{downloader.ver_dir}.zip" 
    if exists(out_zip):
        remove(out_zip)
    zipdir(downloader.ver_dir, out_zip)

    h = hashlib.sha256()
    with open(out_zip, "rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    zip_sha256 = h.hexdigest()

    print("\nDOWNLOAD COMPLETE!")
    print(f"Archive created: {out_zip}")
    print(f"SystemVersion NCA FAT: {downloader.sv_nca_fat or 'Not Found'}")
    print(f"SystemVersion NCA exFAT: {downloader.sv_nca_exfat or 'Not Found'}")
    print(f"Archive SHA256: {zip_sha256}")
    print("Verify hashes before installation!")
