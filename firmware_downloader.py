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
from zipfile import ZipFile, ZIP_DEFLATED 

from requests import request
from requests.exceptions import HTTPError

try:
    from anynet import tls
except ImportError:
    print("Module 'anynet' not found. Install it with: pip install anynet")
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

def dlfile(url, out):
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
        ], check=True)
    except FileNotFoundError:
        print(f"downloading {basename(out)} via requests")
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

def dlfiles(dltable):
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
        for url, dirc, fname, fhash in dltable:
            makedirs(dirc, exist_ok=True)
            out = join(dirc, fname)
            dlfile(url, out)
    finally:
        try:
            remove("dl.tmp")
        except FileNotFoundError:
            pass

def nin_request(method, url, headers=None):
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
    
    # --- MODIFICATION CLÉ ---
    # Force l'utilisation de l'exécutable hactool dans le répertoire courant.
    # Dans le workflow, hactool-linux a été renommé en hactool et rendu exécutable.
    hactool_bin = "hactool.exe" if os.name == "nt" else "./hactool" 
    # -----------------------
    
    cnmt_temp_dir = f"cnmt_tmp_{ncaf}"
    
    # Le script tente de lancer './hactool'
    run(
        [hactool_bin, "-k", "prod.keys", nca, "--section0dir", cnmt_temp_dir],
        stdout=PIPE, stderr=PIPE
    )
    
    cnmt_file = glob(f"{cnmt_temp_dir}/*.cnmt")[0]
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

seen_titles = set()
queued_ncas = set()

def dltitle(title_id, version, is_su=False):
    global update_files, update_dls, sv_nca_fat, sv_nca_exfat, seen_titles, queued_ncas, ver_string_simple

    key = (title_id, version, is_su)
    if key in seen_titles:
        return
    seen_titles.add(key)

    p = "s" if is_su else "a"
    try:
        cnmt_id = nin_request(
            "HEAD",
            f"https://atumn.hac.{ENV}.d4c.nintendo.net/t/{p}/{title_id}/{version}?device_id={device_id}"
        ).headers["X-Nintendo-Content-ID"]
    except HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            print(f"INFO: Title {title_id} version {version} not found (404).")
            if title_id == "010000000000081B":
                sv_nca_exfat = ""
            return
        raise

    ver_dir = f"Firmware {ver_string_simple}"
    makedirs(ver_dir, exist_ok=True)

    cnmt_nca = f"{ver_dir}/{cnmt_id}.cnmt.nca"
    update_files.append(cnmt_nca)
    dlfile(
        f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/{p}/{cnmt_id}?device_id={device_id}",
        cnmt_nca
    )

    if is_su:
        for t_id, ver in parse_cnmt(cnmt_nca):
            dltitle(t_id, ver)
    else:
        for nca_id, nca_hash in parse_cnmt(cnmt_nca):
            if title_id == "0100000000000809":
                sv_nca_fat = f"{nca_id}.nca"
            elif title_id == "010000000000081B":
                sv_nca_exfat = f"{nca_id}.nca"

            if nca_id not in queued_ncas:
                queued_ncas.add(nca_id)
                update_files.append(f"{ver_dir}/{nca_id}.nca")
                update_dls.append((
                    f"https://atumn.hac.{ENV}.d4c.nintendo.net/c/c/{nca_id}?device_id={device_id}",
                    ver_dir,
                    f"{nca_id}.nca",
                    nca_hash
                ))

def zipdir(src_dir, out_zip):
    with ZipFile(out_zip, "w", compression=ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(src_dir):
            for name in files:
                full = os.path.join(root, name)
                rel  = os.path.relpath(full, start=src_dir) 
                zf.write(full, arcname=rel)

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
        prod_keys.read_string("[keys]" + f.read())

    if not exists("PRODINFO.bin"):
        print("File 'PRODINFO.bin' not found in root directory.")
        exit(1)
        
    with open("PRODINFO.bin", "rb") as pf:
        if pf.read(4) != b"CAL0":
            print("Invalid PRODINFO (invalid header)!")
            exit(1)
        device_id = utf8(readdata(pf, 0x2b56, 0x10))
        print("Device ID:", device_id)

    user_agent = f"NintendoSDK Firmware/11.0.0-0 (platform:NX; did:{device_id}; eid:{ENV})"

    if VERSION == "":
        print("INFO: No version specified, searching for the latest version...")
        su_meta = nin_request(
            "GET",
            f"https://sun.hac.{ENV}.d4c.nintendo.net/v1/system_update_meta?device_id={device_id}"
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

    ver_dir = f"Firmware {ver_string_simple}"
    print(f"Downloading firmware. Internal version: {ver_string_raw}. Folder: {ver_dir}")

    update_files = []
    update_dls   = []
    sv_nca_fat   = ""
    sv_nca_exfat = ""

    seen_titles.clear()
    queued_ncas.clear()

    dltitle("0100000000000816", ver_raw, is_su=True)
    dlfiles(update_dls)

    if not sv_nca_exfat:
        print("INFO: exFAT not found via meta — direct attempt 010000000000081B…")
        dltitle("010000000000081B", ver_raw, is_su=False)
        if sv_nca_exfat:
            dlfiles(update_dls)
        else:
            print("INFO: No separate SystemVersion exFAT found for this firmware version.")

    failed = False
    for fpath in update_files:
        if not exists(fpath):
            print(f"DOWNLOAD FAILED: {fpath} missing")
            failed = True
    if failed:
        exit(1)

    out_zip = f"{ver_dir}.zip" 
    if exists(out_zip):
        remove(out_zip)
    zipdir(ver_dir, out_zip)

    print("\nDOWNLOAD COMPLETE!")
    print(f"Archive created: {out_zip}")
    print(f"SystemVersion NCA FAT: {sv_nca_fat or 'Not Found'}")
    print(f"SystemVersion NCA exFAT: {sv_nca_exfat or 'Not Found'}")
    print("Verify hashes before installation!")