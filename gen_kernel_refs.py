#!/usr/bin/env python3
"""gen_kernel_refs.py - ONE script that builds the "known kernels" reference lists
used by   av.sh --offline-root PATH -K   for every supported distribution.

  ./gen_kernel_refs.py                      # everything, files go to ./signatures/kernel_refs/
  ./gen_kernel_refs.py -o /root/av/signatures/kernel_refs
  ./gen_kernel_refs.py --only ubuntu,alma   # just some families
  ./gen_kernel_refs.py --list               # show what would be read, download nothing

Families (one output file each):  ubuntu  debian  alma  rocky  centos
The script knows the official mirrors and, for the RPM families, finds the
"vault" (older minor releases) by itself. A repository that is unreachable or
changed its layout only produces a warning; the others continue.
Re-running is incremental: kernels that are already in the output file are not
downloaded again, so a monthly refresh takes seconds.

How it works: no kernel is downloaded. Every package records the digest of the
files it contains in its metadata, and that metadata sits at the very START of
the package file, so only the first 128 KB (deb) / 2 MB (rpm) are fetched:
  deb  - control.tar -> md5sums: md5 of boot/vmlinuz-<ver>
  rpm  - header: sha256 (md5 on CentOS 7) of /lib/modules/<ver>/vmlinuz
         (kernel-core, EL8+; /boot/vmlinuz-<ver> is only a %ghost copy there)
         or /boot/vmlinuz-<ver> (kernel, EL7)
Output TSV: hash <TAB> vmlinuz-<ver> <TAB> package <TAB> version <TAB> source
(hash = md5 [32 hex] or sha256 [64 hex]; av.sh tells them apart by length)

Needs only Python 3.8+ and network access. zstd-compressed packages/repodata
need the `zstandard` module (pip install zstandard) or the `zstd` binary.
"""
import argparse, bz2, gzip, io, lzma, os, re, struct, subprocess, sys, tarfile, threading
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

UA = {"User-Agent": "orphus-av-kernel-refs/2.0"}
LOG_LOCK = threading.Lock()


def log(msg):
    with LOG_LOCK:
        print(msg, file=sys.stderr, flush=True)


def http_get(url, rng=None, timeout=90):
    h = dict(UA)
    if rng:
        h["Range"] = "bytes=%d-%d" % rng
    with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=timeout) as r:
        return r.read()


def decompress(name, data):
    if name.endswith(".gz"):
        return gzip.decompress(data)
    if name.endswith(".xz"):
        return lzma.decompress(data)
    if name.endswith(".bz2"):
        return bz2.decompress(data)
    if name.endswith(".zst"):
        try:
            import zstandard
            return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
        except ImportError:
            pass
        try:
            return subprocess.run(["zstd", "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            raise RuntimeError("zstd data: install `pip install zstandard` or the zstd binary")
    return data


def dir_listing(url, pattern):
    """names of sub-directories in an HTML index page matching `pattern` (a regex with one group)"""
    html = http_get(url, timeout=60).decode("utf-8", "replace")
    return sorted(set(re.findall(r'href="(' + pattern + r')/?"', html)))


# =============================== DEB (Ubuntu, Debian) =========================
class Incomplete(Exception):
    pass


def deb_control(buf):
    """first bytes of a .deb -> dict(member name -> bytes) of the control archive files"""
    if buf[:8] != b"!<arch>\n":
        raise ValueError("not a deb")
    pos = 8
    while pos + 60 <= len(buf):
        name = buf[pos:pos + 16].decode("ascii", "replace").strip().rstrip("/")
        size = int(buf[pos + 48:pos + 58])
        data0 = pos + 60
        if name.startswith("control.tar"):
            if data0 + size > len(buf):
                raise Incomplete()
            raw = decompress(name, buf[data0:data0 + size])
            out = {}
            with tarfile.open(fileobj=io.BytesIO(raw)) as t:
                for m in t.getmembers():
                    if m.isfile():
                        out[m.name.lstrip("./")] = t.extractfile(m).read()
            return out
        pos = data0 + size + (size & 1)
    raise Incomplete()


def deb_vmlinuz(url):
    n = 128 << 10
    while True:
        buf = http_get(url, (0, n - 1))
        try:
            ctl = deb_control(buf)
            break
        except Incomplete:
            if len(buf) < n or n >= (8 << 20):
                raise
            n *= 4
    res = []
    for line in ctl.get("md5sums", b"").decode("utf-8", "replace").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[1].startswith("boot/vmlinuz-"):
            res.append((parts[0], parts[1][5:]))
    return res


def deb_packages(mirror, suite, component="main", arch="amd64"):
    data = http_get("%s/dists/%s/%s/binary-%s/Packages.gz" % (mirror, suite, component, arch), timeout=180)
    out = []
    for stanza in gzip.decompress(data).decode("utf-8", "replace").split("\n\n"):
        f = dict(re.findall(r"^(Package|Version|Filename): (.*)$", stanza, re.M))
        p = f.get("Package", "")
        if re.match(r"linux-image-(unsigned-)?[0-9]", p) and not p.endswith("-dbg"):
            out.append((p, f["Version"], mirror + "/" + f["Filename"], suite))
    return out


DEB_FAMILIES = {
    "ubuntu": dict(mirror="http://archive.ubuntu.com/ubuntu", security="http://archive.ubuntu.com/ubuntu",
                   suites=["focal", "focal-updates", "focal-security", "jammy", "jammy-updates", "jammy-security",
                           "noble", "noble-updates", "noble-security"]),
    "debian": dict(mirror="http://deb.debian.org/debian", security="http://security.debian.org/debian-security",
                   suites=["bullseye", "bullseye-updates", "bullseye-security", "bookworm", "bookworm-updates",
                           "bookworm-security", "trixie", "trixie-updates", "trixie-security"]),
}


# =============================== RPM (Alma, Rocky, CentOS) ====================
T_INT16, T_INT32, T_STRING, T_BIN, T_STRARRAY, T_I18N = 3, 4, 6, 7, 8, 9
TAG = dict(NAME=1000, VERSION=1001, RELEASE=1002, FILEFLAGS=1037, DIRINDEXES=1116, BASENAMES=1117,
           DIRNAMES=1118, FILEDIGESTS=1035, FILEDIGESTALGO=5011)


def _read_header(buf, pos):
    if pos + 16 > len(buf):
        raise Incomplete()
    if buf[pos:pos + 3] != b"\x8e\xad\xe8":
        raise ValueError("bad header magic at %d" % pos)
    nindex, hsize = struct.unpack(">II", buf[pos + 8:pos + 16])
    ix0 = pos + 16
    data0 = ix0 + 16 * nindex
    end = data0 + hsize
    if end > len(buf):
        raise Incomplete()
    entries = {}
    for i in range(nindex):
        tag, typ, off, cnt = struct.unpack(">IIII", buf[ix0 + 16 * i:ix0 + 16 * i + 16])
        entries[tag] = (typ, off, cnt)
    return entries, buf[data0:end], end


def _val(entries, data, tag):
    if tag not in entries:
        return None
    typ, off, cnt = entries[tag]
    if typ in (T_STRING, T_I18N):
        return data[off:data.index(b"\0", off)].decode("utf-8", "replace")
    if typ == T_STRARRAY:
        out = []
        for _ in range(cnt):
            e = data.index(b"\0", off)
            out.append(data[off:e].decode("utf-8", "replace"))
            off = e + 1
        return out
    if typ == T_INT32:
        return list(struct.unpack(">%dI" % cnt, data[off:off + 4 * cnt]))
    if typ == T_INT16:
        return list(struct.unpack(">%dH" % cnt, data[off:off + 2 * cnt]))
    return None


def parse_rpm_head(buf):
    """-> dict(name, version, release, algo, files=[(path, digest, flags)]); raises Incomplete"""
    if buf[:4] != b"\xed\xab\xee\xdb":
        raise ValueError("not an RPM")
    _, _, end = _read_header(buf, 96)          # signature header
    pos = (end + 7) & ~7                         # padded to 8 bytes
    ent, data, _ = _read_header(buf, pos)        # main header

    def g(k):
        return _val(ent, data, TAG[k])
    base, dirs, didx, dig = g("BASENAMES") or [], g("DIRNAMES") or [], g("DIRINDEXES") or [], g("FILEDIGESTS") or []
    flags = g("FILEFLAGS") or [0] * len(base)
    algo = (g("FILEDIGESTALGO") or [1])[0]       # 1 = md5 (default), 8 = sha256
    files = [(dirs[didx[i]] + base[i], dig[i] if i < len(dig) else "", flags[i] if i < len(flags) else 0)
             for i in range(len(base))]
    return dict(name=g("NAME"), version=g("VERSION"), release=g("RELEASE"), algo=algo, files=files)


def rpm_head(url):
    size = 2 << 20
    while True:
        buf = http_get(url, (0, size - 1))
        try:
            return parse_rpm_head(buf)
        except Incomplete:
            if len(buf) < size or size >= (32 << 20):
                raise
            size *= 2


def rpm_packages(repo, names=("kernel", "kernel-core"), arch="x86_64"):
    repo = repo.rstrip("/") + "/"
    repomd = ET.fromstring(http_get(repo + "repodata/repomd.xml"))
    href = None
    for d in repomd.iter():
        if d.tag.endswith("}data") and d.get("type") == "primary":
            for c in d:
                if c.tag.endswith("}location"):
                    href = c.get("href")
    if not href:
        raise RuntimeError("no primary metadata")
    xml = decompress(href, http_get(repo + href, timeout=300))
    out = []
    for _, el in ET.iterparse(io.BytesIO(xml)):
        if el.tag.endswith("}package"):
            n = el.find("{*}name").text
            if n in names and el.find("{*}arch").text == arch:
                v = el.find("{*}version")
                out.append((n, v.get("ver") + "-" + v.get("rel"), repo + el.find("{*}location").get("href"), repo))
            el.clear()
    return out


KERNEL_PATH = re.compile(r"^/(lib/modules/[^/]+/vmlinuz|boot/vmlinuz-[^/]+)$")


def rpm_vmlinuz(url, path_re=KERNEL_PATH):
    res = []
    for path, digest, _flags in rpm_head(url)["files"]:
        if digest and path_re.match(path):          # directories and %ghost files carry no digest
            m = re.match(r"^/lib/modules/([^/]+)/vmlinuz$", path) or re.match(r"^/boot/vmlinuz-(.+)$", path)
            res.append((digest.lower(), "vmlinuz-" + (m.group(1) if m else path.rsplit("/", 1)[-1])))
    return res


# Repository discovery for the RPM families. Each function returns [(label, repo_url)].
def _try_list(url, pat):
    try:
        return dir_listing(url, pat)
    except Exception as e:
        log("[WARN] cannot list %s: %s" % (url, e))
        return []


def repos_alma():
    r = [("alma%s" % v, "https://repo.almalinux.org/almalinux/%s/BaseOS/x86_64/os/" % v) for v in ("8", "9", "10")]
    for d in _try_list("https://repo.almalinux.org/vault/", r"[0-9]+\.[0-9]+"):
        r.append(("alma-vault-" + d, "https://repo.almalinux.org/vault/%s/BaseOS/x86_64/os/" % d))
    return r


def repos_rocky():
    r = [("rocky%s" % v, "https://dl.rockylinux.org/pub/rocky/%s/BaseOS/x86_64/os/" % v) for v in ("8", "9", "10")]
    for d in _try_list("https://dl.rockylinux.org/vault/rocky/", r"[0-9]+\.[0-9]+"):
        r.append(("rocky-vault-" + d, "https://dl.rockylinux.org/vault/rocky/%s/BaseOS/x86_64/os/" % d))
    return r


def repos_centos():
    r = [("stream%s" % v, "https://mirror.stream.centos.org/%s-stream/BaseOS/x86_64/os/" % v) for v in ("9", "10")]
    for d in _try_list("https://vault.centos.org/", r"[0-9]+\.[0-9]+(?:\.[0-9]+)?"):
        if d.startswith("7."):
            r += [("centos-%s-os" % d, "https://vault.centos.org/%s/os/x86_64/" % d),
                  ("centos-%s-updates" % d, "https://vault.centos.org/%s/updates/x86_64/" % d)]
        elif d.startswith("8."):
            r.append(("centos-%s" % d, "https://vault.centos.org/%s/BaseOS/x86_64/os/" % d))
    return r


RPM_FAMILIES = {"alma": repos_alma, "rocky": repos_rocky, "centos": repos_centos}


# =============================== driver =======================================
def load_existing(path):
    done, rows = set(), []
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if line.startswith("#") or not line.strip():
                continue
            rows.append(line.rstrip("\n"))
            p = line.rstrip("\n").split("\t")
            if len(p) >= 4:
                done.add((p[2], p[3]))
    return done, rows


def write_out(path, family, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Orphus known-kernel reference, %s (tools/gen_kernel_refs.py)\n" % family)
        f.write("# hash<TAB>file<TAB>package<TAB>version<TAB>source - md5 (deb) or sha256 (rpm) of the kernel image as recorded in the distribution's own package\n")
        for r in sorted(set(rows)):
            f.write(r + "\n")


def run_family(fam, a):
    out = os.path.join(a.out, fam + ".tsv")
    done, rows = load_existing(out)
    todo = []                                    # (kind, package, version, url, source)
    if fam in DEB_FAMILIES:
        cfg = DEB_FAMILIES[fam]
        flav = re.compile(a.flavors) if a.flavors else None
        seen = set()
        for s in (a.suites.split(",") if a.suites else cfg["suites"]):
            m = cfg["security"] if s.endswith("-security") else cfg["mirror"]
            try:
                pk = deb_packages(m, s)
            except Exception as e:
                log("[WARN] %s: no index for %s (%s)" % (fam, s, e))
                continue
            log("[*] %s %s: %d kernel packages" % (fam, s, len(pk)))
            for p, v, url, suite in pk:
                key = (p, v)
                if key in seen or key in done:
                    continue
                f = re.sub(r"^linux-image-(unsigned-)?[0-9.]+-[0-9]+-", "", p)
                if flav and not flav.search(f):
                    continue
                seen.add(key)
                todo.append(("deb", p, v, url, suite))
    else:
        seen = set()
        for label, repo in RPM_FAMILIES[fam]():
            try:
                pk = rpm_packages(repo, arch=a.arch)
            except Exception as e:
                log("[WARN] %s: %s (%s) skipped: %s" % (fam, label, repo, e))
                continue
            log("[*] %s %s: %d kernel packages" % (fam, label, len(pk)))
            for p, v, url, _r in pk:
                if (p, v) in done or (p, v) in seen:
                    continue
                seen.add((p, v))
                todo.append(("rpm", p, v, url, label))
    log("[*] %s: %d new packages to read (%d already known)" % (fam, len(todo), len(done)))
    if a.list or not todo:
        if not todo:
            write_out(out, fam, rows) if rows else None
        return

    def one(t):
        kind, p, v, url, src = t
        try:
            hits = deb_vmlinuz(url) if kind == "deb" else rpm_vmlinuz(url)
        except Exception as e:
            log("[WARN] %s %s %s: %s" % (fam, p, v, e))
            return []
        return ["\t".join((h.lower(), n, p, v, src)) for h, n in hits]

    new = []
    with ThreadPoolExecutor(a.jobs) as ex:
        for r in ex.map(one, todo):
            new += r
    write_out(out, fam, rows + new)
    log("[OK] %s: +%d entries -> %s" % (fam, len(new), out))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default="signatures/kernel_refs", help="output directory")
    ap.add_argument("--only", default="ubuntu,debian,alma,rocky,centos", help="comma-separated families")
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--arch", default="x86_64", help="rpm architecture")
    ap.add_argument("--suites", default="", help="deb: override the suites (comma-separated)")
    ap.add_argument("--flavors", default="", help="deb: regex on the kernel flavor, e.g. '^(generic|lowlatency|kvm|aws|azure|gcp|oracle)$'")
    ap.add_argument("--list", action="store_true", help="only report what would be read")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for fam in a.only.split(","):
        fam = fam.strip()
        if fam not in DEB_FAMILIES and fam not in RPM_FAMILIES:
            ap.error("unknown family: " + fam)
        run_family(fam, a)


if __name__ == "__main__":
    main()
