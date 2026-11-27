"""Scratch-only deterministic solid Git history prototype; never deploy without review."""
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_STORED, ZIP_DEFLATED, ZipFile, ZipInfo
import json, re, zlib

MAX_ZIP=16*1024*1024
MAX_RAW=64*1024*1024
MAX_COUNT=100000
MAX_MANIFEST=8*1024*1024
FORMAT='license-index-history-v2'
REPOSITORY='https://github.com/software-commons/license-index'
CODEC={'name':'zlib','version':'1.3','level':9}

def require(ok,msg):
    if not ok: raise ValueError(msg)

def canonical(x): return (json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()

def object_hash(kind,data):
    from hashlib import sha1
    return sha1(f'{kind} {len(data)}\0'.encode()+data,usedforsecurity=False).hexdigest()

def frame(records):
    return b''.join((oid+' '+kind+' '+str(len(data))+'\0').encode('ascii')+data for oid,(kind,data) in sorted(records.items()))

def build(manifest,records):
    require(zlib.ZLIB_VERSION==zlib.ZLIB_RUNTIME_VERSION==CODEC['version'] and manifest.get('codec')==CODEC,'unsupported codec')
    raw=frame(records)
    require(sum(len(data) for _,data in records.values())<=MAX_RAW and len(records)<=MAX_COUNT,'raw/count exceeds limit')
    man=canonical(manifest);require(len(man)<=MAX_MANIFEST,'manifest exceeds limit')
    compressed=zlib.compress(raw,9)
    out=BytesIO()
    with ZipFile(out,'w',allowZip64=False) as z:
        for name,data,method in [('manifest.json',man,ZIP_DEFLATED),('objects.zlib',compressed,ZIP_STORED)]:
            info=ZipInfo(name,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=0o100444<<16
            z.writestr(info,data,compress_type=method,compresslevel=9)
    result=out.getvalue();require(len(result)<=MAX_ZIP,'archive exceeds limit');return result

def verify(payload,base,head):
    require(zlib.ZLIB_VERSION==zlib.ZLIB_RUNTIME_VERSION==CODEC['version'],'unsupported codec runtime')
    require(len(payload)<=MAX_ZIP and len(payload)>=22,'archive size')
    # Canonical archives have EOCD with zero comment at the very end.
    require(payload[-22:-18]==b'PK\x05\x06' and payload[-2:]==b'\0\0','trailing data or comment')
    with ZipFile(BytesIO(payload)) as z:
        require(z.namelist()==['manifest.json','objects.zlib'],'unexpected or duplicate archive entries')
        infos=z.infolist();require(infos[0].compress_type==ZIP_DEFLATED and infos[1].compress_type==ZIP_STORED,'unexpected method')
        require(infos[0].file_size<=MAX_MANIFEST and infos[1].file_size<=MAX_ZIP,'member size')
        require(all(not (i.flag_bits & 1) for i in infos),'encrypted member')
        man=z.read(infos[0]); manifest=json.loads(man);require(man==canonical(manifest),'noncanonical manifest')
        require(manifest.get('codec')==CODEC,'unsupported codec declaration')
        require((manifest['format'],manifest['repository'],manifest['object_format'],manifest['base'],manifest['head'])==(FORMAT,REPOSITORY,'sha1',base,head),'pins differ')
        objects=manifest['objects'];require(isinstance(objects,dict) and 0<len(objects)<=MAX_COUNT,'object count')
        require(all(re.fullmatch('[0-9a-f]{40}',oid) for oid in objects),'invalid oid')
        require(all(type(e.get('size')) is int and e['size']>=0 and e.get('type') in {'commit','tree','blob'} and re.fullmatch('[0-9a-f]{64}',e.get('sha256','')) for e in objects.values()),'invalid object entry')
        require(sum(e['size'] for e in objects.values())<=MAX_RAW,'raw limit')
        # Each frame adds at most 40-byte oid, 6-byte type, 9-byte size, separators.
        bound=MAX_RAW+len(objects)*64
        decoder=zlib.decompressobj(); raw=decoder.decompress(z.read(infos[1]),bound+1)
        require(len(raw)<=bound and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,'truncated, excessive or trailing stream')
    pos=0;records={}
    for oid in sorted(objects):
        end=raw.find(b'\0',pos);require(end>=pos and end-pos<=64,'invalid frame')
        e=objects[oid];expected=(oid+' '+e['type']+' '+str(e['size'])).encode('ascii')
        require(raw[pos:end]==expected,'frame identity/order mismatch')
        pos=end+1;data=raw[pos:pos+e['size']];pos+=e['size']
        require(len(data)==e['size'] and sha256(data).hexdigest()==e['sha256'] and object_hash(e['type'],data)==oid,'object digest mismatch')
        records[oid]=(e['type'],data)
    require(pos==len(raw),'extra frame bytes')
    # A deterministic byte-for-byte rebuild rejects prepended data, gaps,
    # noncanonical headers, central/local mismatch and altered encoding.
    require(build(manifest,records)==payload,'noncanonical archive framing')
    # The v1 verifier checks every declared association but does not prove the
    # declaration includes every newly introduced snapshot. Derive that set
    # independently from the authenticated base/head trees.
    def mode_entries(raw_tree):
        entries={};offset=0
        while offset<len(raw_tree):
            end=raw_tree.find(b'\0',offset);require(end>=offset,'invalid tree')
            parts=raw_tree[offset:end].split(b' ',1);require(len(parts)==2,'invalid tree entry')
            mode,name=parts
            require(mode in {b'40000',b'100644',b'100755',b'120000'} and name and b'/' not in name
                    and name not in entries and end+21<=len(raw_tree),'invalid tree mode or name')
            entries[name]=(mode,raw_tree[end+1:end+21].hex());offset=end+21
        return entries
    def tree_at_mode(commit,path):
        require(commit in records and records[commit][0]=='commit','commit missing')
        oid,_=commit_links(records[commit][1]); kind='tree'
        for part in path.split('/'):
            require(kind=='tree' and oid in records and records[oid][0]=='tree','tree path missing')
            entries=mode_entries(records[oid][1]); key=part.encode('utf-8')
            require(key in entries,'tree entry missing');mode,oid=entries[key]
            require(mode in {b'40000',b'100644',b'100755'},'nonregular scoped path')
            kind='tree' if mode==b'40000' else 'blob'
        return kind,oid,mode
    def tree_at(commit,path):
        kind,oid,_=tree_at_mode(commit,path)
        return kind,oid
    def snapshot_paths(commit):
        root='registry/coverage/snapshots'; kind,root_oid=tree_at(commit,root)
        require(kind=='tree','snapshot root not tree')
        found={}; stack=[(root,root_oid)]; visited=set()
        while stack:
            prefix,oid=stack.pop();require((prefix,oid) not in visited,'duplicate tree path');visited.add((prefix,oid))
            require(oid in records and records[oid][0]=='tree','snapshot tree missing')
            for name,(mode,child_oid) in mode_entries(records[oid][1]).items():
                child=prefix+'/'+name.decode('utf-8')
                if mode==b'40000': stack.append((child,child_oid))
                else: require(mode in {b'100644',b'100755'} and child not in found,'nonregular snapshot path');found[child]=(mode,child_oid)
        return found
    base_paths=snapshot_paths(base); head_paths=snapshot_paths(head)
    require(all(head_paths.get(path)==oid for path,oid in base_paths.items()),
            'prior snapshot deleted or modified')
    for path,(_,oid) in base_paths.items():
        require(oid in records and records[oid][0]=='blob','prior snapshot blob missing')
        snapshot=json.loads(records[oid][1])
        require(isinstance(snapshot,dict) and isinstance(snapshot.get('source_manifest'),str),
                'prior snapshot source missing')
        source=snapshot['source_manifest']
        require(tree_at_mode(base,source)==tree_at_mode(head,source),
                'prior snapshot source deleted or modified')
        require(tree_at(base,source)[0]=='blob','prior snapshot source not regular')
    pending=set(head_paths)-set(base_paths)
    require(set(manifest['snapshots'])==pending,'snapshot association set incomplete or extra')
    current_kind,current_oid=tree_at(head,'registry/coverage/current.json')
    require(current_kind=='blob' and current_oid in records,'current snapshot missing')
    selected=json.loads(records[current_oid][1])['snapshot']
    require(selected in pending and head_paths[selected][1]==current_oid,'current selection mismatch')
    for path,association in manifest['snapshots'].items():
        commit,source=association['commit'],association['source_manifest']
        for scoped in ('registry/coverage/current.json',path,source):
            require(tree_at(commit,scoped)[0]=='blob','nonregular historical scoped path')
        require(tree_at(head,source)[0]=='blob','nonregular head source path')
    # A static copy of v1's graph/snapshot logic examines a transient bounded
    # v1 projection. The real v2 payload has already passed MAX_ZIP; no module
    # globals are modified, including during concurrent verification.
    old_manifest=dict(manifest);old_manifest['format']=V1_FORMAT
    v1=projection_zip_bytes(old_manifest,records)
    require(verify_projection(v1,base,head)==old_manifest,'v1 graph mismatch')
    return manifest

V1_FORMAT="license-index-history-v1"
CURRENT="registry/coverage/current.json"
canonical_json=canonical
def oid_valid(oid):
    return re.fullmatch(r"[0-9a-f]{40}", oid) is not None


def commit_links(raw):
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    tree = headers[0].removeprefix(b"tree ").decode("ascii")
    parents = tuple(line[7:].decode("ascii") for line in headers if line.startswith(b"parent "))
    require(headers[0].startswith(b"tree ") and oid_valid(tree) and all(oid_valid(oid) for oid in parents),
            "invalid commit tree or parent")
    return tree, parents


def tree_entries(raw):
    entries = {}
    offset = 0
    modes = {b"40000": "tree", b"100644": "blob", b"100755": "blob", b"120000": "blob"}
    while offset < len(raw):
        end = raw.index(b"\0", offset)
        mode, name = raw[offset:end].split(b" ", 1)
        require(mode in modes and name and b"/" not in name and name not in entries
                and end + 21 <= len(raw), "invalid regular Git tree entry")
        entries[name] = modes[mode], raw[end + 1:end + 21].hex()
        offset = end + 21
    return entries


def verify_projection(payload, base, head):
    with ZipFile(BytesIO(payload), "r") as archive:
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        objects = manifest["objects"]
        require(manifest_bytes == canonical_json(manifest), "history manifest is not canonical")
        require((manifest["format"], manifest["repository"], manifest["object_format"],
                 manifest["base"], manifest["head"]) == (V1_FORMAT, REPOSITORY, "sha1", base, head),
                "history manifest pins differ")
        require(archive.namelist() == ["manifest.json", *[f"objects/{oid}" for oid in sorted(objects)]],
                "unexpected history ZIP members")
        require(sum(entry["size"] for entry in objects.values()) <= MAX_RAW and len(payload) <= MAX_RAW + MAX_MANIFEST + MAX_COUNT * 256,
                "history ZIP exceeds size limits")
        commits = {}
        trees = {}
        for oid, entry in objects.items():
            raw = archive.read(f"objects/{oid}")
            kind = entry["type"]
            require(len(raw) == entry["size"] and sha256(raw).hexdigest() == entry["sha256"]
                    and object_hash(kind, raw) == oid, f"history ZIP object mismatch: {oid}")
            if kind == "commit":
                commits[oid] = commit_links(raw)
            elif kind == "tree":
                trees[oid] = tree_entries(raw)
            else:
                require(kind == "blob", f"unexpected history object type: {oid}")

        def descendants(origin, only_commits):
            stack = [("commit", origin)]
            visited = set()
            while stack:
                kind, oid = stack.pop()
                require(objects[oid]["type"] == kind, f"wrong history object type: {oid}")
                if oid in visited:
                    continue
                visited.add(oid)
                if kind == "commit":
                    tree, parents = commits[oid]
                    stack.extend(("commit", parent) for parent in parents)
                    if not only_commits:
                        stack.append(("tree", tree))
                elif kind == "tree":
                    stack.extend(trees[oid].values())
            return visited

        def path_at(commit, path):
            kind, oid = "tree", commits[commit][0]
            for part in path.split("/"):
                require(kind == "tree", f"non-directory parent: {commit}:{path}")
                kind, oid = trees[oid][part.encode("utf-8")]
            return kind, oid

        require(descendants(head, False) == set(objects), "history object graph is incomplete or includes unseen objects")
        head_commits = descendants(head, True)
        require(base in head_commits, "base is not an ancestor of the archived head")
        incoming = head_commits - descendants(base, True)
        for path, association in manifest["snapshots"].items():
            commit, blob = association["commit"], association["blob"]
            require(commit in incoming, f"snapshot commit is outside the requested range: {path}")
            require(path_at(commit, CURRENT) == path_at(commit, path) == path_at(head, path) == ("blob", blob),
                    f"snapshot does not resolve to exact current/archived bytes: {path}")
            snapshot = json.loads(archive.read(f"objects/{blob}"))
            source = association["source_manifest"]
            require(snapshot["snapshot"] == path and snapshot["source_manifest"] == source
                    and snapshot["schema_version"] == association["schema_version"],
                    f"snapshot declaration differs from manifest: {path}")
            require(path_at(commit, source) == path_at(head, source) == ("blob", association["source_blob"]),
                    f"source manifest does not resolve to the same exact bytes: {path}")
        return manifest



def projection_zip_bytes(manifest, records):
    output = BytesIO()
    with ZipFile(output, "w", allowZip64=False, compresslevel=9) as archive:
        def put(name, data):
            item = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.external_attr = 0o100444 << 16
            archive.writestr(item, data, compress_type=ZIP_DEFLATED, compresslevel=9)

        put("manifest.json", canonical_json(manifest))
        for oid, (_, data) in records.items():
            put(f"objects/{oid}", data)
    return output.getvalue()


