from importlib.util import spec_from_file_location,module_from_spec
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, ZipInfo, BadZipFile, ZIP_DEFLATED, ZIP_STORED
import copy,json,sys,zlib,warnings
sys.path.insert(0,'/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-design-research-implement-and-publish/work/history-v2-prototype');import solid_history_v2 as v
s=spec_from_file_location('official','/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-initialize-the-software-commons-github/work/commission-software-commons/build-license-history-packet.py');m=module_from_spec(s);s.loader.exec_module(m)
base='d73d256ffe9b92e82636c8cc9292704964915080';head='07c29292d548edf43ece38ce5af10184911b33c8';good=Path('/root/Documents/Codex/license-ccremaining-reviewed-candidate-0218/history-v2-prototype.zip').read_bytes()
with ZipFile(BytesIO(good)) as z: man=json.loads(z.read('manifest.json')); body=z.read('objects.zlib')
def pack(x,stream=body,extra=None,dup=False):
 b=BytesIO()
 with warnings.catch_warnings():
  warnings.simplefilter('ignore')
  with ZipFile(b,'w') as a:
   for name,data,method in [('manifest.json',v.canonical(x),ZIP_DEFLATED),('objects.zlib',stream,ZIP_STORED)]:
    info=ZipInfo(name,(1980,1,1,0,0,0));info.create_system=3;info.external_attr=0o100444<<16
    a.writestr(info,data,compress_type=method,compresslevel=9)
   if extra:a.writestr('extra',b'x')
   if dup:a.writestr('manifest.json',v.canonical(x))
 return b.getvalue()
def reject(label,payload,b=base,h=head):
 try:v.verify(payload,b,h,m)
 except (ValueError,KeyError,IndexError,UnicodeError,zlib.error,EOFError,BadZipFile) as e:print('PASS',label,type(e).__name__);return
 raise AssertionError('accepted '+label)
reject('wrong base',good,'0'*40)
reject('wrong head',good,base,'0'*40)
reject('zip trailing',good+b'x')
reject('zip prefix',b'JUNK'+good)
reject('zip gap',good[:-22]+b'GAP!'+good[-22:])
local_mismatch=bytearray(good); local_mismatch[30]^=1; reject('local name mismatch',bytes(local_mismatch))
reject('oversize archive',good+b'x'*(v.MAX_ZIP-len(good)+1))
reject('extra member',pack(man,extra=True))
reject('duplicate member',pack(man,dup=True))
reject('truncated compressed stream',pack(man,body[:-2]))
reject('appended compressed stream',pack(man,body+zlib.compress(b'extra')))
reject('bad compressed stream',pack(man,bytes([body[0]^1])+body[1:]))
x=copy.deepcopy(man);x['objects'].pop(next(iter(x['objects'])));reject('missing object',pack(x))
x=copy.deepcopy(man); x['objects'][next(iter(x['objects']))]['size']=v.MAX_RAW+1;reject('raw bound',pack(x))
x=copy.deepcopy(man);x['objects'][next(iter(x['objects']))]['sha256']='0'*64;reject('changed sha',pack(x))
x=copy.deepcopy(man);x['format']='license-index-history-v1';reject('wrong version',pack(x))
x=copy.deepcopy(man);x['codec']['version']='0.0';reject('wrong codec',pack(x))
x=copy.deepcopy(man);x['snapshots'][next(iter(x['snapshots']))]['blob']='0'*40;reject('snapshot mismatch',pack(x))
x=copy.deepcopy(man);x['snapshots']={};reject('omitted association',pack(x))
x=copy.deepcopy(man);x['snapshots']['registry/coverage/snapshots/extra.json']=copy.deepcopy(next(iter(man['snapshots'].values())));reject('extra association',pack(x))
reject('excessive decoded bytes',pack(man,zlib.compress(b'x'*(v.MAX_RAW+len(man['objects'])*64+1),9)))
print('ALL 21 adversarial cases rejected')
