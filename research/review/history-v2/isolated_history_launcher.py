"""Scratch isolated launcher; stage launcher and package under issuer ownership."""
import sys,resource,signal,os,stat,hashlib,json,re
if not sys.flags.isolated: raise ValueError('python -I required')
resource.setrlimit(resource.RLIMIT_AS,(512*1024*1024,512*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU,(120,120));signal.alarm(125)
PACKAGE_SHA='571c027af5342351ae5f99d5c6eba1e7fb2a06b31aef43878433c77ad590b2f5'
if len(sys.argv)!=4: raise ValueError('usage: launcher package-directory review-input.json review-history.zip')
def trusted_owner(st):
 if st.st_uid==0:return True
 # Reviewer :minimal uses a single-entry user namespace. Host root appears
 # as the overflow UID; issuer preflight must independently establish actual
 # root ownership before staging. Never rely on this sandbox check alone.
 if st.st_uid!=65534 or os.geteuid()!=1000:return False
 try:
  with open('/proc/self/uid_map','r',encoding='ascii') as f: mapping=f.read().split()
 except OSError:return False
 return mapping==['1000','0','1']
def read_regular(path,maximum,require_root=False):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 with os.fdopen(fd,'rb') as f:
  st=os.fstat(f.fileno())
  if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>maximum:raise ValueError('unsafe file')
  if require_root and (st.st_uid!=0 or st.st_mode&0o022):raise ValueError('package ownership')
  data=f.read(maximum+1)
  if len(data)!=st.st_size or len(data)>maximum:raise ValueError('file size changed')
  return data
parentfd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
try:
 st=os.fstat(parentfd)
 if not trusted_owner(st) or st.st_mode&0o022:raise ValueError('package directory ownership')
 fd=os.open('issuer_history_v2_pinned.py',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
 try:
  ps=os.fstat(fd)
  if not stat.S_ISREG(ps.st_mode) or not trusted_owner(ps) or ps.st_mode&0o022 or ps.st_nlink!=1 or ps.st_size>1024*1024:raise ValueError('package metadata')
  with os.fdopen(fd,'rb',closefd=False) as f: package=f.read(1024*1024+1)
  if len(package)!=ps.st_size or hashlib.sha256(package).hexdigest()!=PACKAGE_SHA:raise ValueError('package digest')
 finally:os.close(fd)
finally:os.close(parentfd)
# Compile only the already verified in-memory package bytes, never candidate code.
module={'__name__':'trusted_history'};exec(compile(package,'<pinned-history-verifier>','exec'),module)
info=json.loads(read_regular(sys.argv[2],1024*1024));token=info['inspection_token'];base=info['base'];head=info['head'];expected=info['review_history_sha256']
if not isinstance(token,str) or not re.fullmatch('[A-Za-z0-9_-]{16,128}',token):raise ValueError('inspection token')
if not re.fullmatch('[0-9a-f]{40}',base) or not re.fullmatch('[0-9a-f]{40}',head) or not re.fullmatch('[0-9a-f]{64}',expected):raise ValueError('pins')
payload=read_regular(sys.argv[3],16*1024*1024)
if hashlib.sha256(payload).hexdigest()!=expected:raise ValueError('history digest')
from io import BytesIO
from zipfile import ZipFile
with ZipFile(BytesIO(payload)) as archive:
 member=archive.getinfo('manifest.json')
 if member.file_size>8*1024*1024:raise ValueError('manifest size')
 fmt=json.loads(archive.read(member))['format']
if fmt=='license-index-history-v2':result=module['verify'](payload,base,head)
elif fmt=='license-index-history-v1':result=module['verify_projection'](payload,base,head)
else:raise ValueError('history format')
line='review-history.zip '+hashlib.sha256(token.encode('ascii')+payload).hexdigest()+'\n'
print('history-proof 0 '+hashlib.sha256(line.encode('ascii')).hexdigest())
print(json.dumps({'format':fmt,'sha256':expected,'objects':len(result['objects']),'snapshots':len(result['snapshots']),'base':base,'head':head},sort_keys=True))
