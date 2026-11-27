from importlib.util import spec_from_file_location,module_from_spec
from hashlib import sha256
from pathlib import Path
import json,subprocess,sys,tempfile
sys.path.insert(0,'/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-design-research-implement-and-publish/work/history-v2-prototype');import solid_history_v2 as v
s=spec_from_file_location('official','/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-initialize-the-software-commons-github/work/commission-software-commons/build-license-history-packet.py');m=module_from_spec(s);s.loader.exec_module(m)
for mode in ('delete','modify','mode','source_modify','source_delete','source_mode','source_shared'):
 with tempfile.TemporaryDirectory(prefix='solid-history-test-') as td:
  p=Path(td)
  def git(*args):return subprocess.check_output(['git','-C',str(p),*args],stderr=subprocess.DEVNULL).decode().strip()
  git('init','-q');git('config','user.email','fixture@example.test');git('config','user.name','Fixture')
  (p/'registry/coverage/snapshots').mkdir(parents=True);(p/'research').mkdir();(p/'research/source.json').write_text('{}\n')
  old={'snapshot':'registry/coverage/snapshots/old.json','source_manifest':'research/source.json','schema_version':'1'};oldtext=json.dumps(old)+'\n'
  (p/'registry/coverage/snapshots/old.json').write_text(oldtext);(p/'registry/coverage/current.json').write_text(oldtext)
  git('add','.');git('commit','-qm','base');base=git('rev-parse','HEAD')
  if mode=='delete':(p/'registry/coverage/snapshots/old.json').unlink()
  elif mode=='modify':(p/'registry/coverage/snapshots/old.json').write_text(oldtext+' ')
  elif mode in ('source_modify','source_shared'):(p/'research/source.json').write_text('changed\n')
  elif mode=='source_delete':(p/'research/source.json').unlink()
  new={'snapshot':'registry/coverage/snapshots/new.json','source_manifest':'research/source.json','schema_version':'1'};newtext=json.dumps(new)+'\n'
  (p/'registry/coverage/snapshots/new.json').write_text(newtext);(p/'registry/coverage/current.json').write_text(newtext)
  if mode.startswith('source_') and mode!='source_shared':
   (p/'research/new.json').write_text('{}\n');new['source_manifest']='research/new.json';newtext=json.dumps(new)+'\n';(p/'registry/coverage/snapshots/new.json').write_text(newtext);(p/'registry/coverage/current.json').write_text(newtext)
  git('add','-A')
  if mode=='mode':git('update-index','--chmod=+x','registry/coverage/snapshots/old.json')
  if mode=='source_mode':git('update-index','--chmod=+x','research/source.json')
  git('commit','-qm','head');head=git('rev-parse','HEAD')
  g=m.make_git(p/'.git');records=m.reachable_objects(g,head)
  manifest={'format':v.FORMAT,'codec':v.CODEC,'repository':v.REPOSITORY,'object_format':'sha1','base':base,'head':head,'objects':{oid:{'type':kind,'size':len(data),'sha256':sha256(data).hexdigest()} for oid,(kind,data) in records.items()},'snapshots':m.identify_snapshots(g,base,head,records)}
  payload=v.build(manifest,records)
  try:v.verify(payload,base,head,m)
  except ValueError as e:
   assert str(e) in ('prior snapshot deleted or modified','prior snapshot source deleted or modified','tree entry missing'),str(e);print('PASS',mode,'prior snapshot rejected')
  else:raise AssertionError('accepted prior snapshot '+mode)
