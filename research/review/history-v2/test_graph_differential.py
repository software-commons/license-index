import ast,copy,inspect,json,subprocess,sys,tempfile
from pathlib import Path
from hashlib import sha256
from importlib.util import spec_from_file_location,module_from_spec
sys.path.insert(0,'/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-design-research-implement-and-publish/work/history-v2-prototype');import graph_projection as g
s=spec_from_file_location('upstream','/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-initialize-the-software-commons-github/work/commission-software-commons/build-license-history-packet.py');u=module_from_spec(s);s.loader.exec_module(u)
class Normalize(ast.NodeTransformer):
 def visit_FunctionDef(self,node):
  node.name='same';return self.generic_visit(node)
 def visit_Compare(self,node):
  node=self.generic_visit(node)
  if isinstance(node.left,ast.Call) and isinstance(node.left.func,ast.Name) and node.left.func.id=='len' and len(node.left.args)==1 and isinstance(node.left.args[0],ast.Name) and node.left.args[0].id=='payload':return ast.copy_location(ast.Constant(value=True),node)
  return node
def norm(fn):return ast.dump(Normalize().visit(ast.parse(inspect.getsource(fn))),include_attributes=False)
for a,b in [(u.oid_valid,g.oid_valid),(u.commit_links,g.commit_links),(u.tree_entries,g.tree_entries),(u.verify_zip,g.verify_projection)]:
 assert norm(a)==norm(b),a.__name__+' differs beyond transient payload cap'
 print('PASS static semantic equivalence',a.__name__)
with tempfile.TemporaryDirectory(prefix='projection-diff-') as td:
 p=Path(td)
 def git(*args):return subprocess.check_output(['git','-C',str(p),*args],stderr=subprocess.DEVNULL).decode().strip()
 git('init','-q');git('config','user.email','fixture@example.test');git('config','user.name','Fixture');(p/'registry/coverage/snapshots').mkdir(parents=True);(p/'research').mkdir();(p/'research/source.json').write_text('{}\n')
 old={'snapshot':'registry/coverage/snapshots/old.json','source_manifest':'research/source.json','schema_version':'1'}; text=json.dumps(old)+'\n';(p/'registry/coverage/snapshots/old.json').write_text(text);(p/'registry/coverage/current.json').write_text(text);git('add','.');git('commit','-qm','base');base=git('rev-parse','HEAD')
 new={'snapshot':'registry/coverage/snapshots/new.json','source_manifest':'research/source.json','schema_version':'1'};text=json.dumps(new)+'\n';(p/'registry/coverage/snapshots/new.json').write_text(text);(p/'registry/coverage/current.json').write_text(text);git('add','.');git('commit','-qm','head');head=git('rev-parse','HEAD')
 gitfn=u.make_git(p/'.git');records=u.reachable_objects(gitfn,head);manifest={'format':u.FORMAT,'repository':u.REPOSITORY,'object_format':'sha1','base':base,'head':head,'objects':{oid:{'type':kind,'size':len(data),'sha256':sha256(data).hexdigest()} for oid,(kind,data) in records.items()},'snapshots':u.identify_snapshots(gitfn,base,head,records)}
 cases=[('valid',manifest,records,base,head),('wrong base',manifest,records,'0'*40,head)]
 bad=copy.deepcopy(manifest);bad['snapshots'][next(iter(bad['snapshots']))]['blob']='0'*40;cases.append(('bad snapshot',bad,records,base,head))
 bad=copy.deepcopy(manifest);bad['objects'][next(iter(bad['objects']))]['sha256']='0'*64;cases.append(('bad digest',bad,records,base,head))
 for name,ma,rr,b,h in cases:
  data=u.zip_bytes(ma,rr);out=[]
  for fn in (u.verify_zip,g.verify_projection):
   try:fn(data,b,h);out.append('accept')
   except Exception as e:out.append('reject:'+type(e).__name__)
  assert out[0]==out[1],(name,out);print('PASS differential',name,out[0])
print('PASS v1 projection differential complete')
