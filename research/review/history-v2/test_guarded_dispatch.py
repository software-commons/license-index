import hashlib,os,pathlib,subprocess,sys,tempfile,unittest
from unittest.mock import patch
sys.path.insert(0,'/mnt/c/Users/timdi/Documents/Codex/2026-11-22/task-design-research-implement-and-publish/work/history-v2-prototype');import guarded_preflight as g
class GuardedTests(unittest.TestCase):
 def binding(self):return {'launcher_sha256':'a','package_sha256':'b','launcher_inode':[1,2,3,4],'package_inode':[1,3,4,5],'history_proof':'x','outcome':{'sha256':'z'}}
 def test_preflight_failure_prevents_launch(self):
  called=[]
  with patch.object(g,'preflight',side_effect=ValueError('failed')):
   with self.assertRaises(ValueError):g.dispatch_after_preflight('/x','/y','/z',lambda:called.append(True))
  self.assertEqual(called,[])
 def test_postflight_change_rejects_trace(self):
  before=self.binding();after=self.binding();after['package_inode']=[1,8,4,5]
  with patch.object(g,'preflight',side_effect=[before,after]):
   with self.assertRaisesRegex(ValueError,'binding changed'):g.dispatch_after_preflight('/x','/y','/z',lambda:'trace')
 def test_success_returns_trace_after_two_checks(self):
  b=self.binding()
  with patch.object(g,'preflight',side_effect=[b,b]) as p:self.assertEqual(g.dispatch_after_preflight('/x','/y','/z',lambda:'trace'),('trace',b));self.assertEqual(p.call_count,2)
 def test_real_ancestor_and_file_attacks(self):
  with tempfile.TemporaryDirectory(prefix='history-owned-',dir='/tmp') as tmp:
   root=pathlib.Path(tmp);owned=root/'owned';owned.mkdir(mode=0o755);file=owned/'package';file.write_bytes(b'expected');file.chmod(0o444)
   fd=g.root_chain(str(owned));f,identity=g.pinned_file(fd,'package',hashlib.sha256(b'expected').hexdigest());os.close(f);os.close(fd)
   link=root/'link';link.symlink_to(owned,target_is_directory=True)
   with self.assertRaises((OSError,ValueError)):g.root_chain(str(link))
   os.chmod(owned,0o777)
   with self.assertRaisesRegex(ValueError,'writable ancestor'):g.root_chain(str(owned))
   os.chmod(owned,0o755);fd=g.root_chain(str(owned))
   with self.assertRaisesRegex(ValueError,'protected digest'):g.pinned_file(fd,'package','0'*64)
   file.chmod(0o666)
   with self.assertRaisesRegex(ValueError,'unsafe protected'):g.pinned_file(fd,'package',hashlib.sha256(b'expected').hexdigest())
   file.unlink();file.symlink_to('/etc/passwd')
   with self.assertRaises((OSError,ValueError)):g.pinned_file(fd,'package','0'*64)
   os.close(fd)
 def test_unprivileged_cannot_rename_root_owned_directory(self):
  with tempfile.TemporaryDirectory(prefix='history-parent-',dir='/tmp') as tmp:
   root=pathlib.Path(tmp);root.chmod(0o755);owned=root/'owned';owned.mkdir(mode=0o555)
   r=subprocess.run(['runuser','-u','nobody','--','mv',str(owned),str(root/'renamed')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   self.assertNotEqual(r.returncode,0);self.assertTrue(owned.exists())
if __name__=='__main__':unittest.main(verbosity=2)
