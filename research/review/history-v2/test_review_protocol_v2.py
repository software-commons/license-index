import base64,json,pathlib,unittest,copy
import review_protocol_v2 as p
root=pathlib.Path(__file__).resolve().parent
archive=base64.b64decode((root/'candidate-v2.base64').read_bytes());trace=(root/'sandbox-v2-guarded-trace.jsonl').read_text();before=json.loads((root/'issuer-v2-guarded-before.json').read_text());after=json.loads((root/'issuer-v2-guarded-after.json').read_text());token='0123456789abcdef0123456789abcdef';base='d73d256ffe9b92e82636c8cc9292704964915080';head='07c29292d548edf43ece38ce5af10184911b33c8'
def validate(t=trace,b=before,a=after,ar=archive):return p.validate_v2_history(t,token,ar,base,head,b,a)
class ProtocolTests(unittest.TestCase):
 def test_authentic_trace(self):self.assertEqual(validate()['preflight'],'passed')
 def test_missing_preflight(self):
  b=copy.deepcopy(before);b['preflight']='failed'
  with self.assertRaises(ValueError):validate(b=b)
 def test_changed_inode(self):
  a=copy.deepcopy(after);a['package_inode'][1]+=1
  with self.assertRaises(ValueError):validate(a=a)
 def test_missing_and_malformed_inodes(self):
  for side in ('before','after','both'):
   for key in ('launcher_inode','package_inode','interpreter_inode'):
    for value in (None,[],[1,2,3],[1,0,3,4],[1,2,0,4],[1,True,3,4]):
     b=copy.deepcopy(before);a=copy.deepcopy(after)
     if side in ('before','both'):
      if value is None:b.pop(key)
      else:b[key]=value
     if side in ('after','both'):
      if value is None:a.pop(key)
      else:a[key]=value
     with self.subTest(side=side,key=key,value=value):
      with self.assertRaises(ValueError):validate(b=b,a=a)
 def test_tampered_archive(self):
  with self.assertRaises(ValueError):validate(ar=archive+b'x')
 def test_wrong_output_proof(self):
  with self.assertRaises(ValueError):validate(t=trace.replace(before['history_proof'],'history-proof 0 '+64*'0'))
 def test_printed_proof_without_launcher(self):
  fake=json.dumps({'item':{'type':'command_execution','status':'completed','exit_code':0,'command':'/bin/bash -lc "printf fake"','aggregated_output':before['history_proof']+'\n'}})
  with self.assertRaises(ValueError):validate(t=fake)
 def test_shell_chain_cannot_spoof(self):
  fake=json.dumps({'item':{'type':'command_execution','status':'completed','exit_code':0,'command':'/bin/bash -lc "true; python3 -I trusted/isolated_history_launcher.py trusted review-input.json review-history.zip"','aggregated_output':before['history_proof']+'\n'}})
  with self.assertRaises(ValueError):validate(t=fake)
 def test_path_and_function_substitution_rejected(self):
  for command in ('python3 -I trusted/isolated_history_launcher.py trusted review-input.json review-history.zip',
                  '/usr/bin/env -i PATH=/tmp /usr/bin/python3 -I trusted/isolated_history_launcher.py trusted review-input.json review-history.zip',
                  'python3(){ echo fake; }; python3 -I trusted/isolated_history_launcher.py trusted review-input.json review-history.zip'):
   self.assertFalse(p.command_is_exact(command))
 def test_wrong_tool_pin(self):
  b=copy.deepcopy(before);b['launcher_sha256']='0'*64
  with self.assertRaises(ValueError):validate(b=b)
 def test_wrong_interpreter_pin(self):
  b=copy.deepcopy(before);b['interpreter_sha256']='0'*64
  with self.assertRaises(ValueError):validate(b=b)
if __name__=='__main__':unittest.main(verbosity=2)
