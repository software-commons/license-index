import ast,json,sys,unittest
from pathlib import Path

class RepositoryBindingTests(unittest.TestCase):
 def test_launcher_checks_exact_requested_repository(self):
  path=Path(__file__).resolve().parent/'isolated_history_launcher.py'
  tree=ast.parse(path.read_text(encoding='utf-8'))
  statement=next(n for n in tree.body if isinstance(n,ast.If) and any(isinstance(x,ast.Constant) and x.value=='repository binding' for x in ast.walk(n)))
  code=compile(ast.Module(body=[statement],type_ignores=[]),str(path),'exec')
  for info,allowed in [({'repository':'software-commons/license-index'},True),({'repository':'software-commons/language-index'},False),({},False),({'repository':None},False)]:
   with self.subTest(info=info):
    if allowed:exec(code,{'info':info})
    else:
     with self.assertRaisesRegex(ValueError,'repository binding'):exec(code,{'info':info})
if __name__=='__main__':unittest.main()
