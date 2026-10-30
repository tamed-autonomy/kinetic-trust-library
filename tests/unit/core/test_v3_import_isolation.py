"""The native implementation must survive removal of the legacy public root."""
import ast,importlib.util,subprocess,sys,unittest
from pathlib import Path


class NativeImportIsolationTests(unittest.TestCase):
    def test_native_modules_load_with_legacy_runtime_blocked(self):
        package=Path(next(iter(importlib.util.find_spec("kinetic_trust_library").submodule_search_locations)))
        script='''
import importlib,importlib.abc,importlib.machinery,sys,types
root=types.ModuleType("kinetic_trust_library")
root.__path__=[sys.argv[1]]
root.__package__="kinetic_trust_library"
root.__spec__=importlib.machinery.ModuleSpec("kinetic_trust_library",loader=None,is_package=True)
sys.modules[root.__name__]=root
class BlockLegacy(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if any(fullname==prefix or fullname.startswith(prefix+".") for prefix in (
                "kinetic_trust_library.models","kinetic_trust_library.proofs","kinetic_trust_library.core")):
            raise ImportError("native v3 attempted legacy runtime import: "+fullname)
sys.meta_path.insert(0,BlockLegacy())
for name in ("kinetic_trust_library.v3","kinetic_trust_library.v3.person_claims",
        "kinetic_trust_library.v3.software_stop_resolution","kinetic_trust_library.v3.software_issuance",
        "kinetic_trust_library.v3.native_issuance"):
    importlib.import_module(name)
'''
        result=subprocess.run([sys.executable,"-c",script,str(package)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_native_code_has_no_deferred_legacy_runtime_imports(self):
        package=Path(next(iter(importlib.util.find_spec("kinetic_trust_library").submodule_search_locations)))
        violations=[]
        prefixes=("kinetic_trust_library.models","kinetic_trust_library.proofs","kinetic_trust_library.core")
        for source in (package/"v3").glob("*.py"):
            for node in ast.walk(ast.parse(source.read_text())):
                names=[]
                if isinstance(node,ast.ImportFrom):
                    base=importlib.util.resolve_name("."*node.level+(node.module or ""),"kinetic_trust_library.v3")
                    names=[base,*(base+"."+n.name for n in node.names if n.name!="*")]
                elif isinstance(node,ast.Import):names=[n.name for n in node.names]
                if any(name==p or name.startswith(p+".") for name in names for p in prefixes):violations.append((source.name,node.lineno))
        self.assertEqual(violations,[])
