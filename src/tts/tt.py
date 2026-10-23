import base64
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_TT_TEMPLATE_PATH = _PROJECT_ROOT / "templates" / "loader.tt"


def generate(dll_bytes, namespace, classname):
    b64 = base64.b64encode(dll_bytes).decode("ascii")
    tt = _TT_TEMPLATE_PATH.read_text()
    tt = tt.replace("BASE64_PH", b64)
    tt = tt.replace("NAMESPACE_PH", namespace)
    tt = tt.replace("CLASSNAME_PH", classname)
    return tt
