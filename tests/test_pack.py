"""Runs both engines and checks parity: every bad pod must be denied by Kyverno AND Rego; the good pod by neither."""
import json, pathlib, re, shutil, subprocess, tempfile, pytest, yaml
ROOT = pathlib.Path(__file__).resolve().parents[1]
need = pytest.mark.skipif(not (shutil.which("kyverno") and shutil.which("conftest")), reason="kyverno/conftest not installed")

def sh(*a): return subprocess.run(a, cwd=ROOT, capture_output=True, text=True)

def bad_names():
    return {d["metadata"]["name"] for d in yaml.safe_load_all((ROOT / "tests/resources/bad.yaml").read_text())}

@need
def test_kyverno_matrix():
    p = sh("kyverno", "test", "tests")
    assert p.returncode == 0 and "48 tests passed and 0 tests failed" in p.stdout, p.stdout[-2000:]

@need
def test_kyverno_test_catches_wrong_expectation(tmp_path):
    """Sanity: the harness must go red if an expectation is wrong (guards against vacuous passes)."""
    t = yaml.safe_load((ROOT / "tests/kyverno-test.yaml").read_text())
    for r in t["results"]:
        if r["resources"] == ["app/bad-latest"] and r["policy"] == "disallow-latest-tag":
            r["result"] = "pass"
    t["policies"] = [str(ROOT / "tests" / p) for p in t["policies"]]
    t["resources"] = [str(ROOT / "tests" / p) for p in t["resources"]]
    (tmp_path / "kyverno-test.yaml").write_text(yaml.safe_dump(t))
    p = subprocess.run(["kyverno", "test", str(tmp_path)], capture_output=True, text=True)
    assert p.returncode != 0 or "1 tests failed" in p.stdout

@need
def test_rego_unit():
    assert sh("conftest", "verify", "-p", "rego").returncode == 0

@need
def test_parity_kyverno_vs_rego():
    k = sh("kyverno", "apply", "kyverno/", "-r", "tests/resources/bad.yaml", "-r", "tests/resources/good.yaml")
    ky_denied = set(re.findall(r"resource app/Pod/([\w-]+) failed", k.stdout))
    c = sh("conftest", "test", "-p", "rego", "-o", "json", "tests/resources/bad.yaml", "tests/resources/good.yaml")
    rg_denied = {re.match(r"\w+/([\w-]+):", f["msg"]).group(1) for r in json.loads(c.stdout) for f in (r.get("failures") or [])}
    assert ky_denied == bad_names() == rg_denied
    assert "good" not in ky_denied | rg_denied

@need
def test_kyverno_autogen_covers_deployments():
    k = sh("kyverno", "apply", "kyverno/", "-r", "tests/resources/deployment-mixed.yaml")
    assert "Deployment/legacy-api failed" in k.stdout

@need
def test_known_gap_registry_port_untagged():
    """Documented finding: Kyverno '*:*' tag pattern is fooled by a registry port (registry.local:5000/app).
    Rego checks only the last path segment and catches it. If Kyverno ever catches it, update README."""
    k = sh("kyverno", "apply", "kyverno/disallow-latest-tag.yaml", "-r", "tests/resources/deployment-mixed.yaml")
    assert "failed" not in k.stdout  # gap still present
    c = sh("conftest", "test", "-p", "rego", "tests/resources/deployment-mixed.yaml")
    assert "is not pinned" in c.stdout
