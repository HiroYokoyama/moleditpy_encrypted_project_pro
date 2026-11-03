import ast
import importlib.util
import json
from pathlib import Path
import shutil
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def test_distribution_is_folder_plugin_and_notices_only(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "release", ROOT / "scripts/release_common.py"
    )
    release = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(release)
    config = json.loads((ROOT / "scripts/release-config.json").read_text())
    staged = tmp_path / "repo"
    staged.mkdir()
    shutil.copytree(ROOT / "encrypted_project_pro", staged / "encrypted_project_pro")
    for name in config["include"]:
        shutil.copy2(ROOT / name, staged / name)
    config["archive"] = "package.zip"
    tree = ast.parse((ROOT / config["source"]).read_text())
    version = next(
        ast.literal_eval(n.value)
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "PLUGIN_VERSION" for t in n.targets)
    )
    archive = release.package(staged, config, version)
    with ZipFile(archive) as zipped:
        assert set(zipped.namelist()) == {
            f"encrypted_project_pro/{name}"
            for name in [
                "__init__.py",
                "crypto.py",
                "hardware.py",
                "gui.py",
                "README.md",
                "LICENSE",
                "COPYING",
                "LICENSING.md",
                "SECURITY.md",
            ]
        }
        assert (
            zipped.read("encrypted_project_pro/LICENSE")
            == (ROOT / "LICENSE").read_bytes()
        )
        assert (
            zipped.read("encrypted_project_pro/COPYING")
            == (ROOT / "COPYING").read_bytes()
        )
