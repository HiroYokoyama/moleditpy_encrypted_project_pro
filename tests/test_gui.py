from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from PySide6.QtWidgets import QDialog, QMessageBox, QWidget
import pytest

from encrypted_project_pro import crypto, gui, initialize


@pytest.mark.parametrize("value", ["x", "short"])
def test_short_password_can_be_confirmed_and_round_trips(monkeypatch, value):
    answers = iter([(value, True), (value, True)])
    monkeypatch.setattr(gui.QInputDialog, "getText", lambda *args: next(answers))
    entered = gui.password(None, "Encryption password", confirm=True)
    assert entered == value
    blob = crypto.encrypt(b"project", [crypto.Password(entered)])
    assert crypto.decrypt(blob, {0: crypto.Password(value)}) == b"project"


def test_empty_password_and_confirmation_mismatch_still_rejected(monkeypatch):
    monkeypatch.setattr(gui.QInputDialog, "getText", lambda *args: ("", True))
    with pytest.raises(ValueError, match="cannot be empty"):
        gui.password(None, "Encryption password", confirm=True)
    answers = iter([("x", True), ("y", True)])
    monkeypatch.setattr(gui.QInputDialog, "getText", lambda *args: next(answers))
    with pytest.raises(ValueError, match="do not match"):
        gui.password(None, "Encryption password", confirm=True)


@pytest.fixture
def controller(qtbot):
    window = QWidget()
    qtbot.addWidget(window)
    context = MagicMock()
    context.get_main_window.return_value = window
    window.state_manager = MagicMock()
    window.state_manager.has_unsaved_changes = True
    window.ui_manager = MagicMock()
    window.init_manager = SimpleNamespace(current_file_path="previous.pmeprj")
    return gui.Controller(context)


def test_registration_is_folder_plugin_and_silent(qtbot):
    context = MagicMock()
    window = QWidget()
    qtbot.addWidget(window)
    context.get_main_window.return_value = window
    initialize(context)
    context.register_file_opener.assert_called_once()
    assert context.register_file_opener.call_args.args[0] == ".pmeecp"
    assert context.add_export_action.call_args.args[0].endswith("(.pmeecp)...")
    context.register_drop_handler.assert_called_once()
    assert all(
        "Open Encrypted" not in call.args[0]
        for call in context.add_menu_action.call_args_list
    )


def test_save_dialog_policy_remove_and_no_secrets_in_labels(qtbot):
    dialog = gui.SaveDialog()
    qtbot.addWidget(dialog)
    assert dialog.policy.currentData() == "any"
    dialog.policy.setCurrentIndex(1)
    assert dialog.policy.currentData() == "all"
    assert "unrecoverable" in dialog.explanation.text()
    dialog.factors.append(crypto.Password("a secret passphrase"))
    dialog.entries.addItem("Password")
    dialog.entries.setCurrentRow(0)
    dialog.remove()
    assert not dialog.factors and dialog.entries.count() == 0


def test_actual_async_save_and_open_preserves_project(
    qtbot, monkeypatch, tmp_path, controller
):
    project = {
        "2d_structure": {"atoms": [{"id": 1, "symbol": "C"}]},
        "plugins": {"Some Plugin": {"value": 42}},
    }
    controller.mw.state_manager.create_json_data.return_value = project
    path = tmp_path / "molecule.pmeecp"
    factor = crypto.KeyFile(b"a" * 32)
    dialog = MagicMock()
    dialog.exec.return_value = QDialog.DialogCode.Accepted
    dialog.factors = [factor]
    dialog.policy.currentData.return_value = "any"
    monkeypatch.setattr(gui, "SaveDialog", lambda parent: dialog)
    monkeypatch.setattr(
        gui.QFileDialog, "getSaveFileName", lambda *args: (str(path), "")
    )
    controller.save()
    qtbot.waitUntil(lambda: controller.task is None, timeout=15000)
    assert crypto.decrypt(path.read_bytes(), {0: factor}) == crypto.canonical(project)
    assert list(tmp_path.iterdir()) == [path]
    assert controller.mw.init_manager.current_file_path == "previous.pmeprj"
    monkeypatch.setattr(controller, "credential", lambda record: factor)
    monkeypatch.setattr(
        gui.QMessageBox, "question", lambda *args: QMessageBox.StandardButton.Yes
    )
    controller.open(str(path))
    qtbot.waitUntil(lambda: controller.task is None, timeout=15000)
    controller.mw.state_manager.load_from_json_data.assert_called_once_with(project)
    assert controller.mw.init_manager.current_file_path == str(path.absolute())
    assert controller.mw.state_manager.has_unsaved_changes is False
    controller.context.mark_project_modified.assert_not_called()


def test_authentication_failure_never_loads_or_overwrites(
    qtbot, monkeypatch, tmp_path, controller
):
    path = tmp_path / "project.pmeecp"
    blob = crypto.encrypt(b'{"private":true}', [crypto.KeyFile(b"a" * 32)])
    path.write_bytes(blob)
    monkeypatch.setattr(
        controller, "credential", lambda record: crypto.KeyFile(b"b" * 32)
    )
    warnings = []
    monkeypatch.setattr(gui.QMessageBox, "warning", lambda *args: warnings.append(args))
    controller.open(str(path))
    qtbot.waitUntil(lambda: controller.task is None, timeout=15000)
    assert warnings
    controller.mw.state_manager.load_from_json_data.assert_not_called()
    assert controller.mw.init_manager.current_file_path == "previous.pmeprj"
    assert path.read_bytes() == blob
    assert controller.mw.state_manager.has_unsaved_changes is True


def test_declined_document_replace_preserves_state(monkeypatch, controller):
    monkeypatch.setattr(
        gui.QMessageBox, "question", lambda *args: QMessageBox.StandardButton.No
    )
    controller.restore({"data": "new"}, "project.pmeecp")
    controller.mw.state_manager.load_from_json_data.assert_not_called()
    assert controller.mw.state_manager.has_unsaved_changes is True
    assert controller.mw.init_manager.current_file_path == "previous.pmeprj"


@pytest.mark.parametrize("filename", ["project.pmeecp", "project.PMEECP"])
def test_drop_hook_defers_opening_until_event_returns(
    qtbot, monkeypatch, controller, filename
):
    opener = MagicMock()
    monkeypatch.setattr(controller, "open", opener)
    assert controller.on_drop(filename) is True
    opener.assert_not_called()
    qtbot.waitUntil(lambda: opener.call_count == 1)
    opener.assert_called_once_with(filename)


def test_drop_hook_leaves_other_extensions_to_host(controller, monkeypatch):
    opener = MagicMock()
    monkeypatch.setattr(controller, "open", opener)
    for filename in ["project.pmeprj", "project.pmeenc", "molecule.xyz"]:
        assert controller.on_drop(filename) is False
    opener.assert_not_called()


def test_task_failure_does_not_expose_credentials(qtbot):
    def fail():
        raise ValueError("secret-password-123")

    task = gui.Task(fail)
    with qtbot.waitSignal(task.failed) as result:
        task.start()
    task.wait()
    assert "secret-password-123" not in result.args[0]
    assert task.operation is None


def test_load_public_and_passphrase_private_roundtrip(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    key = x25519.X25519PrivateKey.generate()
    path = Path(tmp_path) / "public.pem"
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    assert crypto.key_id(gui.load_public(path)) == crypto.key_id(key.public_key())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"long passphrase"),
    )
    loaded = serialization.load_pem_private_key(private_pem, b"long passphrase")
    assert crypto.key_id(loaded.public_key()) == crypto.key_id(key.public_key())
