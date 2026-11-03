"""Qt dialogs and explicit encrypted import/export. No plaintext temporary files."""

import json
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from PySide6.QtCore import QObject, QThread, Signal, Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QVBoxLayout,
)

from . import crypto
from .hardware import YubiKeyCredential, YubiKeyRecipient

FILTER = "Encrypted Project Pro (*.pmeecp)"


class Cancelled(Exception):
    pass


def password(parent, title, confirm=False, allow_empty=False):
    value, ok = QInputDialog.getText(
        parent,
        title,
        "Password:"
        if not allow_empty
        else "Private-key passphrase (leave empty if unencrypted):",
        QLineEdit.EchoMode.Password,
    )
    if not ok:
        raise Cancelled()
    if not allow_empty and not value:
        raise ValueError("Password cannot be empty.")
    if confirm:
        if len(value) < 12:
            raise ValueError(
                "Use a password of at least 12 characters; a longer unique passphrase is recommended."
            )
        repeated, ok = QInputDialog.getText(
            parent, title, "Confirm password:", QLineEdit.EchoMode.Password
        )
        if not ok:
            raise Cancelled()
        if value != repeated:
            raise ValueError("Passwords do not match.")
    return value


def select_file(parent, title, pattern):
    path, _ = QFileDialog.getOpenFileName(parent, title, "", pattern)
    if not path:
        raise Cancelled()
    return path


def load_public(path):
    value = crypto.read_bounded(path, crypto.MAX_HEADER)
    try:
        return serialization.load_pem_public_key(value)
    except ValueError:
        return x509.load_pem_x509_certificate(value).public_key()


class SaveDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Save encrypted project")
        self.setMinimumWidth(460)
        self.factors = []
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Add a password or key to protect this project."))
        self.entries = QListWidget()
        layout.addWidget(self.entries)
        buttons = QHBoxLayout()
        for label, kind in [
            ("Password", "password"),
            ("Key file", "key-file"),
            ("Public key", "public-key"),
            ("YubiKey", "yubikey"),
        ]:
            button = QPushButton(label)
            button.clicked.connect(lambda checked=False, k=kind: self.add(k))
            buttons.addWidget(button)
        layout.addLayout(buttons)
        remove = QPushButton("Remove selected")
        remove.clicked.connect(self.remove)
        layout.addWidget(remove)
        self.policy = QComboBox()
        self.policy.addItem("Any one method can unlock (recovery alternatives)", "any")
        self.policy.addItem("All listed methods are required", "all")
        layout.addWidget(self.policy)
        self.explanation = QLabel()
        self.explanation.setWordWrap(True)
        self.policy.currentIndexChanged.connect(self.update_explanation)
        layout.addWidget(self.explanation)
        self.update_explanation()
        actions = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        actions.accepted.connect(self.accept)
        actions.rejected.connect(self.reject)
        layout.addWidget(actions)

    def update_explanation(self):
        self.explanation.setText(
            "Any: losing one method is recoverable with another registered method."
            if self.policy.currentData() == "any"
            else "All: losing any listed password or key makes the file unrecoverable."
        )

    def remove(self):
        row = self.entries.currentRow()
        if row >= 0:
            self.entries.takeItem(row)
            self.factors.pop(row)

    def add(self, kind):
        try:
            if len(self.factors) >= crypto.MAX_FACTORS:
                raise ValueError("Up to eight methods can be registered.")
            if kind == "password":
                factor = crypto.Password(
                    password(self, "Encryption password", confirm=True)
                )
                label = "Password"
            elif kind == "key-file":
                path = select_file(
                    self, "Select 32-byte key file", "Key files (*);;All files (*)"
                )
                factor = crypto.KeyFile(crypto.read_bounded(path, 32))
                label = "Key file: " + Path(path).name
            elif kind == "public-key":
                path = select_file(
                    self,
                    "Select PEM public key or certificate",
                    "PEM files (*.pem *.pub *.crt);;All files (*)",
                )
                factor = crypto.PublicKey(load_public(path))
                label = "Public key: " + crypto.key_id(factor.public)[:12]
            else:
                # Resolve exactly one attached device during encryption. No provisioning.
                factor = YubiKeyRecipient()
                label = "YubiKey PIV (slot 9d; connect one device when saving)"
                if any(item.kind == "yubikey" for item in self.factors):
                    raise ValueError(
                        "Use one YubiKey per save configuration; add a password or key file for recovery."
                    )
            self.factors.append(factor)
            self.entries.addItem(label)
        except Cancelled:
            pass
        except (ValueError, OSError) as error:
            QMessageBox.warning(self, "Cannot add method", str(error))

    def accept(self):
        if not self.factors:
            QMessageBox.warning(
                self, "Choose a method", "Add at least one password or key."
            )
            return
        super().accept()


class Task(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, operation, parent=None):
        super().__init__(parent)
        self.operation = operation

    def run(self):
        try:
            result = self.operation()
        except InvalidTag:
            self.failed.emit("Incorrect credentials or a modified/damaged file.")
        except Exception:
            # Credentials and arbitrary third-party exception text never enter logs/UI.
            self.failed.emit(
                "Operation failed. Check the credentials, key/device availability and file permissions. No PIN was retried automatically."
            )
        else:
            self.completed.emit(result)
        finally:
            self.operation = None


class Controller(QObject):
    def __init__(self, context):
        self.context = context
        self.mw = context.get_main_window()
        super().__init__(self.mw)
        self.task = None
        QApplication.instance().aboutToQuit.connect(self.wait_for_task)

    def wait_for_task(self):
        if self.task is not None:
            self.task.wait()

    def busy(self):
        if self.task is not None:
            self.context.show_status_message(
                "An encrypted-project operation is already running.", 3000
            )
            return True
        return False

    def start(self, operation, success, title):
        progress = QProgressDialog(title, "", 0, 0, self.mw)
        progress.setCancelButton(None)
        progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        progress.setMinimumDuration(0)
        self.task = Task(operation, self)
        self.task.completed.connect(success)
        self.task.failed.connect(
            lambda message: QMessageBox.warning(
                self.mw, "Encrypted Project Pro", message
            )
        )

        def finished():
            progress.close()
            progress.deleteLater()
            task = self.task
            self.task = None
            task.deleteLater()

        self.task.finished.connect(finished)
        progress.show()
        self.task.start()

    def generate_key_file(self):
        path, _ = QFileDialog.getSaveFileName(
            self.mw,
            "Generate random encryption key file",
            "project.key",
            "Key files (*.key)",
        )
        if path:
            try:
                crypto.create_key_file(path)
                QMessageBox.information(
                    self.mw,
                    "Key file created",
                    "Keep this key separately from encrypted projects and keep a secure backup. Existing key files are never overwritten.",
                )
            except OSError:
                QMessageBox.warning(
                    self.mw,
                    "Cannot create key",
                    "Choose a writable path that does not already exist.",
                )

    def save(self):
        if self.busy():
            return
        dialog = SaveDialog(self.mw)
        try:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            path, _ = QFileDialog.getSaveFileName(
                self.mw, "Save encrypted project", "untitled.pmeecp", FILTER
            )
            if not path:
                return
            if not path.lower().endswith(".pmeecp"):
                path += ".pmeecp"
                if (
                    Path(path).exists()
                    and QMessageBox.question(
                        self.mw,
                        "Replace file?",
                        "The encrypted file already exists. Replace it?",
                    )
                    != QMessageBox.StandardButton.Yes
                ):
                    return
            raw = crypto.canonical(self.mw.state_manager.create_json_data())
            if len(raw) > crypto.MAX_PLAINTEXT:
                raise ValueError("Project exceeds 64 MiB.")
            factors, policy = list(dialog.factors), dialog.policy.currentData()

            def operation():
                encrypted = crypto.encrypt(raw, factors, policy)
                crypto.atomic_write(path, encrypted)
                return path

            self.start(
                operation,
                lambda saved: self.context.show_status_message(
                    "Encrypted project exported: " + saved, 5000
                ),
                "Encrypting project…",
            )
        except (ValueError, OSError):
            QMessageBox.warning(
                self.mw,
                "Cannot save project",
                "Unable to prepare this project or destination.",
            )
        finally:
            dialog.factors.clear()
            dialog.deleteLater()

    def choose_open(self):
        if self.busy():
            return
        try:
            self.open(select_file(self.mw, "Open encrypted project", FILTER))
        except Cancelled:
            pass

    def credential(self, record):
        if record["kind"] == "password":
            return crypto.Password(password(self.mw, "Unlock encrypted project"))
        if record["kind"] == "key-file":
            path = select_file(
                self.mw, "Select encryption key file", "Key files (*);;All files (*)"
            )
            return crypto.KeyFile(crypto.read_bounded(path, 32))
        if record["kind"] == "public-key":
            path = select_file(
                self.mw,
                "Select PEM private key",
                "PEM files (*.pem *.key);;All files (*)",
            )
            phrase = password(self.mw, "Private-key passphrase", allow_empty=True)
            return crypto.PrivateKey(
                serialization.load_pem_private_key(
                    crypto.read_bounded(path, crypto.MAX_HEADER),
                    phrase.encode("utf-8") if phrase else None,
                )
            )
        pin = password(self.mw, "YubiKey PIV PIN — touch the key when requested")
        return YubiKeyCredential(pin)

    def open(self, path):
        if self.busy():
            return
        try:
            blob = crypto.read_bounded(path, crypto.MAX_FILE)
            header, _end = crypto.inspect_container(blob)
            records = header["factors"]
            indexes = list(range(len(records)))
            if header["policy"] == "any" and len(records) > 1:
                labels = [
                    f"{index + 1}. {record['kind']}"
                    + (
                        " — " + record.get("key_id", "")[:12]
                        if "key_id" in record
                        else ""
                    )
                    for index, record in enumerate(records)
                ]
                selected, ok = QInputDialog.getItem(
                    self.mw,
                    "Unlock project",
                    "Choose one unlock method:",
                    labels,
                    0,
                    False,
                )
                if not ok:
                    return
                indexes = [labels.index(selected)]
            credentials = {index: self.credential(records[index]) for index in indexes}

            def operation():
                raw = crypto.decrypt(blob, credentials)
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError("Project must be a JSON object.")
                return data

            self.start(
                operation,
                self.restore,
                "Unlocking project… Touch your YubiKey if configured.",
            )
        except Cancelled:
            pass
        except Exception:
            QMessageBox.warning(
                self.mw,
                "Cannot open project",
                "Unsupported/damaged file, invalid credential, or unavailable key. The current project has not been changed.",
            )

    def restore(self, data):
        # The plugin imports as an unsaved document; ordinary Save never writes
        # plaintext over an encrypted file. Export explicitly to encrypt again.
        if (
            QMessageBox.question(
                self.mw,
                "Open decrypted project?",
                "Replace the current document? Unsaved changes will be lost.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            self.mw.ui_manager.restore_ui_for_editing()
            self.mw.state_manager.load_from_json_data(data)
            self.mw.state_manager.reset_undo_stack()
            self.mw.init_manager.current_file_path = None
            self.context.mark_project_modified()
            self.context.refresh_ui()
            QTimer.singleShot(0, self.context.fit_2d_view)
            self.context.show_status_message(
                "Decrypted project opened. Use Export → Encrypted Project Pro to save encrypted.",
                8000,
            )
        except Exception:
            QMessageBox.warning(
                self.mw,
                "Cannot restore project",
                "MoleditPy could not load the decrypted project. Reload the previous document if needed.",
            )
