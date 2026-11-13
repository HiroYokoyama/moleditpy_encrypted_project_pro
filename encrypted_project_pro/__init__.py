"""Encrypted Project Pro. Copyright (C) 2026 Hiromichi Yokoyama.

SPDX-License-Identifier: LGPL-3.0-or-later
"""

PLUGIN_NAME = "Encrypted Project Pro"
PLUGIN_VERSION = "1.0.0"
PLUGIN_AUTHOR = "HiroYokoyama"
PLUGIN_LICENSE = "LGPL-3.0-or-later"
PLUGIN_DESCRIPTION = "Authenticated .pmeecp project encryption with passwords, key files, PEM keys and YubiKey PIV."
PLUGIN_CATEGORY = "File"
PLUGIN_TAGS = ["File", "Utility"]
PLUGIN_DEPENDENCIES = ["cryptography>=46,<52"]
PLUGIN_OPTIONAL_DEPENDENCIES = ["yubikey-manager>=5.9,<6"]
PLUGIN_SUPPORTED_PYTHON_VERSION = ">=3.10,<3.15"
PLUGIN_SUPPORTED_MOLEDITPY_VERSION = ">=5.0.0,<6.0.0"


def initialize(context):
    from .gui import Controller

    controller = Controller(context)
    context.add_export_action("Encrypted Project Pro (.pmeecp)...", controller.save)
    context.register_file_opener(".pmeecp", controller.open_from_host)
    context.register_drop_handler(controller.on_drop)
    context.add_menu_action(
        "File/Generate encryption key file...", controller.generate_key_file
    )
