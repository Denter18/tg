"""Хук python-for-android: регистрирует Java-сервис NoDpiVpnService в манифесте.

Тот же приём, что в основном приложении: манифест генерируется скриптом
build.py ПОСЛЕ хука before_apk_build, поэтому правим его в before_apk_assemble.
"""

from pathlib import Path

SERVICE_NAME = "org.gvcoder.tgbridge.NoDpiVpnService"

SERVICE_XML = (
    '<service android:name="{name}" '
    'android:permission="android.permission.BIND_VPN_SERVICE" '
    'android:exported="false">'
    '<intent-filter><action android:name="android.net.VpnService"/></intent-filter>'
    "</service>"
).format(name=SERVICE_NAME)


def before_apk_build(toolchain):
    pass


def after_apk_build(toolchain):
    pass


def before_apk_assemble(toolchain):
    manifest = Path("src") / "main" / "AndroidManifest.xml"

    if not manifest.is_file():
        raise RuntimeError(
            "p4a_hook: не найден {} (cwd={})".format(manifest, Path.cwd())
        )

    content = manifest.read_text(encoding="utf-8")

    if SERVICE_NAME in content:
        print("p4a_hook: {} уже есть в манифесте".format(SERVICE_NAME))
        return

    if "</application>" not in content:
        raise RuntimeError("p4a_hook: в манифесте нет тега </application>")

    content = content.replace("</application>", SERVICE_XML + "</application>", 1)
    manifest.write_text(content, encoding="utf-8")
    print("p4a_hook: {} добавлен в {}".format(SERVICE_NAME, manifest))
