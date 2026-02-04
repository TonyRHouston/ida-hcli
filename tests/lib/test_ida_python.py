import os
from pathlib import Path

import pytest

from hcli.lib.ida.python import (
    CantInstallPackagesError,
    does_current_ida_have_pip,
    find_current_python_executable,
    is_windows_store_shim,
    verify_pip_can_install_packages,
)


def has_idat():
    """Check if idat is available (same logic as in test_ida.py)"""
    if "HCLI_HAS_IDAT" not in os.environ:
        return True

    if os.environ["HCLI_HAS_IDAT"].lower() in ("", "0", "false", "f"):
        return False

    return True


class TestIsWindowsStoreShim:
    """Tests for is_windows_store_shim function that detects Windows Store Python shims."""

    def test_detects_windows_store_python_shim(self):
        """Test that Windows Store Python shim paths are correctly detected."""
        # Typical Windows Store Python shim paths
        assert is_windows_store_shim(r"C:\Users\User\AppData\Local\Microsoft\WindowsApps\python3.exe")
        assert is_windows_store_shim(r"C:\Users\User\AppData\Local\Microsoft\WindowsApps\python.exe")
        assert is_windows_store_shim(r"C:\Users\User\AppData\Local\Microsoft\WindowsApps\python3.12.exe")

    def test_detects_windows_store_shim_case_insensitive(self):
        """Test that detection is case insensitive."""
        assert is_windows_store_shim(r"C:\Users\User\AppData\Local\MICROSOFT\WINDOWSAPPS\python3.exe")
        assert is_windows_store_shim(r"c:\users\user\appdata\local\microsoft\windowsapps\python3.exe")

    def test_does_not_flag_legitimate_python_paths(self):
        """Test that legitimate Python installations are not flagged as shims."""
        # Standard Python installations
        assert not is_windows_store_shim(r"C:\Python312\python.exe")
        assert not is_windows_store_shim(r"C:\Program Files\Python312\python.exe")
        assert not is_windows_store_shim(r"C:\Users\User\AppData\Local\Programs\Python\Python312\python.exe")

        # IDA's bundled Python
        assert not is_windows_store_shim(r"C:\Program Files\IDA Professional 9.2\python314\python.exe")

        # Linux/macOS paths
        assert not is_windows_store_shim("/usr/bin/python3")
        assert not is_windows_store_shim("/usr/local/bin/python")
        assert not is_windows_store_shim("/home/user/.local/bin/python3")
        assert not is_windows_store_shim("/Applications/IDA Professional 9.2.app/Contents/MacOS/python3")

    def test_handles_none_input(self):
        """Test that None input returns False."""
        assert not is_windows_store_shim(None)

    def test_handles_forward_slash_paths(self):
        """Test that forward slash paths are also detected."""
        # Some tools might normalize to forward slashes
        assert is_windows_store_shim("C:/Users/User/AppData/Local/Microsoft/WindowsApps/python3.exe")


@pytest.mark.skipif(not has_idat(), reason="Skip when idat not present (Free/Home)")
def test_find_current_python_executable_returns_path():
    """Test that find_current_python_executable returns a valid path."""
    result = find_current_python_executable()
    assert isinstance(result, Path)
    assert result.exists()
    assert result.is_file()
    assert "python" in result.name.lower()


@pytest.mark.skipif(not has_idat(), reason="Skip when idat not present (Free/Home)")
def test_does_current_ida_have_pip():
    python_exe = find_current_python_executable()
    assert does_current_ida_have_pip(python_exe)


@pytest.mark.skipif(not has_idat(), reason="Skip when idat not present (Free/Home)")
def test_verify_pip_can_install_packages():
    python_exe = find_current_python_executable()

    verify_pip_can_install_packages(python_exe, ["flare-capa"])

    verify_pip_can_install_packages(python_exe, ["flare-capa==v1.0.0"])
    verify_pip_can_install_packages(python_exe, ["flare-capa==1.0.0"])
    verify_pip_can_install_packages(python_exe, ["flare-capa==1.0"])
    verify_pip_can_install_packages(python_exe, ["flare-capa==1"])
    verify_pip_can_install_packages(python_exe, ["flare-capa==1"])
    verify_pip_can_install_packages(python_exe, ["flare-capa==v1.2.0"])

    # unfortunately this fuzzy matching doesn't work
    with pytest.raises(CantInstallPackagesError):
        verify_pip_can_install_packages(python_exe, ["flare-capa~=1"])

    # duplicates
    verify_pip_can_install_packages(python_exe, ["flare-capa==v1.0.0", "flare-capa==v1.0.0"])

    # obvious conflict
    with pytest.raises(CantInstallPackagesError):
        verify_pip_can_install_packages(python_exe, ["flare-capa==v1.0.0", "flare-capa==v1.2.0"])

    # unfortunately this doesn't work
    with pytest.raises(CantInstallPackagesError):
        verify_pip_can_install_packages(python_exe, ["flare-capa==1", "flare-capa==v1.2.0"])

    with pytest.raises(CantInstallPackagesError):
        verify_pip_can_install_packages(python_exe, ["flare-capa==v1.0.0", "flare-capa>v1.2.0"])

    with pytest.raises(CantInstallPackagesError):
        verify_pip_can_install_packages(python_exe, ["flare-capa==v1.2.0", "flare-capa<=v1.0.0"])
