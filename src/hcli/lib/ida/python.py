# see also hcli.lib.util.python
import logging
import os
import subprocess
from pathlib import Path

from hcli.env import ENV
from hcli.lib.ida import run_py_in_current_idapython

logger = logging.getLogger(__name__)


def is_windows_store_shim(path: str | None) -> bool:
    """Check if a path is a Windows Store Python shim.

    The Windows Store shims are at paths like:
        C:\\Users\\...\\AppData\\Local\\Microsoft\\WindowsApps\\python3.EXE

    These are just redirectors that don't work like a real Python installation
    and should be avoided when detecting IDA's Python.
    """
    if path is None:
        return False
    # Normalize to lowercase and check for both slash types
    lowered = path.lower()
    return "microsoft\\windowsapps" in lowered or "microsoft/windowsapps" in lowered


FIND_PYTHON_PY = """
# output like:
#
#     __hcli__:"/Users/user/.idapro/venv/bin/python"
import shutil
import os.path
import sys
import json


def is_windows_store_shim(path):
    '''Check if a path is a Windows Store Python shim.

    The Windows Store shims are at paths like:
        C:\\Users\\...\\AppData\\Local\\Microsoft\\WindowsApps\\python3.EXE

    These are just redirectors that don't work like a real Python installation
    and should be avoided.
    '''
    if path is None:
        return False
    # Normalize to lowercase and check for both slash types
    lowered = path.lower()
    return "microsoft\\\\windowsapps" in lowered or "microsoft/windowsapps" in lowered


def find_python_from_prefix():
    '''Try to find Python executable from sys.prefix.

    This is particularly useful on Windows where sys.executable may return
    the host application (like idat.exe) instead of python.exe when running
    embedded Python.
    '''
    prefix = sys.prefix
    if not prefix:
        return None

    # On Windows, Python is typically at prefix/python.exe
    if sys.platform == "win32":
        candidate = os.path.join(prefix, "python.exe")
        if os.path.isfile(candidate):
            return candidate

    # On Unix-like systems, check bin/python3 and bin/python
    for name in ("python3", "python"):
        candidate = os.path.join(prefix, "bin", name)
        if os.path.isfile(candidate):
            return candidate

    return None


def find_python_executable():
    # 1. First, check sys.executable if it looks like a Python interpreter
    exe = sys.executable
    if exe and "python" in os.path.basename(exe).lower():
        if not is_windows_store_shim(exe):
            return exe

    # 2. Try to find Python from sys.prefix (reliable in IDA's embedded Python)
    prefix_python = find_python_from_prefix()
    if prefix_python and not is_windows_store_shim(prefix_python):
        return prefix_python

    # 3. Fall back to shutil.which, but filter out Windows Store shims
    for cmd in ("python3", "python"):
        candidate = shutil.which(cmd)
        if candidate and not is_windows_store_shim(candidate):
            return candidate

    # 4. Last resort: return whatever we can find, even if it's a shim
    return shutil.which("python3") or shutil.which("python")


print("__hcli__:" + json.dumps(find_python_executable()))
sys.exit()
"""


def find_current_python_executable() -> Path:
    """find the python executable associated with the current IDA installation"""
    # duplicate here, because we prefer access through ENV
    # but tests might update env vars for the current process.
    exe = os.environ.get("HCLI_CURRENT_IDA_PYTHON_EXE")
    if exe:
        return Path(exe)
    if ENV.HCLI_CURRENT_IDA_PYTHON_EXE is not None:
        return Path(ENV.HCLI_CURRENT_IDA_PYTHON_EXE)

    try:
        exe = run_py_in_current_idapython(FIND_PYTHON_PY)
    except RuntimeError as e:
        raise RuntimeError("failed to determine current IDA Python interpreter") from e

    if "python" not in exe:
        logger.warning("'python' not found in discovered IDA Python interpreter path: %s", exe)

    logger.debug("found IDA Python interpreter path: %s", exe)
    return Path(exe)


def does_current_ida_have_pip(python_exe: Path) -> bool:
    """Check if pip is available in the given Python executable."""
    try:
        process = subprocess.run(
            [str(python_exe), "-m", "pip", "help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10.0
        )
        return process.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


class CantInstallPackagesError(ValueError): ...


def verify_pip_can_install_packages(python_exe: Path, packages: list[str]):
    """Check if the given Python packages (e.g., "foo>=v1.0,<3") can be installed.

    This allows pip to determine if there are any version conflicts
    """
    process = subprocess.run(
        [str(python_exe), "-m", "pip", "install", "--dry-run"] + packages,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        # error output might look like:
        #
        #     ❯ pip install --dry-run flare-capa==v1.0.0 flare-capa==v1.0.1
        #    Collecting flare-capa==v1.0.0
        #      Using cached flare-capa-1.0.0.tar.gz (62 kB)
        #      Installing build dependencies ... done
        #      Getting requirements to build wheel ... done
        #      Preparing metadata (pyproject.toml) ... done
        #    ERROR: Cannot install flare-capa==v1.0.0 and flare-capa==v1.0.1 because these package versions have conflicting dependencies.
        #
        #    The conflict is caused by:
        #        The user requested flare-capa==v1.0.0
        #        The user requested flare-capa==v1.0.1
        #
        #    To fix this you could try to:
        #    1. loosen the range of package versions you've specified
        #    2. remove package versions to allow pip to attempt to solve the dependency conflict
        #
        #    ERROR: ResolutionImpossible: for help visit https://pip.pypa.io/en/latest/topics/dependency-resolution/#dealing-with-dependency-conflicts
        logger.debug("can't install packages")
        logger.debug(stdout.decode())
        logger.debug(stderr.decode())
        raise CantInstallPackagesError(stdout.decode())


def pip_install_packages(python_exe: Path, packages: list[str]):
    """Install the given Python packages (e.g., "foo>=v1.0,<3")."""
    process = subprocess.run(
        [str(python_exe), "-m", "pip", "install"] + packages, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        # error output might look like:
        #
        #     ❯ pip install --dry-run flare-capa==v1.0.0 flare-capa==v1.0.1
        #    Collecting flare-capa==v1.0.0
        #      Using cached flare-capa-1.0.0.tar.gz (62 kB)
        #      Installing build dependencies ... done
        #      Getting requirements to build wheel ... done
        #      Preparing metadata (pyproject.toml) ... done
        #    ERROR: Cannot install flare-capa==v1.0.0 and flare-capa==v1.0.1 because these package versions have conflicting dependencies.
        #
        #    The conflict is caused by:
        #        The user requested flare-capa==v1.0.0
        #        The user requested flare-capa==v1.0.1
        #
        #    To fix this you could try to:
        #    1. loosen the range of package versions you've specified
        #    2. remove package versions to allow pip to attempt to solve the dependency conflict
        #
        #    ERROR: ResolutionImpossible: for help visit https://pip.pypa.io/en/latest/topics/dependency-resolution/#dealing-with-dependency-conflicts
        logger.debug("can't install packages")
        logger.debug(stdout.decode())
        logger.debug(stderr.decode())
        raise CantInstallPackagesError(stdout.decode())


def pip_freeze(python_exe: Path):
    process = subprocess.run([str(python_exe), "-m", "pip", "freeze"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = process.stdout, process.stderr
    if process.returncode != 0:
        raise subprocess.CalledProcessError(process.returncode, [str(python_exe), "-m", "pip", "freeze"])
    return stdout.decode()
