"""Local workload operations for the Notary machine charm."""

import shutil
import subprocess
from pathlib import Path
from typing import BinaryIO, Iterator

from charms.operator_libs_linux.v2 import snap


class WorkloadError(Exception):
    """A local workload operation failed."""


class WorkloadPathError(WorkloadError):
    """A requested local workload path does not exist."""


class NotarySnap:
    """Operate the Notary snap and its writable common directory."""

    snap_name = "notary"
    service_name = "notaryd"

    def install(self, channel: str) -> None:
        """Install or refresh the Notary snap without starting its daemon."""
        try:
            notary_snap = snap.SnapCache()[self.snap_name]
            notary_snap.ensure(snap.SnapState.Latest, channel=channel)
        except snap.SnapError as error:
            raise WorkloadError(str(error)) from error

    def is_running(self) -> bool:
        """Return the status of the Notary daemon."""
        try:
            services = snap.SnapCache()[self.snap_name].services
        except snap.SnapError as error:
            raise WorkloadError(str(error)) from error
        return services.get(self.service_name, {}).get("active", False)

    def start(self) -> None:
        """Start the Notary daemon."""
        try:
            snap.SnapCache()[self.snap_name].start(services=[self.service_name])
        except snap.SnapError as error:
            raise WorkloadError(str(error)) from error

    def stop(self) -> None:
        """Stop the Notary daemon."""
        try:
            snap.SnapCache()[self.snap_name].stop(services=[self.service_name])
        except snap.SnapError as error:
            raise WorkloadError(str(error)) from error

    def restart(self) -> None:
        """Restart the Notary daemon."""
        try:
            snap.SnapCache()[self.snap_name].restart(services=[self.service_name])
        except snap.SnapError as error:
            raise WorkloadError(str(error)) from error

    def path_exists(self, path: str) -> bool:
        """Return whether a local workload path exists."""
        return Path(path).exists()

    def read_text(self, path: str) -> str:
        """Read a UTF-8 workload file."""
        try:
            return Path(path).read_text()
        except FileNotFoundError as error:
            raise WorkloadPathError(path) from error

    def write_text(self, path: str, content: str) -> None:
        """Write a UTF-8 workload file, creating its parent directory."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def copy_from_stream(self, path: str, source: BinaryIO) -> None:
        """Copy binary data into a workload file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as destination:
            shutil.copyfileobj(source, destination)

    def copy_to_stream(self, path: str, destination: BinaryIO) -> None:
        """Copy a workload file into a binary stream."""
        try:
            with Path(path).open("rb") as source:
                shutil.copyfileobj(source, destination)
        except FileNotFoundError as error:
            raise WorkloadPathError(path) from error

    def create_directory(self, path: str) -> None:
        """Create a workload directory."""
        Path(path).mkdir(parents=True, exist_ok=True)

    def remove(self, path: str) -> None:
        """Remove a workload file or directory."""
        target = Path(path)
        if not target.exists():
            raise WorkloadPathError(path)
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    def move(self, source: str, destination: str) -> None:
        """Move a workload path."""
        try:
            shutil.move(source, destination)
        except OSError as error:
            raise WorkloadError(str(error)) from error

    def files(self, path: str) -> Iterator[Path]:
        """List direct descendants of a workload directory."""
        try:
            yield from Path(path).iterdir()
        except FileNotFoundError as error:
            raise WorkloadPathError(path) from error

    def run(self, arguments: list[str], timeout: int) -> None:
        """Run the Notary CLI through the installed snap."""
        try:
            subprocess.run(
                ["snap", "run", self.snap_name, *arguments],
                check=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise WorkloadError(str(error)) from error
