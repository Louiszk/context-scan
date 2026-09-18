import codecs
import glob
import os

from llm_sandbox import SandboxBackend, create_session


class StreamingSandboxSession:
    def __init__(
        self,
        image=None,
        dockerfile=None,
        keep_template=False,
        stream=True,
        verbose=True,
        runtime_configs=None,
        container_type="auto",
        **kwargs,
    ):
        self.verbose = verbose
        self.session = None

        # Determine which container technology backend to use
        backend = None
        if container_type == "docker":
            if not check_docker_running():
                raise RuntimeError("Docker is selected but not running or available.")
            backend = SandboxBackend.DOCKER
        elif container_type == "podman":
            if not check_podman_running():
                raise RuntimeError("Podman is selected but not running or available.")
            backend = SandboxBackend.PODMAN
        elif container_type == "auto":
            if check_docker_running():
                backend = SandboxBackend.DOCKER
            elif check_podman_running():
                backend = SandboxBackend.PODMAN
            else:
                raise RuntimeError("Neither Docker nor Podman are running or available. Please install and start one.")
        else:
            raise ValueError(f"Unknown container type: {container_type}")

        if self.verbose:
            print(f"Using {backend.value} as container runtime")

        # Prepare the arguments for the create_session factory
        session_kwargs = {
            "image": image,
            "dockerfile": dockerfile,
            "keep_template": keep_template,
            "verbose": verbose,
            "runtime_configs": runtime_configs,
            "stream": stream,
            **kwargs,
        }

        # If using Podman, check for our custom isolated socket and add it to the arguments
        if backend == SandboxBackend.PODMAN:
            socket_path = os.environ.get("CONTEXTSCAN_PODMAN_SOCKET")
            if socket_path:
                print(f"--> Connecting Podman client to isolated service socket: {socket_path}")
                # 'base_url' is the kwarg the internal PodmanClient uses for the socket
                session_kwargs["base_url"] = socket_path
            else:
                print("--> WARNING: CONTEXTSCAN_PODMAN_SOCKET not set. Connecting to default Podman service.")

        # Use the library's factory to create the correct session instance
        self.session = create_session(backend=backend, **session_kwargs)

    def open(self):
        if not self.session:
            raise RuntimeError("Session was not initialized correctly.")
        return self.session.open()

    def close(self):
        if self.session:
            return self.session.close()

    def execute_command(self, command, workdir=None):
        if not self.session:
            raise RuntimeError("Session is not open.")

        # Bypass internal buggy execute_command with streaming enabled.
        if hasattr(self.session, "container") and self.session.container:
            try:
                # Use demux=True to get stdout/stderr separately, and don't use stream here
                exit_code, output = self.session.container.exec_run(command, workdir=workdir, demux=True)
                stdout_data, stderr_data = output
                stdout = stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
                stderr = stderr_data.decode("utf-8", errors="replace") if stderr_data else ""

                # Mock the SandboxOutput object
                from collections import namedtuple

                SandboxOutput = namedtuple("SandboxOutput", ["exit_code", "stdout", "stderr"])
                return SandboxOutput(exit_code, stdout, stderr)
            except Exception as e:
                if self.verbose:
                    print(f"Direct exec_run failed: {e}")

        return self.session.execute_command(command, workdir)

    def copy_to_runtime(self, src, dest):
        if not self.session:
            raise RuntimeError("Session is not open.")

        # If it's a Docker session, bypass the buggy llm-sandbox copy_to_runtime which uses Path().parent
        if hasattr(self.session, "container") and self.session.container:
            try:
                import io
                import tarfile
                from pathlib import Path

                # Normalize destination to use forward slashes
                dest = dest.replace("\\", "/")
                dest_path = Path(dest)
                parent_dir = str(dest_path.parent).replace("\\", "/")

                tar_stream = io.BytesIO()
                with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                    tar.add(src, arcname=dest_path.name)

                tar_stream.seek(0)
                # Use put_archive directly with forward-slashed parent directory
                self.session.container.put_archive(parent_dir, tar_stream.getvalue())
                return True
            except Exception as e:
                if self.verbose:
                    print(f"Direct put_archive failed for {src}: {e}")

        # Fallback to library or printf for other backends
        try:
            self.session.copy_to_runtime(src, dest)
            return True
        except Exception:  # noqa: S110
            pass

        return False

    def copy_from_runtime(self, src, dest):
        if not self.session:
            raise RuntimeError("Session is not open.")
        return self.session.copy_from_runtime(src, dest)

    def execute_command_streaming(self, command, workdir=None):
        if not self.session or not self.session.container:
            raise RuntimeError("Session is not open or container is not running.")

        kwargs = {"stream": True, "tty": True}
        if workdir:
            kwargs["workdir"] = workdir

        _, output_stream = self.session.container.exec_run(command, **kwargs)

        # Use an incremental decoder to handle multi-byte characters split across chunks
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        try:
            for chunk in output_stream:
                if not chunk:
                    continue

                try:
                    # The incremental decoder buffers partial characters automatically
                    decoded_text = decoder.decode(chunk, final=False)
                    if decoded_text:
                        yield decoded_text
                except Exception as e:
                    if self.verbose:
                        print(f"\n[Decoding Error] {e}")
                    continue

            # Final flush
            final_text = decoder.decode(b"", final=True)
            if final_text:
                yield final_text
        except Exception as e:
            if self.verbose:
                print(f"\n[Stream Error] {e}")

    def copy_dir_to_runtime(self, src_dir: str, dest_dir: str, pattern: str = "*"):
        """
        Copies files matching a glob pattern from a local source directory
        to a destination directory inside the sandbox.
        """
        if not os.path.isdir(src_dir):
            if self.verbose:
                print(f"Warning: Source directory '{src_dir}' not found, skipping copy.")
            return

        self.execute_command(f"mkdir -p {dest_dir}")

        files_to_copy = glob.glob(os.path.join(src_dir, pattern))

        if not files_to_copy:
            if self.verbose:
                print(f"No files found in '{src_dir}' matching pattern '{pattern}'.")
            return

        if self.verbose:
            print(f"Copying {len(files_to_copy)} files from '{src_dir}' to sandbox '{dest_dir}'...")

        for src_path in files_to_copy:
            if os.path.isfile(src_path):
                filename = os.path.basename(src_path)
                # Ensure dest_path uses forward slashes for the sandbox
                dest_path = f"{dest_dir.rstrip('/')}/{filename}"
                self.copy_to_runtime(src_path, dest_path)

    def copy_dir_from_runtime(self, src_dir: str, dest_dir: str, pattern: str = "*"):
        """
        Copies files matching a glob pattern from a source directory inside the sandbox
        to a local destination directory.
        """
        os.makedirs(dest_dir, exist_ok=True)

        full_path_pattern = os.path.join(src_dir, pattern).replace("\\", "/")
        command = f'sh -c "ls -d {full_path_pattern} 2>/dev/null"'
        command_output = self.execute_command(command)
        file_list_str = str(command_output.stdout) if command_output and command_output.stdout else ""

        if not file_list_str.strip():
            if self.verbose:
                print(f"No files found in sandbox '{src_dir}' matching pattern '{pattern}'.")
            return

        sandbox_paths = [path for path in file_list_str.strip().split("\n") if path]

        if self.verbose:
            print(f"Copying {len(sandbox_paths)} files from sandbox '{src_dir}' to '{dest_dir}'...")

        for src_path_in_sandbox in sandbox_paths:
            filename = os.path.basename(src_path_in_sandbox)
            dest_path_on_host = os.path.join(dest_dir, filename)
            self.copy_from_runtime(src_path_in_sandbox, dest_path_on_host)


def check_docker_running():
    """Check if Docker is running and available."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        return True
    except (ImportError, Exception):
        return False


def check_podman_running():
    """Check if Podman is running and available."""
    if os.environ.get("CONTEXTSCAN_PODMAN_SOCKET"):
        return True

    try:
        from podman import PodmanClient

        client = PodmanClient()
        return client.info()["host"]["remoteSocket"] is not None
    except (ImportError, Exception):
        return False


def setup_sandbox_environment(session, reinstall=False, include_tests=False, max_samples=1000):
    """Set up the sandbox environment with required files and dependencies."""
    if session.verbose:
        print("Setting up sandbox environment for ContextScan...")

    # Create the workspace structure
    session.execute_command("mkdir -p /sandbox/workspace/core")
    session.execute_command("mkdir -p /sandbox/workspace/utils")
    session.execute_command("mkdir -p /sandbox/workspace/data")
    session.execute_command("mkdir -p /sandbox/workspace/sandbox")
    session.execute_command("mkdir -p /sandbox/workspace/output")
    session.execute_command("mkdir -p /sandbox/workspace/base_genomes")

    if include_tests:
        session.execute_command("mkdir -p /sandbox/workspace/tests")

    # Copy sandbox scripts and environment configuration
    required_files = [
        ("sandbox/orchestrator.py", "/sandbox/workspace/sandbox/orchestrator.py"),
        (".env", "/sandbox/workspace/.env"),
        ("requirements-sandbox.txt", "/sandbox/workspace/requirements.txt"),
    ]

    # Core framework files
    session.copy_dir_to_runtime(src_dir="core", dest_dir="/sandbox/workspace/core", pattern="*.py")
    session.copy_dir_to_runtime(src_dir="utils", dest_dir="/sandbox/workspace/utils", pattern="*.py")
    session.copy_dir_to_runtime(src_dir="utils", dest_dir="/sandbox/workspace/utils", pattern="*.json")
    session.copy_dir_to_runtime(src_dir="data", dest_dir="/sandbox/workspace/data", pattern="*.py")

    if include_tests:
        session.copy_dir_to_runtime(src_dir="tests", dest_dir="/sandbox/workspace/tests", pattern="*.py")

    # Copy Radar Cache if it exists on host to avoid rebuilding in container
    radar_files = ["data/radar.bin", "data/radar.bin.hash"]
    for rf in radar_files:
        if os.path.exists(rf):
            session.copy_to_runtime(rf, f"/sandbox/workspace/{rf}")

    # Copy training data ONLY if not in test-only mode
    if not include_tests:
        train_data_path = "data/training_data.json"
        if os.path.exists(train_data_path):
            if max_samples is not None and max_samples > 0:
                import json
                import random
                import tempfile

                try:
                    with open(train_data_path, "r", encoding="utf-8") as f:
                        full_data = json.load(f)

                    sample_size = min(len(full_data), max_samples)
                    sampled_data = random.sample(full_data, sample_size)

                    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
                        json.dump(sampled_data, tmp, ensure_ascii=False, indent=4)
                        tmp_path = tmp.name

                    print(f"Subsampled {sample_size} records from training dataset for sandbox...")
                    session.copy_to_runtime(tmp_path, "/sandbox/workspace/data/training_data.json")
                    os.unlink(tmp_path)
                except Exception as e:
                    print(f"Warning: Failed to subsample training data: {e}. Attempting full copy.")
                    session.copy_to_runtime(train_data_path, "/sandbox/workspace/data/training_data.json")
            else:
                session.copy_to_runtime(train_data_path, "/sandbox/workspace/data/training_data.json")

    session.copy_dir_to_runtime(src_dir="base_genomes", dest_dir="/sandbox/workspace/base_genomes", pattern="*.py")

    for src_path, dest_path in required_files:
        if os.path.exists(src_path):
            # Normalize dest_path for Linux
            normalized_dest = dest_path.replace("\\", "/")
            # Ensure the directory exists
            parent_dir = os.path.dirname(normalized_dest)
            if parent_dir and parent_dir != "/":
                session.execute_command(f"mkdir -p {parent_dir}")

            session.copy_to_runtime(src_path, normalized_dest)
        elif session.verbose:
            print(f"Warning: Required file {src_path} not found")

    if reinstall:
        print("Installing python dependencies from requirements.txt...")
        pip_output = session.execute_command("pip install --no-cache-dir -r /sandbox/workspace/requirements.txt")
        print(pip_output)

    if session.verbose:
        print("Sandbox environment set up successfully!")
    return True
