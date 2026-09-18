import argparse
import datetime
import os
import shlex
import sys

from core.config import settings
from sandbox.sandbox import StreamingSandboxSession, setup_sandbox_environment


def main():
    parser = argparse.ArgumentParser(description="Run ContextScan Evolutionary Engine in a Sandbox")
    parser.add_argument(
        "--iterations", type=int, default=settings.default_iterations, help="Number of evolution iterations"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=settings.default_samples_per_iteration,
        help="Number of training samples to evaluate per iteration",
    )
    parser.add_argument(
        "--container", type=str, default="auto", choices=["docker", "podman", "auto"], help="Container runtime"
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    parser.add_argument("--keep-template", action="store_true", help="Keep the image after the session is closed")
    parser.add_argument(
        "--base-image", default="python:3.11-slim", help="The base container image to use for the sandbox."
    )
    parser.add_argument(
        "--reinstall", action="store_true", help="Force re-installation of dependencies in the sandbox."
    )
    parser.add_argument("--resume", action="store_true", help="Resume evolution from output/best_genome.pkl")
    parser.add_argument(
        "--directive",
        type=str,
        default=None,
        help="A specific directive for the evolution process (e.g., 'Focus on reducing false positives')",
    )

    args = parser.parse_args()

    # Generate a run ID
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")

    print(f"--- Initializing {args.container} sandbox ---")

    session = StreamingSandboxSession(
        image=args.base_image,
        keep_template=args.keep_template,
        verbose=args.verbose,
        container_type=args.container,
        lang="python",
    )

    try:
        print("--- Opening sandbox session ---")
        session.open()

        # 1. Setup the environment
        if setup_sandbox_environment(session, reinstall=args.reinstall):
            # Optional: Resume from previous best genome
            if args.resume:
                resume_file = settings.get_path("output_dir") / "best_genome.pkl"
                if resume_file.exists():
                    print(f"--- Resuming from {resume_file} ---")
                    session.copy_to_runtime(str(resume_file), "/sandbox/workspace/best_genome.pkl")
                else:
                    print(f"--- Warning: Resume requested but {resume_file} not found. Starting fresh. ---")

            # Debug: List workspace contents
            print("--- Sandbox Workspace Diagnostics ---")
            for chunk in session.execute_command_streaming("find /sandbox/workspace -maxdepth 3"):
                print(chunk, end="")
            print("\n------------------------------------")

            # 2. Run the orchestrator
            command = "python3 /sandbox/workspace/sandbox/orchestrator.py"
            env_vars = {
                "EVO_ITERATIONS": str(args.iterations),
                "SAMPLES_LIMIT": str(args.samples),
                "TRAINING_DATA": settings.default_training_data,
            }
            if args.directive:
                env_vars["EVO_DIRECTIVE"] = args.directive

            # Prepend config vars to the command and wrap it in sh -c
            env_prefix = " ".join([f"{k}={shlex.quote(v)}" for k, v in env_vars.items()])
            full_command = f"sh -c {shlex.quote(f'{env_prefix} {command}')}"

            print(f"\n--- Executing Evolutionary Engine (Run ID: {timestamp}) ---")

            # Use streaming execution for real-time feedback
            for output in session.execute_command_streaming(full_command):
                print(output, end="", flush=True)

            print("\n" + "-" * 20)
            print("--- Execution completed ---\n")

            # 3. Copy results back
            print("--- Checking for output data to copy back ---")
            host_output_folder = f"output/run_{timestamp}"
            os.makedirs(host_output_folder, exist_ok=True)

            # Copy evolution results
            session.copy_dir_from_runtime(src_dir="/sandbox/workspace/output", dest_dir=host_output_folder, pattern="*")

            # Persist Radar Cache back to host
            session.copy_dir_from_runtime(src_dir="/sandbox/workspace/data", dest_dir="data", pattern="radar.bin*")

            print(f"Results saved to: {host_output_folder}")

            # Also copy best_genome.pkl to the root output if it exists
            session.copy_dir_from_runtime(
                src_dir="/sandbox/workspace/output", dest_dir="output", pattern="best_genome.pkl"
            )
        else:
            print("Error: Failed to set up sandbox environment")

    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        print("\n--- Closing sandbox session ---")
        session.close()
        print("Session closed.")


if __name__ == "__main__":
    main()
