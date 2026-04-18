import sys
import argparse
from sandbox.sandbox import StreamingSandboxSession, setup_sandbox_environment

def main():
    parser = argparse.ArgumentParser(description="Run ContextScan Unit Tests in a Sandbox")
    parser.add_argument("--container", type=str, default="auto", choices=["docker", "podman", "auto"], help="Container runtime")
    parser.add_argument("--keep-template", action="store_true", help="Keep the image after the session is closed")
    parser.add_argument("--base-image", default="python:3.11-slim", help="The base container image to use for the sandbox.")
    parser.add_argument("--reinstall", action="store_true", help="Force re-installation of dependencies in the sandbox.")
    
    args = parser.parse_args()

    print(f"--- Initializing {args.container} test sandbox ---")
    
    session = StreamingSandboxSession(
        image=args.base_image,
        keep_template=args.keep_template,
        container_type=args.container
    )
    
    try:
        session.open()
        
        # Setup
        if setup_sandbox_environment(session, reinstall=args.reinstall, include_tests=True):
            print("\n--- Running Unit Tests ---")
            
            # Execute unittest inside the container
            command = "python -m unittest discover tests"
            for output in session.execute_command_streaming(command, workdir="/sandbox/workspace"):
                print(output, end="", flush=True)
                
    except Exception as e:
        print(f"Test execution failed: {e}")
        sys.exit(1)
    finally:
        session.close()

if __name__ == "__main__":
    main()
