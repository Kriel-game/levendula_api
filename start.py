import signal
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
COMMANDS = (
    ("backend", [sys.executable, "-m", "uvicorn", "Backend.main:app", "--host", "127.0.0.1", "--port", "8000"]),
    ("frontend", [sys.executable, "-m", "streamlit", "run", "Frontend/app.py"]),
    ("maintenance status check", [sys.executable, "Karbantarto/karbantarto.py", "--check-only"]),
)


def stop_processes(processes):
    running = [process for process in processes if process.poll() is None]
    for process in running:
        try:
            if sys.platform == "win32":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGTERM)
        except (OSError, ValueError):
            process.terminate()

    for process in running:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    processes = []
    try:
        for name, command in COMMANDS:
            if sys.platform == "win32":
                process = subprocess.Popen(
                    command,
                    cwd=PROJECT_ROOT,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                )
            else:
                process = subprocess.Popen(
                    command, cwd=PROJECT_ROOT, start_new_session=True
                )
            processes.append(process)
            print(f"Started {name} (PID {process.pid}).", flush=True)

        while True:
            for (name, _), process in zip(COMMANDS[:2], processes[:2]):
                return_code = process.poll()
                if return_code is not None:
                    print(f"{name} exited with status {return_code}; stopping other services.", flush=True)
                    return return_code
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopping all services...", flush=True)
    finally:
        stop_processes(processes)


if __name__ == "__main__":
    sys.exit(main() or 0)
