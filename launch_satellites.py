"""Launch multiple numbered satellite workers from one terminal.

Set the shared MASTER_* environment variables first, then run:
    python launch_satellites.py

Each child receives SATELLITE_ID=pc-local-<number> and PORT=9000+<number>.
"""

import os
import subprocess
import sys
from pathlib import Path


DEFAULT_START_PORT = 9001


def read_positive_int(prompt: str, default: int | None = None) -> int:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"{prompt}{suffix}: ").strip()
        if not raw and default is not None:
            return default
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            pass
        print("Vui lòng nhập một số nguyên lớn hơn 0.")


def main() -> None:
    worker_file = Path(__file__).with_name("satellite_worker.py")
    if not worker_file.is_file():
        raise SystemExit(f"Không tìm thấy worker: {worker_file}")
    if not os.environ.get("MASTER_URL") or not os.environ.get("MASTER_TOKEN"):
        raise SystemExit("Hãy đặt MASTER_URL và MASTER_TOKEN trước khi chạy launcher.")

    count = read_positive_int("Nhập số lượng pc-local")
    start_port = read_positive_int("Port bắt đầu", DEFAULT_START_PORT)
    logs_dir = Path(__file__).with_name("satellite_logs")
    logs_dir.mkdir(exist_ok=True)

    processes: list[tuple[subprocess.Popen, object]] = []
    try:
        for number in range(1, count + 1):
            satellite_id = f"pc-local-{number}"
            port = start_port + number - 1
            environment = os.environ.copy()
            environment["SATELLITE_ID"] = satellite_id
            # satellite_worker.py must read PORT. Change this key if it expects
            # a different variable name, such as SATELLITE_PORT.
            environment["PORT"] = str(port)

            log_file = (logs_dir / f"{satellite_id}.log").open("a", encoding="utf-8")
            process = subprocess.Popen(
                [sys.executable, str(worker_file)],
                cwd=worker_file.parent,
                env=environment,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
            processes.append((process, log_file))
            print(f"Đã chạy {satellite_id} | port {port} | PID {process.pid}")

        print("\nCác worker đang chạy. Nhấn Ctrl+C để dừng toàn bộ.")
        for process, _ in processes:
            process.wait()
    except KeyboardInterrupt:
        print("\nĐang dừng các worker...")
        for process, _ in processes:
            if process.poll() is None:
                process.terminate()
        for process, _ in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
    finally:
        for _, log_file in processes:
            log_file.close()


if __name__ == "__main__":
    main()
