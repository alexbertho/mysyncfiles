"""Measure one Linux CLI child; sample logical I/O, measure rusage exactly."""
import json
import os
import resource
import signal
import subprocess
import sys
import tempfile
import threading
import time


def measure(command):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.perf_counter()
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        io = {}
        stopped = threading.Event()

        def sample_io():
            while not stopped.is_set():
                try:
                    with open(f"/proc/{child.pid}/io", encoding="ascii") as source:
                        io.update({key: int(value) for key, value in
                                   (line.split(":", 1) for line in source)})
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    pass  # Linux may deny access once the process has exited.
                stopped.wait(0.002)

        sampler = threading.Thread(target=sample_io)
        sampler.start()
        daemon_seconds = float(os.environ.get("MYSYNC_BENCH_DAEMON_SECONDS", "0"))
        timer = threading.Timer(
            daemon_seconds or 300,
            lambda: child.send_signal(signal.SIGTERM if daemon_seconds else signal.SIGKILL),
        )
        timer.start()
        try:
            os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
            wall_ms = (time.perf_counter() - started) * 1000
            child.wait()
        finally:
            stopped.set()
            sampler.join()
            timer.cancel()
            timer.join()
            if child.returncode is None:
                child.kill()
                child.wait()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        stdout.seek(0)
        stderr.seek(0)
        timings = {}
        errors = []
        for line in stderr.read().decode(errors="replace").splitlines():
            if line.startswith("MYSYNC_TIMING "):
                _, phase, milliseconds = line.split()
                timings[phase] = timings.get(phase, 0) + float(milliseconds)
            else:
                errors.append(line)
        return dict(
            wall_ms=wall_ms, user_ms=usage.ru_utime * 1000,
            sys_ms=usage.ru_stime * 1000, maxrss_kib=usage.ru_maxrss,
            in_blocks=usage.ru_inblock, out_blocks=usage.ru_oublock,
            io_sampled=io, io_sample_interval_ms=2,
            returncode=child.returncode, phases_ms=timings,
            stdout=stdout.read().decode(errors="replace").strip(),
            stderr="\n".join(errors[-8:]),
        )


if __name__ == "__main__":
    print(json.dumps(measure(sys.argv[1:])))
