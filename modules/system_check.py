import psutil
import os
import time
import logging


class CheckSystem:

    @staticmethod
    def get_system_info():
        # Get CPU usage
        cpu_usage = psutil.cpu_percent(interval=2)
        ram_info = psutil.virtual_memory()

        print(
            f"CPU Usage: {cpu_usage}%  RAM Usage is: {ram_info.percent}% of the total {ram_info.available / (1024 ** 3):.2f} GB"
        )

        # print(f"Total RAM: {ram_info.total / (1024 ** 3):.2f} GB")
        # print(f"Used RAM: {ram_info.used / (1024 ** 3):.2f} GB")

    @staticmethod
    def run_monitoring(pid):
        try:
            process = psutil.Process(pid)
            while True:
                cpu_usage = process.cpu_percent(interval=1)
                ram_usage = process.memory_percent()

                tic_disk_io = process.io_counters()
                time.sleep(1)
                toc_disk_io = process.io_counters()

                bytes_diff = toc_disk_io.read_bytes - tic_disk_io.read_bytes
                print(
                    f"CPU Usage:{cpu_usage}%  RAM Usage:{ram_usage:0.2f}%  DISK:{bytes_diff/1024:.2f} KB/s"
                )
                # return 0 if system resources are on full load:
                # if
        except psutil.NoSuchProcess:
            print(f"No process found with PID: {pid}")


if __name__ == "__main__":
    cs = CheckSystem()
    pid = os.getpid()

    cs.get_system_info()
    cs.run_monitoring(pid)
