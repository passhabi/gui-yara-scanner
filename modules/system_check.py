import psutil
import os
import time
# import logging
from .monkeytest import get_args, Benchmark
from concurrent.futures import ThreadPoolExecutor
import asyncio

class RunWithSysCheck:
    def __init__(self) -> None:
        # self.logger = logging.getLogger(__name__)
        pass
        
    def get_system_info(self):
        # Get CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        ram_info = psutil.virtual_memory()

        print(
            f"CPU Usage: {cpu_usage}%  RAM Usage is: {ram_info.percent}% of the total {ram_info.available / (1024 ** 3):.2f} GB"
        )

        # Test Hdd with MonkeyTest:
        args = get_args()
        
        benchmark = Benchmark(
        file=args.file,
        write_mb=args.size,
        write_block_kb=args.write_block_size,
        read_block_b=args.read_block_size,
        ).print_result()
        
        # todo: get result of benchmarkfor further dues.
        
        # print(f"Total RAM: {ram_info.total / (1024 ** 3):.2f} GB")
        # print(f"Used RAM: {ram_info.used / (1024 ** 3):.2f} GB")

    @staticmethod
    def run_func(pid, fn, *args, **kwargs):
        print("pid:", pid)
        process = psutil.Process(pid)
        
        excutor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="YaraScan")
            
        # Running the main function:
        feature = excutor.submit(fn, *args, **kwargs)
            
        # while True:
        #     cpu_usage = process.cpu_percent(interval=1)
        #     ram_usage = process.memory_percent()

        #     tic_disk_io = process.io_counters()
        #     time.sleep(1)
        #     toc_disk_io = process.io_counters()

        #     bytes_diff = toc_disk_io.read_bytes - tic_disk_io.read_bytes
        #     print(
        #         f"CPU Usage:{cpu_usage}%  RAM Usage:{ram_usage:0.2f}%  DISK:{bytes_diff/1024:.2f} KB/s"
        #     )
            
            # if cpu_usage > 30:
            #     excutor.shutdown(cancel_futures=True)

            

if __name__ == "__main__":
    cs = RunWithSysCheck()
    pid = os.getpid()

    cs.get_system_info()
    cs.run_func(pid)
