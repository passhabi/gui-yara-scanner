from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod
import time
from colorama import Fore
import threading
import psutil
import monkeytest


class ThreadRunProgram(ABC):
    def __init__(self):

        self.num_workers = 20  # default number of threads
        self.inc_dec_workers = 4  # number of threads to increase or decrease
        self.generate_workers(self.num_workers)
        self.isactive = False  # Either if the ThreadPoolExecutor is active or not!
        self.futures = []

    def trp_start(self):
        # the ThreadRunProgram subclasses, to assign each task to the workers usually use a for loop which will be a bottle neck for tk ui:
        threading.Thread(target=self.task, name="ThreadRoot_task", daemon=True).start()

    @abstractmethod
    def task():
        pass
    
    def restart(self, is_decrease_threads: bool = True):
        """Restart the current (running) executor with assining more or less threads.

        Args:
            down_thread (bool): _description_
        """
        self.shutdown()
        self.isactive = False

        if is_decrease_threads is True:
            self.decrease_threads()
        else:
            self.increase_threads()

    def generate_workers(self, num_workers):
        self.isactive = True
        self.executor = ThreadPoolExecutor(
            num_workers, thread_name_prefix="ThreadPool" + str(self)
        )

    def assign_task_to_workers(self, func, args):
        try:
            future = self.executor.submit(func, args)
            self.futures.append(future)
        except RuntimeError as e:
            # Wait until an executor will be generated and then continue:
            while not self.isactive:
                print(Fore.MAGENTA + "No Thread!" + Fore.RESET)
                time.sleep(0.5)
            print(Fore.BLUE + "Got a Thread!" + Fore.RESET)

            # Handel the the path has been passed and there was no the executor for it:
            future = self.executor.submit(func, args)
            self.futures.append(future)

    def wait_on_result(self):
        for f in self.futures:
            f.result()  # result method of ThreadPoolExecutor!

    def shutdown(self):
        self.executor.shutdown(wait=True)

    def increase_threads(self):
        self.num_workers = self.num_workers + self.inc_dec_workers
        print(Fore.GREEN + "Increasing the number of threads" + Fore.RESET)
        self.generate_workers(self.num_workers)

    def decrease_threads(self):
        num_workers = self.num_workers - self.inc_dec_workers
        self.num_worker = num_workers or 1  # check to have at least 1 worker.

        print(Fore.MAGENTA + "Decreasing the number of threads" + Fore.RESET)
        self.generate_workers(self.num_workers)

    def __str__(self):
        return self.__class__.__name__


class RunWithSysCheck:
    def __init__(self, object: ThreadRunProgram, pid, console_print=True) -> None:
        self.obj = object        
        self.pid = pid
        self.console_print = console_print
        

    def get_system_info(self):
        # Get CPU usage
        cpu_usage = psutil.cpu_percent(interval=1)
        ram_info = psutil.virtual_memory()

        print(
            f"CPU Usage: {cpu_usage}%  RAM Usage is: {ram_info.percent}% of the total {ram_info.available / (1024 ** 3):.2f} GB"
        )

        # Test Hdd with MonkeyTest:
        args = monkeytest.get_args()

        benchmark = monkeytest.Benchmark(
            file=args.file,
            write_mb=args.size,
            write_block_kb=args.write_block_size,
            read_block_b=args.read_block_size,
        ).print_result()

        # todo: get result of benchmarkfor further dues.

        # print(f"Total RAM: {ram_info.total / (1024 ** 3):.2f} GB")
        # print(f"Used RAM: {ram_info.used / (1024 ** 3):.2f} GB")

    def start_benchmark_time(self) -> str:
        """
        Returns:
            str: elapsed time in seconds.
        """
        time.sleep(3)
        tic = time.perf_counter()
        self.obj.trp_start()
        toc = time.perf_counter()

        elapsed_time = toc - tic
        return f"{elapsed_time:.2f} # returns time"

    def monitoring(self):
        """It runs the object task with monitoring. signals the task to use more threads or less."""
        process = psutil.Process(self.pid)

        while True:
            cpu_usage = process.cpu_percent(interval=1)
            ram_usage = process.memory_percent()

            tic_disk_io = process.io_counters()
            time.sleep(1)
            toc_disk_io = process.io_counters()

            bytes_diff = toc_disk_io.read_bytes - tic_disk_io.read_bytes

            if self.console_print:
                print(
                    f"CPU Usage:{cpu_usage}%  RAM Usage:{ram_usage:0.1f}%  DISK:{bytes_diff/1024:.2f} KB/s"
                )

            # if cpu_usage > 20:  # percent
            #     self.task.restart(is_decrease_threads=True)

            # if cpu_usage < 10:  # percent
            #     self.task.restart(is_decrease_threads=False)

    def start_task(self):
        #  a thread for monitoring and starting:
        th_monitor = threading.Thread(
            target=self.monitoring, name="MonitoringThread", daemon=True
        )
        # start monitoring the system
        th_monitor.start()

        # start the program
        self.obj.trp_start()
    

if __name__ == "__main__":
    from scanner import YaraScanner
    from pathlib import Path
    import os

    directory = Path("C:/Program Files/Git/")
    rule_path = Path("./rules.yar")

    scanner = YaraScanner(directory, rule_path, console_print=False)
    # scanner.start()

    pid = os.getpid()
    run_with_syscheck = RunWithSysCheck(scanner, pid)

    run_with_syscheck.start_task()

    # cs.get_system_info()
    # cs.run_func(pid)
