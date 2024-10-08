from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod
import time
from colorama import Fore
import threading
import psutil


class ThreadRunProgram(ABC):
    def __init__(self):
        
        self.num_workers = 20  # default nubmer of threads
        self.inc_dec_workers = 5  # number of threads to increase or decrease
        self.generate_workers(self.num_workers)
        self.isactive = False # Either if the ThreadPoolExecutor is active or not!
        self.futures = []
        
    @abstractmethod
    def start(self):
        pass

    def restart(self, do_decrese_threads:bool=True):
        """Restart the current (running) executor with assining more or less threads. 

        Args:
            down_thread (bool): _description_
        """
        self.shutdown()
        self.isactive = False
        if do_decrese_threads is True:
            self.decrese_threads()
        else:
            self.increase_threads()
    
    def generate_workers(self, num_workers):
        self.isactive = True
        self.executor = ThreadPoolExecutor(num_workers, thread_name_prefix='ThreadPool'+ str(self))
    
    def assing_task_to_workers(self, func, args):
        try:
            future = self.executor.submit(func, args)
            self.futures.append(future)
        except RuntimeError as e:
            # Wait until an executor will be generated and then continue:
            while not self.isactive:
                print(Fore.MAGENTA + "No Thread!" + Fore.RESET)
                time.sleep(1)
            print(Fore.BLUE + "Got a Thread!" + Fore.RESET)
            
            # Handel the the path has been passed and there was no the executor for it:
            future = self.executor.submit(func, args)
            self.futures.append(future)
            
    def wait_on_result(self):
        for f in self.futures:
            f.result()
        
    def shutdown(self):
        self.executor.shutdown(wait=True)

    def increase_threads(self):
        self.num_workers = self.num_workers + self.inc_dec_workers
        print(Fore.GREEN + "Incresing the number of threads" + Fore.RESET)
        self.generate_workers(self.num_workers)

    def decrese_threads(self):
        self.num_workers = self.num_workers - self.inc_dec_workers
        print(Fore.MAGENTA + "Decresing the number of threads" + Fore.RESET)
        self.generate_workers(self.num_workers)
    
    def __str__(self):
        return self.__class__.__name__


class RunWithSysCheck:
    def __init__(self, object:ThreadRunProgram, pid) -> None:
        self.obj = object
        self.pid = pid
    
    def start_benchmark_time(self):
        time.sleep(3)
        tic = time.perf_counter()
        self.obj.start()
        toc = time.perf_counter()
        print(Fore.RED + f"{toc - tic:.2f}sec")
    
    def monitoring(self):
        
        process = psutil.Process(pid)
        
        while True:
            cpu_usage = process.cpu_percent(interval=1)
            ram_usage = process.memory_percent()

            tic_disk_io = process.io_counters()
            time.sleep(1)
            toc_disk_io = process.io_counters()

            bytes_diff = toc_disk_io.read_bytes - tic_disk_io.read_bytes
            print(
                f"CPU Usage:{cpu_usage}%  RAM Usage:{ram_usage:0.1f}%  DISK:{bytes_diff/1024:.2f} KB/s"
            )
            
            if cpu_usage > 5: # precent
                self.obj.restart(do_decrese_threads=True)
    
    def start_with_monitoring(self):
        th_monitor = threading.Thread(target=self.monitoring, args=(), name='MonitoringThread')
        
        # start monitoring the system
        th_monitor.start()
        
        # start the program
        self.obj.start()
        
        # Wait for all threads to complete
        th_monitor.join()
        
        
    
    
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

    run_with_syscheck.start_with_monitoring()
    

    # cs.get_system_info()
    # cs.run_func(pid)
