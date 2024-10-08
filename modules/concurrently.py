from concurrent.futures import ThreadPoolExecutor
from abc import ABC, abstractmethod


class ThreadRunProgram(ABC):
    def __init__(self):
        
        self.workers = 20  # default nubmer of threads
        self.genereate_workers(self.workers)
        self.futures = []
        
    @abstractmethod
    def start(self):
        pass

    def restart(self, down_thread:bool):
        """Restart the current (running) executor with assining more or less threads. 

        Args:
            down_thread (bool): _description_
        """
        pass
    
    def genereate_workers(self, num_workers):
        self.executor = ThreadPoolExecutor(num_workers)
    
    def assing_task_to_workers(self, func, args):
        # try:
        future = self.executor.submit(func, args)
        self.futures.append(future)
        # except RejectedExecutionException as e:
        #     print(f"\33[35m has been shutdown.... {e}")
            
            
    def wait_on_result(self):
        for f in self.futures:
            f.result()
        
    def shutdown(self):
        self.executor.shutdown(wait=True)

    def up_thread(self):
        pass

    def down_thread(self):
        pass


class RunWithSysCheck:
    def __init__(self, object:ThreadRunProgram, pid) -> None:
        self.obj = object
        self.pid = pid
        
    def run(self):
        self.obj.main()
    
    def check_usage(self):
        pass
    
    def pause(self):
        pass
    
    def shutdown(self):
        pass
    
    
    
if __name__ == "__main__":
    cs = RunWithSysCheck()
    pid = os.getpid()

    cs.get_system_info()
    cs.run_func(pid)
