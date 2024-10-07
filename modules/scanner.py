# import logging
import yara
from pathlib import Path
import time
from typing import Union
from colorama import Fore
from concurrent.futures import ThreadPoolExecutor, as_completed

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
        future = self.executor.submit(func, args)
        self.futures.append(future)
    
    def wait_on_result(self):
        for f in self.futures:
            f.result()
        
    def shutdown(self):
        self.executor.shutdown(wait=True)

    def up_thread(self):
        pass

    def down_thread(self):
        pass


class YaraScanner(ThreadRunProgram):
    """Class for scanning files using Yara rules."""

    def __init__(
        self,
        directory: Union[str, Path],
        rule_path: Union[str, Path],
        console_print=True,
    ):
        """
        Initialize YaraScanner with directory and rule path.
            directory: root directory to search over all files and sub directories.
            rule_path: str path to Yara rules.
        """ 
        
        super().__init__()
        self.directory = Path(directory)
        self.rule = yara.compile(filepath=str(rule_path), includes=False)

        self.console_print = (
            console_print  # print the path of the file is checking in console.
        )

        
        # self.logger = logging.getLogger(__name__)
        
    def scan_directory(self):
        """Scan files in the directory."""
        for file_path in self.directory.rglob("*"):
            self.assing_task_to_workers(self.scan_file, file_path)
            

    def start(self):
        print(Fore.GREEN + f"Scanning {self.directory} ...", Fore.RESET)
        self.scan_directory()
        
        self.wait_on_result()
        
        
    def scan_file(self, file_path: Path):
        """Scan a specific file."""
        # todo: use Semaphore?

        if file_path.is_file():  # pass if is a directory.

            # todo: remove this 2 line check to get better preformance:
            if self.console_print:
                print(file_path)

            self.file_path = file_path
            try:
                result = self.rule.match(
                    str(file_path),
                    callback=self.find_match,
                    which_callbacks=yara.CALLBACK_MATCHES,
                )

            except yara.Error:
                print(
                    Fore.LIGHTRED_EX + f"Couldn't read the file {file_path},",
                    Fore.RESET,
                )

    def find_match(self, data):
        """Find a match in the scanned file."""
        print(Fore.RED + f"{data['rule']}: {self.file_path}", Fore.RESET)
        return yara.CALLBACK_CONTINUE


if __name__ == "__main__":

    time.sleep(3)

    tic = time.perf_counter()
    directory = Path("C:/Program Files/Git/")
    rule_path = Path("./rules.yar")

    scanner = YaraScanner(directory, rule_path)
    scanner.start()

    toc = time.perf_counter()
    print(Fore.RED + f"{toc - tic:.2f}sec")
