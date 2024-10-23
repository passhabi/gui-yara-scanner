# import logging
import yara
from pathlib import Path
from typing import Union
from colorama import Fore
import time
from concurrently import ThreadRunProgram
import queue


class YaraScanner(ThreadRunProgram):
    """Class for scanning files using Yara rules."""

    def __init__(
        self,
        directory: Union[str, Path],
        rule_path: Union[str, Path],
        log=False,
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

        self.yara_outputs_q = queue.Queue()
        self.file_counter = 0  # count the number of file thats we are scanning.
        # self.logger = logging.getLogger(__name__)

    def task(self) -> int:
        """Start scanning the given directory.

        Returns:
            int: Returns number of scanned files.
        """
        print(Fore.GREEN + f"Scanning {self.directory} ...", Fore.RESET)
        self.scan_directory()

        self.wait_on_result()
        
        # Signal that scanning is done by putting a special value in the queue:
        self.yara_outputs_q.put(None)
        # return number of scanned files after done scanning:
        # return self.file_counter

    def scan_directory(self):
        """Scan files in the directory."""
        for file_path in self.directory.rglob("*"):
            self.assign_task_to_workers(self.scan_file, file_path)

    def scan_file(self, file_path: Path):
        """Scan a specific file."""
        if file_path.is_file():  # pass if is a directory.
            self.file_counter += 1

            # todo: remove this 2 line check to get better performance:
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
        # put each output in the queue:
        self.yara_outputs_q.put(f"{data['rule']}:\n {self.file_path}") #custom output for yara
        return yara.CALLBACK_CONTINUE


    def get_number_tracked_file(self):
        return self.file_counter


if __name__ == "__main__":

    time.sleep(3)

    tic = time.perf_counter()
    directory = Path("C:/Program Files/Git/")
    rule_path = Path("./rules.yar")

    scanner = YaraScanner(directory, rule_path)
    scanner.trp_start()

    toc = time.perf_counter()
    print(Fore.RED + f"{toc - tic:.2f}sec")
