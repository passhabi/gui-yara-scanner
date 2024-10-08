from scanner import YaraScanner
from pathlib import Path
import os
from concurrently import RunWithSysCheck
import unittest


class TestYaraScanner(unittest.TestCase):
    
    def test_get_number_tracked_file_after_run(self):
        
        # Run the scan process
        directory = Path("C:/Program Files/Git/")
        rule_path = Path("./rules.yar")

        scanner = YaraScanner(directory, rule_path, console_print=False)
        run_with_syscheck = RunWithSysCheck(scanner, os.getpid())

        yara_output = run_with_syscheck.start_with_monitoring()
        
        test_output = 0
        # compute number of fiels;
        for file_path in directory.rglob("*"): 
            if file_path.is_file():
                test_output += 1
                
        self.assertEqual(test_output, yara_output)
        

if __name__ == '__main__':
    unittest.main()

