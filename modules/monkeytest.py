#!/usr/bin/env python
"""
MonkeyTest -- test your hard drive read-write speed in Python
A simplistic script to show that such system programming
tasks are possible and convenient to be solved in Python

The file is being created, then written with random data, randomly read
and deleted, so the script doesn't waste your drive

(!) Be sure, that the file you point to is not something
    you need, cause it'll be overwritten during test

Runs on both Python3 and 2, despite that I prefer 3
Has been tested on 3.5 and 2.7 under ArchLinux
Has been tested on 3.5.2 under Ubuntu Xenial
"""
from __future__ import division, print_function  # for compatability with py2

import os, sys
from random import shuffle
import argparse
from time import perf_counter as time

def get_args():
    parser = argparse.ArgumentParser(
        description="Arguments", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-f",
        "--file",
        required=False,
        action="store",
        default=str(os.path.join(".", "hdd_tempfile")),
        help="The file to read/write to",
    )
    parser.add_argument(
        "-s",
        "--size",
        required=False,
        action="store",
        type=int,
        default=128,
        help="Total MB to write",
    )
    parser.add_argument(
        "-w",
        "--write-block-size",
        required=False,
        action="store",
        type=int,
        default=1024,
        help="The block size for writing in bytes",
    )
    parser.add_argument(
        "-r",
        "--read-block-size",
        required=False,
        action="store",
        type=int,
        default=512,
        help="The block size for reading in bytes",
    )
    parser.add_argument(
        "-j", "--json", required=False, action="store", help="Output to json file"
    )
    args = parser.parse_args()
    return args


class Benchmark:

    def __init__(self, file, write_mb, write_block_kb, read_block_b):
        self.file = file
        self.file_size = write_mb
        self.write_block_kb = write_block_kb
        self.read_block_b = read_block_b
        wr_blocks = int(self.file_size * 1024 / self.write_block_kb)
        rd_blocks = int(self.file_size * 1024 * 1024 / self.read_block_b)
        self.write_results = self.write_test(1024 * self.write_block_kb, wr_blocks)
        self.read_results = self.read_test(self.read_block_b, rd_blocks)

    def write_test(self, block_size, blocks_count, show_progress=True):
        """
        Tests write speed by writing random blocks, at total quantity
        of blocks_count, each at size of block_size bytes to disk.
        Function returns a list of write times in sec of each block.
        """

        f = os.open(self.file, os.O_CREAT | os.O_WRONLY, 0o777)  # low-level I/O

        took = []
        for i in range(blocks_count):
            if show_progress:
                # dirty trick to actually print progress on each iteration
                sys.stdout.write(
                    "\rWriting: {:.2f} %".format((i + 1) * 100 / blocks_count)
                )
                sys.stdout.flush()
            buff = os.urandom(block_size)
            start = time()
            os.write(f, buff)
            os.fsync(f)  # force write to disk
            t = time() - start
            took.append(t)

        os.close(f)
        return took

    def read_test(self, block_size, blocks_count, show_progress=True):
        """
        Performs read speed test by reading random offset blocks from
        file, at maximum of blocks_count, each at size of block_size
        bytes until the End Of File reached.
        Returns a list of read times in sec of each block.
        """
        f = os.open(self.file, os.O_RDONLY, 0o777)  # low-level I/O
        # generate random read positions
        offsets = list(range(0, blocks_count * block_size, block_size))
        shuffle(offsets)

        took = []
        for i, offset in enumerate(offsets, 1):
            if (
                show_progress
                and i % int(self.write_block_kb * 1024 / self.read_block_b) == 0
            ):
                # read is faster than write, so try to equalize print period
                sys.stdout.write(
                    "\rReading: {:.2f} %".format((i + 1) * 100 / blocks_count)
                )
                sys.stdout.flush()
            start = time()
            os.lseek(f, offset, os.SEEK_SET)  # set position
            buff = os.read(f, block_size)  # read from position
            t = time() - start
            if not buff:
                break  # if EOF reached
            took.append(t)

        os.close(f)
        return took

    def _remove_tempfile_dec(self, func):
        def inner_func(*args, **kwargs):
            result = func(*args, **kwargs)
            os.remove(self.file)
            return result
        return inner_func
    
    

    def print_result(self):
        print(
            "\nWritten {filesize} MB in {time_in_sec:.4f} s\nWrite speed is  {write_speed:.2f} MB/s"
            "\nMax speed: {max:.2f}, Min speed: {min:.2f}\n".format(
                filesize=self.file_size,
                time_in_sec=sum(self.write_results),
                write_speed=self.file_size / sum(self.write_results),
                max=self.write_block_kb / (1024 * min(self.write_results)),
                min=self.write_block_kb / (1024 * max(self.write_results)),
            )
        )
        print(
            "Read {H_block} x {W_block} B blocks in {time_in_sec:.4f} s\nRead speed is  {read_speed:.2f} MB/s"
            "\nMax speed: {max:.2f}, Min speed: {min:.2f}\n".format(
                H_block=len(self.read_results),
                W_block=self.read_block_b,
                time_in_sec=sum(self.read_results),
                read_speed=self.file_size / sum(self.read_results),  # in MB
                max=self.read_block_b / (1024 * 1024 * min(self.read_results)),
                min=self.read_block_b / (1024 * 1024 * max(self.read_results)),
            )
        )
    

    def get_write_result(self):

        return {
            "filesize": self.file_size,
            "time_in_sec": sum(self.write_results),
            "write_speed": self.file_size / sum(self.write_results),
            "max_speed": self.write_block_kb / (1024 * min(self.write_results)),
            "min_speed": self.write_block_kb / (1024 * max(self.write_results)),
        }

    def get_read_result(self):
        return {
            "block_size": (
                len(self.read_results),
                self.read_block_b,
            ),
            "time_in_sec": sum(self.read_results),
            "read_speed": self.file_size / sum(self.read_results),  # in MB
            "max_speed": self.read_block_b / (1024 * 1024 * min(self.read_results)),
            "min_speed": self.read_block_b / (1024 * 1024 * max(self.read_results)),
        }



    



if __name__ == '__main__':
    args = get_args()
    
    benchmark = Benchmark(
        file=args.file,
        write_mb=args.size,
        write_block_kb=args.write_block_size,
        read_block_b=args.read_block_size,
    )
    
    benchmark.print_result()
    