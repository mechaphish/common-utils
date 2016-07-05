import string
import os
import subprocess
import random
import stat
from ..simple_logging import *


class BinaryTester(object):
    """
    Class that handles testing a binary
    """
    CRASH_RESULT = "C"
    FAIL_RESULT = "F"
    PASS_RESULT = "S"

    def __init__(self, binary, testcase, pcap_output_file=None, is_pov=False, is_cfe=True, timeout=None,
                 standlone=False):
        """
        Constructor of BinaryTester Object.
        :param binary: local folder containing binaries or
                       path to the binary to be tested.
        :param testcase: local path of the PoV to be tested
        :param pcap_output_file: File to which pcap output needs to be captured.
        :param is_pov: flag to indicate if this is a PoV
        :param is_cfe: flag to indicate if this is a cfe
        :param timeout: Timeout (for cb test)
        :return: BinaryTester Object
        """
        self.target_binary = os.path.abspath(binary)
        self.target_test = os.path.abspath(testcase)
        self.pcap_output_file = pcap_output_file
        self.is_pov = is_pov
        self.is_cfe = is_cfe
        self.timeout = timeout
        self.standalone = standlone

    def create_temp_dir(self):
        """
        Create a temp directory.
        :return: Directory name of the created temp directory.
        """
        dir_name = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        dir_name = os.path.join("/tmp", dir_name)
        self.run_command('rm -rf ' + str(dir_name))
        self.run_command('mkdir -p ' + str(dir_name))
        return dir_name

    def test_cb_binary(self):
        """
        Test the binary.
        :return: ret_code, output_text, error_text
        """

        def get_cb_test_args(binary_path, test_xml_path):
            if os.path.isdir(binary_path):
                binary_dir_path = binary_path
                binary_names = BinaryTester.find_all_executables(binary_dir_path)
            else:
                binary_dir_path = os.path.dirname(binary_path)
                binary_names = [os.path.basename(binary_path)]
            args = ['cb-test']
            if self.timeout:
                args.extend(['--timeout', str(int(self.timeout))])
            if self.is_cfe:
                args.extend(['--negotiate'])
            if self.is_pov:
                args.extend(['--should_core'])
            if self.pcap_output_file is not None:
                args.extend(['--pcap', str(self.pcap_output_file)])
            args.extend(['--cb'] + binary_names + ['--xml', test_xml_path] + ['--directory', binary_dir_path])
            return args

        def is_port_failure(stdout_text):
            if "cb-server: unable to bind port:" in stdout_text:
                return True
            else:
                return False

        base_cb_test_args = get_cb_test_args(self.target_binary, self.target_test)
        if self.standalone:
            # There is a race condition on port selection, I try to mitigate it by choosing a port
            port = 10000 + (os.getppid() % 5)*10000 + (os.getpid() % 100)*100 + random.randrange(0, 100)
            ret_code, output_text, error_text = self.run_command(base_cb_test_args + ["--port", str(port)])
            while is_port_failure(output_text):
                # If it fails I keep trying normally (cb-test picks a random port)
                # testing 1000 on 40 processes it fails on about 5-10
                ret_code, output_text, error_text = self.run_command(base_cb_test_args)
            return ret_code, output_text, error_text
        else:
            # Test the binary, in game mode.
            # we do not care if it fails because of port issue as it will be tested again.
            log_info("Trying to test binary:" + self.target_binary)
            ret_code, output_text, error_text = self.run_command(base_cb_test_args)
            log_success("Successfully Tested Binary:" + self.target_binary)
            # return Output
            return ret_code, output_text, error_text

    @staticmethod
    def find_all_executables(folder):
        """

        :param folder:
        :return:
        """
        executable_flag = stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
        return [f for f in os.listdir(folder) if os.stat(os.path.join(folder, f)).st_mode & executable_flag]

    @staticmethod
    def parse_cb_test_out(output_buf, ignore_cb_server_timeout=True):
        """
        Parse the output of the cb-test to get various performance counters.
        :param output_buf: Output of cb test
        :param ignore_cb_server_timeout: Ignore if cb-server fails, only consider polls and tests.
        :return: flag indicating if the performance counters have been computed,
                final_result (single letter indicating final result of the test)
                , Dictionary containing performance metrics in the following format:
                {"perf" : {
                            "rss": <long>
                            "flt": <long>
                            "cpu_clock": <long>
                            "task_clock": <long>
                             "utime": <long>
                          }
                }
        """
        final_result = None
        has_perf_counters = False
        performance_json = {"rss": 0, "flt": 0, "utime": 0.0,  "cpu_clock": 0, "task_clock": 0}

        # Performance counters
        # Format: (key check, split value, json key, type)
        performance_counters = {("cb-server: total maxrss", "total maxrss", "rss", long),
                                ("cb-server: total minflt", "total minflt", "flt", long),
                                ("cb-server: total sw-cpu-clock", "sw-cpu-clock", "cpu_clock", long),
                                ("cb-server: total sw-task-clock", "sw-task-clock", "task_clock", long),
                                ("cb-server: total utime", "utime", "utime", float)}
        total_failed = -1
        for curr_line in output_buf.split("\n"):
            for curr_perf_tuple in performance_counters:
                if (curr_perf_tuple[0] in curr_line) and len(curr_line.split(curr_perf_tuple[1])) > 1:
                    str_val = curr_line.split(curr_perf_tuple[1])[1].strip()
                    performance_json[curr_perf_tuple[2]] += curr_perf_tuple[3](str_val)
                    has_perf_counters = True
            if "total tests failed" in curr_line or "polls failed" in curr_line:
                total_failed = int(curr_line.split(":")[1])
            elif "SIGSEGV" in curr_line or "SIGFPE" in curr_line or "SIGILL" in curr_line:
                final_result = BinaryTester.CRASH_RESULT
            elif "SIGALRM" in curr_line:
                final_result = BinaryTester.FAIL_RESULT
            elif not ignore_cb_server_timeout and "not ok - process timed out" in curr_line:
                final_result = BinaryTester.FAIL_RESULT

        if total_failed > 0:
            final_result = BinaryTester.FAIL_RESULT
        elif final_result is None:
            final_result = BinaryTester.PASS_RESULT

        return has_perf_counters, final_result, {"perf": performance_json}

    @staticmethod
    def run_command(command_line):
        """
        Run the provided command line in shell
        :param command_line: shell command line to run
        :return: return_code, stdout, stderr
        """
        p = subprocess.Popen(command_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             close_fds=True)
        output_buf, error_buf = p.communicate()
        ret_code = p.returncode
        return ret_code, output_buf, error_buf
