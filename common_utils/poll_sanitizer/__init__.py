from ..simple_logging import *
from ..binary_tester import BinaryTester
from ..pcap_parser import PcapParser
from farnsworth.actions import CFE_POLL, Data, Write, Read, Match, cfe_poll_from_xml
import os
import binascii
import uuid

NEW_POLL_TEST_TIMES = 5  # Number of time Poll needs to be tested before considered stable.
END_READ_LENGTH = 10000  # Maximum amount of output we match
DARPA_POLL_HEADER = """<?xml version="1.0" standalone="no" ?>
                        <!DOCTYPE pov SYSTEM "/usr/share/cgc-docs/replay.dtd">
                    """
READ_TIME_OUT = 2  # 2 seconds
RANDOM_SEED_LENGTH = 96  # length of the random seed used while creating poll

IGNORE_CB_TEST_RET_CODE = True  # Flag to indicate whether to ignore cb-test return code and check only its output.


def __get_unique_fp(file_contents, optional_prefix='', optional_suffix=''):
    """
        Create a new non-exiting file and dump the contents and return corresponding path.
    :param file_contents: file contents.
    :param optional_prefix: Prefix to be used for file name
    :param optional_suffix: Suffix to be used for file name
    :return: Path of the newly created file.
    """
    target_file_path = os.path.join(os.path.expanduser("~"),  optional_prefix + str(uuid.uuid4()) + optional_suffix)
    while os.path.exists(target_file_path):
        target_file_path = os.path.join(os.path.expanduser("~"),  optional_prefix + str(uuid.uuid4()) + optional_suffix)
    xml_file_fd = open(target_file_path, 'w')
    xml_file_fd.write(str(file_contents))
    xml_file_fd.close()
    return target_file_path


def __check_poll_stability(cfe_poll_xml, target_cbs_bin, no_of_tries=NEW_POLL_TEST_TIMES, optional_prefix=''):
    """
        Check the stability of the provided poll xml.
        Basically, just test the provided poll.xml multiple times using cb-test
        if everything works fine, return success.
    :param cfe_poll_xml: Poll content to be tested.
    :param target_cbs_bin: Path to the folder (in case of multi-binary CS) or CB path
    :param no_of_tries: No of times the poll needs to be tested.
    :param optional_prefix: Prefix to be used while creating files.
    :return: (result, poll_test_res, ret_code).
            result: bool indicating whether the poll is success.
            poll_test_res: BinaryTester.PASS_RESULT or FAIL_RESULT or CRASH_RESULT
            ret_code: Return code of cb-test
    """
    # Test the newly generated poll for specified number of times, for sanity.
    poll_ok = True
    final_result = BinaryTester.PASS_RESULT
    ret_code = -1
    cfe_test_file = __get_unique_fp(cfe_poll_xml, optional_prefix=optional_prefix , optional_suffix='_test.xml')
    for i in range(no_of_tries):
        bin_tester = BinaryTester(target_cbs_bin, cfe_test_file, is_cfe=True, standlone=True)
        ret_code, output_text, _ = bin_tester.test_cb_binary()
        if IGNORE_CB_TEST_RET_CODE:
            _, final_result, _ = BinaryTester.parse_cb_test_out(output_text)
            if final_result != BinaryTester.PASS_RESULT:
                log_failure("Poll Test:" + cfe_test_file + " Number:" + str(i+1) + " Failed with Result=" +
                            str(final_result))
                poll_ok = False
                break
        elif ret_code != 0:
            log_failure("Poll Test:" + cfe_test_file + " Number:" + str(i+1) + " Failed with ret_code=" +
                        str(ret_code))
            _, final_result, _ = BinaryTester.parse_cb_test_out(output_text)
            poll_ok = False
            break
    os.system('rm ' + cfe_test_file)
    return poll_ok, final_result, ret_code


def __generate_poll_by_pcap(only_write_pov, target_cbs_bin, optional_prefix='', log_suffix=''):
    """
        Method to generate poll by generating PCAP.
        It first, verifies the provided Poll for crashes.
        if the poll does not lead to crashes then it will try to create a valid CFE poll using following procedure:
        Step 1:
        Create a pcap generator poll xml :
            with a random seed, append all write tags and at the end add a read tag with huge length.
        With the pacp generator xml, run cb-test and capture the pcap.
        Now, from the PCAP, generate a valid poll. Also, verify the generated poll certain number of times
        on unpatched binary, just in case.
    :param only_write_pov:
    :param target_cbs_bin: Path to the unpatched folder (in case of multi-binary CS) or CB path
    :param optional_prefix:
    :param log_suffix:
    :return:
    """

    def get_actual_data_pkts(curr_pkts, first_write_guy):
        """
            Get actual data pkts from the data captured from network.
            This is needed because, PCAP also captures seed negotiation
            and response. For this, we need to start considering pkts from
            the point where we do the first write.
        :param curr_pkts: All network pkts parsed from PCAP
        :param first_write_guy: First Write element in the Poll used to generate the PCAP.
        :return: list of pkts that need to be considered for creating Poll
        """

        to_ret = []
        if first_write_guy is not None:
            for i in range(len(curr_pkts)):
                curr_pkt = curr_pkts[i]
                if curr_pkt.is_input and len(first_write_guy.data_vars) > 0 and \
                   str(first_write_guy.data_vars[0].data) == curr_pkt.data:
                    to_ret = curr_pkts[i:]
                    break
        # if the PCAP does not contain expected write or we have no writes.
        # ignore first 2-packets (seed negotiation and response)
        if not to_ret:
            num_valid_pkts = 0
            for i in range(len(curr_pkts)):
                if num_valid_pkts >= NUM_NEGOTIATION_PKTS:
                    to_ret = curr_pkts[i:]
                    break
                curr_pkt = curr_pkts[i]
                if curr_pkt.data is not None:
                    num_valid_pkts += 1
        return to_ret

    # number of pkts in PCAP that are used for negotiation.
    NUM_NEGOTIATION_PKTS = 2
    temp_files = []
    valid_poll_xml = None
    poll_test_res = BinaryTester.FAIL_RESULT
    dummy_end_read = Read(length=END_READ_LENGTH)
    first_write_element = None
    if len(only_write_pov.actions) > 0:
        first_write_element = only_write_pov.actions[0]
    only_write_pov.actions.append(dummy_end_read)
    pcap_test_xml = __get_unique_fp(DARPA_POLL_HEADER + str(only_write_pov), optional_prefix=optional_prefix,
                                    optional_suffix='_pcap_test.xml')
    temp_files.append(pcap_test_xml)

    # Making sure that no other thread is using it.
    pcap_output_file = __get_unique_fp('', optional_prefix=optional_prefix, optional_suffix='_gen.pcap')
    temp_files.append(pcap_output_file)
    # create pcap file
    bin_tester = BinaryTester(target_cbs_bin, pcap_test_xml, is_cfe=True, pcap_output_file=pcap_output_file,
                              timeout=READ_TIME_OUT, standlone=True)
    ret_code, _, _ = bin_tester.test_cb_binary()

    if os.path.exists(pcap_output_file):
        if ret_code:
            log_success("Good, we were able to read everything from binary." + str(log_suffix))
        else:
            log_failure("The binary could produce more than:" + str(END_READ_LENGTH) +
                        ' bytes of data. Considering only ' + str(END_READ_LENGTH) + ' bytes to compare.' +
                        str(log_suffix))

        # parse the PCAP to get the data outputted by the binary
        log_info("Parsing PCAP:" + pcap_output_file + " to Poll Xml." + str(log_suffix))
        try:
            bin_data_stream = PcapParser(pcap_output_file).get_data_stream()
            new_actions = []
            # Get valid data pkts from PCAP.
            valid_pcap_data_pkts = get_actual_data_pkts(bin_data_stream.data_pkts, first_write_element)
            if len(valid_pcap_data_pkts) == 0:
                # if we expect some data? log failure.
                if len(bin_data_stream.data_pkts) > NUM_NEGOTIATION_PKTS:
                    log_failure("Potential Bug, There are " + str(len(bin_data_stream.data_pkts)) +
                                " pkts, but there are no valid data pkts")
                # return PASS
                poll_test_res = BinaryTester.PASS_RESULT
            else:
                # Get the data pkts from PCAP and construct a Poll.
                for curr_packet in valid_pcap_data_pkts:
                    # If this is output from binary, then we should expect this in Poll
                    if curr_packet.is_output:
                        curr_action = Read(length=len(curr_packet.data), match=Match([Data(curr_packet.data)]))
                    # else, if this is input then we should write this.
                    elif curr_packet.is_input:
                        curr_action = Write([Data(curr_packet.data)])
                    else:
                        log_failure("Got unknown action:" + str(curr_packet) + " from PCAP." + str(log_suffix))
                    new_actions.append(curr_action)
                # Create the resulting poll
                new_pov = CFE_POLL(only_write_pov.target, only_write_pov.seed, new_actions)
                # Check the stability of the Poll.
                is_poll_ok, poll_test_res, ret_code = __check_poll_stability(DARPA_POLL_HEADER + str(new_pov),
                                                                             target_cbs_bin,
                                                                             optional_prefix=optional_prefix)
                if is_poll_ok:
                    valid_poll_xml = DARPA_POLL_HEADER + str(new_pov)

        except Exception as e:
            log_error("Error occured:" + str(e) + ", while trying to generate poll from PCAP." + str(log_suffix))

    # clean up
    for curr_t_file in temp_files:
        os.system('rm ' + str(curr_t_file))

    return valid_poll_xml, poll_test_res, ret_code


def sanitize_pcap_poll(cfe_poll_xml, target_cbs_bin, optional_prefix='', log_suffix=''):
    """
        Method to generate a valid CFE Poll from poll extracted from PCAP.

    :param cfe_poll_xml: XML of the poll extracted from PCAP.
    :param target_cbs_bin: Path to the unpatched folder (in case of multi-binary CS) or CB path
    :param optional_prefix: Optional Prefix (helps in maintaining isolation in case of multi-threaded execution)
    :param log_suffix: Suffix to be used for logging.
    :return: (poll_xml, poll_test_res, ret_code).
            poll_xml: Valid CFE POLL XML, generated from provided cfe poll.
            poll_test_res: BinaryTester.PASS_RESULT or FAIL_RESULT or CRASH_RESULT
            ret_code: Return code of cb-test
    """
    # Check if we get lucky and the poll is valid
    is_poll_ok, poll_test_res, ret_code = __check_poll_stability(cfe_poll_xml, target_cbs_bin)
    if is_poll_ok:
        log_success("Poll generated from PCAP is valid!" + str(log_suffix))
        return cfe_poll_xml, poll_test_res, ret_code
    if poll_test_res == BinaryTester.CRASH_RESULT:
        log_failure("Poll generated from PCAP results in Crash, This is a potential Exploit." + str(log_suffix))
        return None, poll_test_res, ret_code
    log_info("Original Poll is Invalid, Trying to generate from PCAP.")
    log_info("Trying to generate Poll by using cb-test." + str(log_suffix))

    # Nope, we need to create a new poll
    cfe_poll = cfe_poll_from_xml(cfe_poll_xml)
    # get only writes from POLL and generate Poll.
    only_writes = filter(lambda x: isinstance(x, Write), cfe_poll.actions)
    only_write_pov = CFE_POLL(cfe_poll.target, cfe_poll.seed, only_writes)

    return __generate_poll_by_pcap(only_write_pov, target_cbs_bin, optional_prefix=optional_prefix,
                                   log_suffix=log_suffix)


def generate_poll_from_input(input_data, target_cbs_bin, cbn_id, optional_prefix='', log_suffix=''):
    """
        Method to generate CFE Poll from input data.

    :param input_data: input from which Poll needs to be created.
    :param target_cbs_bin: Path to the unpatched folder (in case of multi-binary CS) or CB path
    :param cbn_id: cbn or cs id of the binary to be tested.
    :param optional_prefix: Optional Prefix (helps in maintaining isolation in case of multi-threaded execution)
    :param log_suffix: Suffix to be used for logging.
    :return: (poll_xml, poll_test_res, ret_code).
            poll_xml: Valid CFE POLL XML, generated from provided cfe poll.
            poll_test_res: BinaryTester.PASS_RESULT or FAIL_RESULT or CRASH_RESULT
            ret_code: Return code of cb-test
    """
    # Create Random Seed.
    rand_seed = binascii.b2a_hex(os.urandom(RANDOM_SEED_LENGTH))
    rand_seed = rand_seed[0:RANDOM_SEED_LENGTH]
    # Create Poll Xml with single write.
    default_actions = [Write([Data(input_data)])]
    target_poll = CFE_POLL(cbn_id, rand_seed, list(default_actions))
    cfe_test_xml_content = DARPA_POLL_HEADER + str(target_poll)
    # First, just check with input.
    is_poll_ok, poll_test_res, ret_code = __check_poll_stability(cfe_test_xml_content, target_cbs_bin, no_of_tries=1)
    # if input itself leads to crash, then exit.
    if not is_poll_ok:
        return None, poll_test_res, ret_code
    return __generate_poll_by_pcap(target_poll, target_cbs_bin, optional_prefix=optional_prefix,
                                   log_suffix=log_suffix)
