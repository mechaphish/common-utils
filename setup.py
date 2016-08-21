from setuptools import setup

setup(
    name='common_utils',
    version='0.0.1',
    packages=['common_utils', 'common_utils.binary_tester', 'common_utils.pcap_parser', 'common_utils.poll_sanitizer',
              'common_utils.simple_logging'],
    description='Common utilities needed for testing, PCAP parsing and stuff.',
    url='https://github.com/mechaphish/common-utils',
)
