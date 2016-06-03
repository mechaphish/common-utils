def log_error(msg):
    """
    Log error message
    :param msg: Message to be logged
    :return: None
    """
    print("[!] " + str(msg))


def log_info(msg):
    """
    Log info message
    :param msg: Message to be logged
    :return: None
    """
    print("[*] " + str(msg))


def log_success(msg):
    """
    Log success message
    :param msg: Message to be logged
    :return: None
    """
    print("[+] " + str(msg))


def log_failure(msg):
    """
    Log failure message
    :param msg: Message to be logged
    :return: None
    """
    print("[-] " + str(msg))