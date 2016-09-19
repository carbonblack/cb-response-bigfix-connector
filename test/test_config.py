import time
from random import randrange
from threading import Thread

from test.t_tools import fake_bigfix_server as fake_bigfix_server

test_config_file_path = "/home/rad/files/doran-connector.config"


def mutate_to_test_config(
        fletch_config,
        fake_bigfix_server_enable=True,
        fake_bigfix_server_requests=2,
        bigfix_cache_enabled=False,
        bigfix_cache_package_interval=10,
        ssl_verification_off=True,
):
    """
    Whole purpose of this file is to allow for customizations of the standard
    configuration to allow for testing in a easy and customizable fashion.
    All testing setup reused by more than one or two test cases should be
    brought into this function.
    :param fletch_config: original 'production' configuration
    :param fake_bigfix_server_enable:  use our fake GET/POST echo service
    :param fake_bigfix_server_requests:  expected number of requests before
                    the fake server powers down.
    :param bigfix_cache_enabled: whether to use the caching mechanism for
                    requests to the bigfix server.
    :param bigfix_cache_package_interval: if using the cache, how frequently
                    it should be purged.
    :return: the modified configuration according to the parameters
    """
    if fake_bigfix_server_enable:
        port = randrange(40000, 50000)
        fletch_config.ibm_bigfix.url = 'localhost:{0}'.format(port)
        fletch_config.ibm_bigfix.protocol = 'http'
        fake_bigfix_server.max_requests_before_shutdown = \
            fake_bigfix_server_requests
        Thread(target=fake_bigfix_server.init_fake_server,
               kwargs={'port': port}
               ).start()
        time.sleep(1)

    fletch_config.ibm_bigfix.cache_enabled = bigfix_cache_enabled
    fletch_config.ibm_bigfix.packaging_interval = bigfix_cache_package_interval

    if not ssl_verification_off:
        fletch_config.ibm_bigfix.ssl_verify = False
        fletch_config.cb_comms.ssl_verify = False

    return fletch_config
