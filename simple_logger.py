
import logging
import graypy
import time

my_logger = logging.getLogger('test_logger')
my_logger.setLevel(logging.DEBUG)

handler = graypy.GELFTCPHandler('localhost', 12201)
my_logger.addHandler(handler)

while True:
    my_logger.debug('hello.')
    time.sleep(1)