# TCP client
import socket
import logging
import time
import sys
import random
import string

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)

try:
    logging.info('Conectare cu %s', str(server_address))
    sock.connect(server_address)
    time.sleep(3)

    current_time = time.time()

    while True:
        if time.time() - current_time > 2:
            break
        time.sleep(1)
        characters = string.ascii_letters + string.digits
        message = ''.join(random.choice(characters) for _ in range (20))

        sock.send(message.encode('utf-8'))

        data = sock.recv(1024)
        if len(data) > 0:
            current_time = time.time()
            logging.info('Content primit: "%s"', data.decode('utf-8'))
except KeyboardInterrupt:
    logging.info('closing socket')
    sock.close()
finally:
    logging.info('closing socket')
    sock.close()