import logging
import asyncore
import socket
import redis
import ipasn_redis as ipasn
import argparse

argParser = argparse.ArgumentParser(description='Whois server for ipasn history')
argParser.add_argument('-v', action='store_true', help='DEBUG logs activated')
argParser.add_argument('-l', action='store_true', help='Log queries along with source IP address and TCP port')
argParser.add_argument('-b', type=str, default="0.0.0.0", help='Binding address (default: 0.0.0.0)')
argParser.add_argument('-p', type=int, default=4343, help='TCP port (default: 4343)')
args = argParser.parse_args()

if args.v:
    logginglevel = logging.DEBUG
else:
    logginglevel = logging.INFO

logging.basicConfig(level=logginglevel, format="ipasn-whois %(created)-15s %(msecs)d %(levelname)8s %(thread)d %(name)s %(message)s")

log                     = logging.getLogger(__name__)

SIZE                    = 1024

# async handler based on the sample from the asyncore documentation

class IPASNHandler(asyncore.dispatcher):

    def __init__(self, conn_sock, client_address, server):
        self.server             = server
        self.client_address     = client_address
        self.buffer             = ""
        self.is_writable        = False

        asyncore.dispatcher.__init__(self, conn_sock)
        log.debug("created handler; waiting for loop")

    def readable(self):
        return True

    def writable(self):
        return self.is_writable

    def handle_read(self):
        log.debug("handle_read")
        data = self.recv(SIZE)
        log.debug("after recv")
        if data:
            log.debug("got data")
            self.buffer += data
            self.is_writable = True
        else:
            log.debug("got null data")

    def handle_write(self):
        log.debug("handle_write")
        if self.buffer:
            iplookup = self.buffer.rstrip()
            try:
                socket.inet_aton(iplookup)
            except:
                val = "Incorrect IPv4 address"
                log.info("junk query from %s:%s for %s" % (self.client_address[0], self.client_address[1], iplookup))
                sent = self.send(val)
                self.buffer = self.buffer[sent:]
                self.close()

            val = ""
            single=True

            for first_date, last_date, asn, block in ipasn.aggregate_history(iplookup):
                    val = first_date+"|"+last_date+"|"+asn+"|"+block+"|"+iplookup
                    if not single:
                        val = val+"\n"
                    single=False

            sent = self.send(val)

            if args.l:
                log.info("query from %s:%s for %s" % (self.client_address[0], self.client_address[1], iplookup))

            log.debug("sent data " + str(val))
            self.buffer = self.buffer[sent:]
            self.close()
        else:
            log.debug("nothing to send")
        if len(self.buffer) == 0:
            self.is_writable = False

    def handle_close(self):
        log.debug("handle_close")
        log.info("conn_closed: client_address=%s:%s" % \
                     (self.client_address[0],
                      self.client_address[1]))
        self.close()

class IPASNServer(asyncore.dispatcher):

    allow_reuse_address         = False
    request_queue_size          = 5
    address_family              = socket.AF_INET
    socket_type                 = socket.SOCK_STREAM

    def __init__(self, address, handlerClass=IPASNHandler):
        self.address            = address
        self.handlerClass       = handlerClass

        asyncore.dispatcher.__init__(self)
        self.create_socket(self.address_family, self.socket_type)

        if self.allow_reuse_address:
            self.set_reuse_addr()

        self.server_bind()
        self.server_activate()

    def server_bind(self):
        self.bind(self.address)
        log.debug("bind: address=%s:%s" % (self.address[0], self.address[1]))

    def server_activate(self):
        self.listen(self.request_queue_size)
        log.debug("listen: backlog=%d" % self.request_queue_size)

    def fileno(self):
        return self.socket.fileno()

    def serve_forever(self):
        asyncore.loop()

    def handle_accept(self):
        (conn_sock, client_address) = self.accept()
        if self.verify_request(conn_sock, client_address):
            self.process_request(conn_sock, client_address)

    def verify_request(self, conn_sock, client_address):
        return True

    def process_request(self, conn_sock, client_address):
        log.debug("conn_made: client_address=%s:%s" % \
                     (client_address[0],
                      client_address[1]))
        self.handlerClass(conn_sock, client_address, self)

    def handle_close(self):
        self.close()

server = IPASNServer((args.b, args.p))
server.serve_forever()
