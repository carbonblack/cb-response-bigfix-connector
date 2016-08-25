"""
Data input service for setting up a TCP socket, listening to event forwarder
information, and placing it into the right event processing channels.

Overall data path:

-> cb-event-forwarder
 -> CbEventListener
  -> Channel("incoming_cb_events")
   -> CbEventHandler
    -> Channel("core_event_stream")

From the core event stream the output plugins can do whatever they'd like
to the data and ship it to where it needs to go.
"""
import logging
from json import loads as json_loads
from socket import socket, timeout
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from select import epoll, EPOLLIN
from threading import Thread


class CbEventListener(object):
    """
    Sets up a socket and listens to incoming data from the cb-event-forwarder.
    Only sends along JSON docs for the events we are truly interested in
    processing.
    https://docs.python.org/2/howto/sockets.html
    """

    def __init__(self, fletch_config, switchboard):
        """
        Starts a TCP listener on the specified port.
        Will listen on all IP addresses.
        Expects a connection from cb-event-forwarder. When received,
        it will spawn off sub-processes for each connection.
        Loops indefinitely, will never return unless on exception.
        :param fletch_config: Fletch Config object to read settings from
        :param switchboard: Reference to the message switchboard instance
        """
        self._listen_port = fletch_config.cb_event_listener.listen_port
        self._switchboard = switchboard
        self._shutdown = False
        self.logger = logging.getLogger(__name__)

        # create our channels in the switchboard
        self._incoming_chan = self._switchboard.channel(
            fletch_config.cb_event_listener.sb_incoming_cb_events)

        # start the listener
        Thread(target=self._open_listening_socket,
               name="cb_event_listener_server").start()

    def shutdown(self):
        self._shutdown = True

    def _open_listening_socket(self):
        """
        Start listening. For every received connection we spawn another thread
        to handle the data transfer.

        IMPORTANT: This will never return until a shutdown is called.
        Start this function as a target of a thread.
        """

        # open a TCP socket
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        # bind the socket to a public host,
        # and a well-known port
        server_socket.bind(('0.0.0.0', self._listen_port))

        # become a server socket
        server_socket.listen(5)

        # use epoll for waiting on connects but allowing timeouts to
        # check for shutdown status
        epoll_instance = epoll()
        epoll_instance.register(server_socket.fileno(), EPOLLIN)

        while not self._shutdown:
            # accept connections from outside
            # we use epoll here to sit and wait for a client to connect,
            # but we are still able to use a timeout for checking to see
            # if we should be shutting down.
            poll_data = epoll_instance.poll(timeout=1)
            for event in poll_data:
                (client_socket, address) = server_socket.accept()
                Thread(target=self._connection_handler,
                       args=(client_socket, address)).start()

        server_socket.close()

    def _connection_handler(self, client_socket, address):
        """
        Deals with receiving the actual JSON from over the wire.
        Submits a message to the core event channel for output processing.

        IMPORTANT: this function only returns once the connection is closed.
        Highly recommend this is within its own thread.
        """

        # ensure we timeout to check in and see if we should shutdown
        # our connection and close down operations.
        client_socket.settimeout(1)

        connection_alive = True
        self.logger.info("Opening Connection With %s", address)

        # this is a hack way to read data from the socket and
        # turn it into a JSON object without over-reading data.
        # TODO: refactor this into a better handler
        while connection_alive is True and self._shutdown is False:
            try:
                json_string = list()
                char = ''
                while char != '\n' and connection_alive is True:
                    char = client_socket.recv(1)
                    if not char:
                        connection_alive = False
                        self.logger.info("Closing Connection With %s",
                                         address)
                    else:
                        json_string.append(char)

                json_object = json_loads("".join(json_string))

                # TODO test case of sending watchlist hit through here
                accepted_message_types = [
                    "feed.storage.hit.process",
                    "watchlist.storage.hit.process"
                ]

                # assume keys are present, fetch what we need
                # (errors will be caught anyhow by the try-except wrapper)
                if json_object["type"] in accepted_message_types:
                    self.logger.debug("Received message of type: {0}".format(
                        json_object['type']
                    ))
                    self._incoming_chan.send(json_object)

                else:
                    self.logger.debug("Skipping unrelated object: {0}".format(
                        json_object["type"]))

            except timeout:
                pass

            except Exception as e:
                self.logger.exception(e)
