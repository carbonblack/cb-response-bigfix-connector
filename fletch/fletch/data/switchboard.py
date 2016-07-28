from threading import Thread, RLock
from Queue import Queue, Empty as QEmpty
from logging import info as log_info
from logging import warn as log_warn
from logging import exception as log_exception


class CallBackData(object):
    """
    Simple enclosure for tracking data we are storing for
    doing callbacks.
    """
    def __init__(self, args, kwargs):
        self.args = args
        self.kwargs = kwargs


class Channel(object):
    """
    A message channel. Supports receiving messages and sending to
    registered listeners.
    """

    def __init__(self, name):

        # manager-style locking, only for non-async vars
        self._lock = RLock()
        self._callbacks = dict()
        self._callback_subscribe_id_counter = 1000
        self._shutdown_flag = False   # used to shutdown daemon threads
        self._name = name

        # no manager lock required
        self._queue = Queue()
        self._log_info = log_info
        self._log_warn = log_warn
        self._log_exception = log_exception

        # kick out our transmit_message thread.
        Thread(target=self._transmit_message,
               name="Chan-{0}-Transmit".format(self._name)).start()

    def _transmit_message(self):
        """
        Responsible for calling out to recipients with the data
        required. NOTE that we create a new thread here to perform
        the callback with.

        IMPORTANT: this function infinitely loops. Call it as the
        target of a thread.

        EXCEPTIONS: This function catches all raised exceptions to
        prevent the message transmissions from dying.
        """
        while True:
            try:
                callback_data = self._queue.get(timeout=1)

                # since we have real data (Empty would have been
                # raised otherwise), process it.
                self._lock.acquire()
                try:
                    for target_id in self._callbacks:
                        target = self._callbacks[target_id]
                        thread_name = "Chan-{0}-TX-{1}".format(self._name,
                                                               target_id)
                        Thread(target=target,
                               name=thread_name,
                               args=callback_data.args,
                               kwargs=callback_data.kwargs,
                               ).start()
                except Exception as e:
                    self._log_exception(e)
                self._lock.release()
                self._queue.task_done()

            except QEmpty as e:
                pass

            # check to see if we should shutdown
            # also check if we timed out or have real data
            if self._shutdown_flag is True:
                break

    def _get_unique_subscription_id(self):
        """
        Grabs a unique identifier for a subscriber.
        :return: uniqueID
        """
        self._lock.acquire()
        returnable_id = self._callback_subscribe_id_counter
        self._callback_subscribe_id_counter += 1
        self._lock.release()
        return returnable_id

    def shutdown(self):
        """
        Shutdown the channel, clean up whatever is running.
        """
        self._lock.acquire()
        self._shutdown_flag = True
        self._lock.release()

    def send(self, *args, **kwargs):
        """
        Add message to the queue. Accepts any
        arguments that the sender wishes. This will be passed along
        as arguments to the callback function.
        """
        self._queue.put(CallBackData(args, kwargs))

    def register_callback(self, callback):
        """
        Adds a function pointer for callbacks
        :param callback: the function
        :return: the numeric id needed for un-subscription
        """
        self._lock.acquire()
        target_id = self._get_unique_subscription_id()
        self._callbacks[target_id] = callback
        self._lock.release()
        return target_id

    def remove_callback(self, target_id):
        """
        Removes a specified callback from the listener list
        :param target_id: the callback's unique target id
        """
        self._lock.acquire()
        del self._callbacks[target_id]
        self._lock.release()


class Switchboard(object):
    """
    A pub-sub board. Maintains a queue for each type of message channel
    registered with us.

    For each channel we track who has registered listeners for the data.
    Specification of the function calls are the responsibility of the
    """

    def __init__(self):
        self._channels = {}

    def channel(self, name):
        """
        Create a new message channel to send messages to. If it already
        exists, it will simply return the one that is already made.
        This will not add any listeners! You must do that separately.
        :param name: Name for the channel
        """
        if name not in self._channels:
            self._channels[name] = Channel(name)
        return self._channels[name]

    def shutdown(self):
        """
        Performs a shutdown. Tells each channel to clean up and go away
        """
        for chan_id in self._channels:
            chan = self._channels[chan_id]
            chan.shutdown()









