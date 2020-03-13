"""
NI-XNET interface module.
ni
Implementation references:
* https://github.com/ni/nixnet-python
* https://buildmedia.readthedocs.org/media/pdf/nixnet/latest/nixnet.pdf
* https://nixnet.readthedocs.io/en/latest/
* https://www.ni.com/pdf/manuals/372840h.pdf

TODO: 
    * Check error situations and implementations

"""


import logging
import sys

import nixnet
from nixnet import xnet_constants
from nixnet import xnet_types

# Error codes defined in the NI-XNET-errors.txt
TIMEOUT_ERROR_CODE = -1074384886


logger = logging.getLogger(__name__)



def check_status(result, function, arguments):
    if result > 0:
        logger.warning(get_error_message(result))
    elif result < 0:
        raise NiXnetError(function, result, arguments)
    return result

class NiXnetBus(BusABC):
    """
    The CAN Bus implemented for the NI-XNET interface.

    .. warning::

        This interface does implement efficient filtering of messages, but
        the filters have to be set in :meth:`~can.interfaces.nican.NicanBus.__init__`
        using the ``can_filters`` parameter. Using :meth:`~can.interfaces.nican.NicanBus.set_filters`
        does not work.

    """

    def __init__(
        self, channel, can_filters=None, bitrate=None, log_errors=True, **kwargs
    ):
        """
        :param str channel:
            Name of the object to open (e.g. 'CAN0')

        :param int bitrate:
            Bitrate in bits/s

        :param list can_filters:
            See :meth:`can.BusABC.set_filters`.

        :param bool log_errors:
            If True, communication errors will appear as CAN messages with
            ``is_error_frame`` set to True and ``arbitration_id`` will identify
            the error (default True)

        :raises can.interfaces.nican.NiXnetError:
            If starting communication fails

        """
        if nixnet is None:
            raise ImportError(
                "The NI-XNET driver could not be loaded. "
            )

        self.channel = channel
        self.channel_info = "NI-XNET: " + channel
        if not isinstance(channel, bytes):
            channel = channel.encode()
			
            
        with nixnet.FrameInQueuedSession(self.channel) as self.input_session:
            with nixnet.FrameOutQueuedSession(self.channel) as self.output_session:
                self.input_session.start()
                # Start the input session manually to make sure that the first
                # # signal value sent before the initial read will be received.			
        
        super().__init__(
            channel=channel,
            can_filters=can_filters,
            bitrate=bitrate,
            log_errors=log_errors,
            **kwargs
        )

    def _recv_internal(self, timeout):
        """
        Read a message from a NI-XNET bus.

        :param float timeout:
            Max time to wait in seconds or None if infinite

        :raises can.interfaces.nican.NiXnetError:
            If reception fails
        """
       
       
        try:
			frames_pending =self.input_session.num_pend()
            if (frames_pending >0)
        except NiXnetError as e:
            if e.error_code == TIMEOUT_ERROR_CODE:
                return None, True
            else:
                raise

		rcvd_frame = self.input_session.frames.read(
			num_frames=1,		# Read one frame.
			timeout=timeout,
			frame_type=CanFrame)

		if rcvd_frame.type == CYCLIC_REMOTE || EVENT_REMOTE:
			is_remote_frame = True
			       
        msg = Message(
            timestamp=rcvd_frame.timestamp,
            channel=self.channel,
            is_remote_frame=is_remote_frame,
            is_error_frame=is_error_frame,
            is_extended_id=rcvd_frame.identifier.extended,
            arbitration_id=rcvd_frame.identifier,
            dlc=sizeof(rcvd_frame.payload),
            data=rcvd_frame.payload,
        )
        return msg, True

    def send(self, msg, timeout=None):
        """
        Send a message to NI-XNET.

        :param can.Message msg:
            Message to send

        :raises can.interfaces.nican.NiXnetError:
            If writing to transmit buffer fails.
            It does not wait for message to be ACKed currently.
        """
        if msg.is_extended_id:
            msgIsExtended = True
        else:
            msgIsExtended = False

        arb_id = xnet_types.CanIdentifier(msg.arbitration_id, extended = msgIsExtended)

        frame = xnet_types.CanFrame(arb_id, constants.FrameType.CAN_DATA, msg.data)

        self.output_session.frames.write([frame],timeout)

    def flush_tx_buffer():
        self.output_session.flush()

    def shutdown(self):
        """Close object."""
        self.input_session.close()
        self.output_session.close()


class NiXnetError(CanError):
    """Error from NI-XENT driver."""

    def __init__(self, function, error_code, arguments):
        super().__init__()
        #: Status code
        self.error_code = error_code
        #: Function that failed
        self.function = function
        #: Arguments passed to function
        self.arguments = arguments

    def __str__(self):
        return "Function %s failed:\n%s" % (
            self.function.__name__,
            get_error_message(self.error_code),
        )
