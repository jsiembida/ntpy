#!/usr/bin/env python3


#   Copyright 2024 Jarek Siembida
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


#
# Pure Python, clean room implementation of NTP4 client.
#
# https://datatracker.ietf.org/doc/html/rfc5905
#

# Type annotations, refactoring and docstrings by Tamas Nepusz <ntamas@gmail.com>

import logging
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from ipaddress import IPv6Address, ip_address
from random import random
from socket import AF_INET, AF_INET6, SOCK_DGRAM, gaierror, getaddrinfo, socket
from struct import pack, unpack
from time import sleep, time
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from argparse import ArgumentParser

VERSION = 4
TOLERANCE = 15e-6  # 15 us/s (clock drift assumed in RFC)
PRECISION = -18  # 2**-18 s (again, this is assumed in RFC)
MINPOLL = 16  # 16 s
MAXPOLL = 3600  # 1 h
MAXDISP = 16  # 16 s
MINDISP = 0.005  # 5 ms
MAXDIST = 1
MAXSTRAT = 16
NSTAGE = 8
NMIN = 3
NOSYNC = 3


log = logging.getLogger("ntp")


def ntptime(t: float | None = None) -> tuple[int, int]:
    """Convert a Unix timestamp to an NTP timestamp tuple.

    Args:
        t: Unix time in seconds. If omitted, the current system time is used.

    Returns:
        A ``(seconds, fraction)`` tuple in NTP 64-bit fixed-point format,
        where ``seconds`` are counted from the NTP epoch (1900-01-01) and
        ``fraction`` contains the 32-bit fractional part.
    """
    if t is None:
        t = time()
    secs = int(t)
    frac = int(4294967296 * (t - secs))
    # Secs from 1900/01/01
    return secs + 2208988800, frac


class NtpError(Exception):
    """Base class for NTP-related errors."""

    pass


class NtpUnsynchronizedError(NtpError):
    """Raised when synchronization data is unavailable or unusable."""

    pass


class NtpDeniedError(NtpError):
    """Raised when an NTP server denies the client's request."""

    pass


class NtpThrottledError(NtpError):
    """Raised when an NTP server asks the client to reduce its query rate."""

    pass


class NtpPacketError(NtpError):
    """Raised when an NTP packet is malformed or inconsistent."""

    pass


class NtpMessage:
    """Representation of an NTP packet and its associated local timing data."""

    def __init__(
        self,
        *,
        delay: float = MAXDISP,
        dispersion: float = MAXDISP,
        leap: int = NOSYNC,
        mode: int = 3,
        poll: int = MINPOLL,
        precision: int = PRECISION,
        reference: bytes = b"",
        stratum: int = MAXSTRAT,
        t: float | None = None,
        t_dst: tuple[int, int] = (0, 0),
        t_org: tuple[int, int] = (0, 0),
        t_rec: tuple[int, int] = (0, 0),
        t_ref: tuple[int, int] = (0, 0),
        t_xmt: tuple[int, int] = (0, 0),
        version: int = VERSION,
    ):
        """Initialize an NTP message.

        The constructor arguments map directly to the NTP message fields used
        by this implementation, including the timestamp tuples carried by the
        packet and the local receive timestamp recorded in ``t``.
        """
        if t is None:
            t = time()

        self.delay = delay
        self.dispersion = dispersion
        self.leap = leap
        self.mode = mode
        self.poll = poll
        self.precision = precision
        self.reference = reference
        self.stratum = stratum
        self.t = t
        self.t_dst = t_dst
        self.t_org = t_org
        self.t_rec = t_rec
        self.t_ref = t_ref
        self.t_xmt = t_xmt
        self.version = version

    @staticmethod
    def to_short(x: int | float) -> tuple[int, int]:
        """Convert a value to the NTP short fixed-point format.

        Args:
            x: Delay or dispersion value in seconds, expressed as an integer or
                floating-point number.

        Returns:
            A ``(seconds, fraction)`` tuple representing the 16.16 fixed-point
            NTP short format.

        Raises:
            NtpError: If ``x`` is not an ``int`` or ``float``.
        """
        # Page 13, short format is 32bit, unsigned, fixed point.
        if isinstance(x, int):
            return x & 0xFFFF, 0
        if isinstance(x, float):
            secs = int(x)
            frac = int(65536 * (x - secs))
            return secs & 0xFFFF, frac & 0xFFFF
        raise NtpError("Invalid NTP short format value")

    @staticmethod
    def to_timestamp(x: int | float) -> tuple[int, int]:
        """Convert a value to the full NTP timestamp format.

        Args:
            x: Timestamp value in seconds, expressed as an integer or
                floating-point number.

        Returns:
            A ``(seconds, fraction)`` tuple representing the 32.32 fixed-point
            NTP timestamp format.

        Raises:
            NtpError: If ``x`` is not an ``int`` or ``float``.
        """
        # Page 13, timestamp is 64bit, unsigned, fixed point.
        if isinstance(x, int):
            return x & 0xFFFFFFFF, 0
        if isinstance(x, float):
            secs = int(x)
            frac = int(4294967296 * (x - secs))
            return secs & 0xFFFFFFFF, frac & 0xFFFFFFFF
        raise NtpError("Invalid NTP timestamp value")

    @staticmethod
    def from_short(secs: int, frac: int) -> float:
        """Convert an NTP short fixed-point value to seconds.

        Args:
            secs: Integer part of the 16.16 fixed-point value.
            frac: Fractional part of the 16.16 fixed-point value.

        Returns:
            The decoded value in seconds as a floating-point number.
        """
        return secs + frac / 65536

    @staticmethod
    def from_timestamp(secs: int, frac: int) -> float:
        """Convert an NTP timestamp value to seconds.

        Args:
            secs: Integer part of the 32.32 fixed-point timestamp.
            frac: Fractional part of the 32.32 fixed-point timestamp.

        Returns:
            The decoded timestamp in seconds as a floating-point number.
        """
        return secs + frac / 4294967296

    def serialize(self) -> bytes:
        """Serialize the message to the wire format used by NTP.

        Returns:
            The 48-byte binary representation of the NTP packet.
        """
        b1 = ((self.leap & 3) << 6) | ((self.version & 7) << 3) | ((self.mode & 7) << 0)
        delay_secs, delay_frac = self.to_short(self.delay)
        dispersion_secs, dispersion_frac = self.to_short(self.dispersion)
        t_ref_secs, t_ref_frac = self.t_ref
        t_org_secs, t_org_frac = self.t_org
        t_rec_secs, t_rec_frac = self.t_rec
        t_xmt_secs, t_xmt_frac = self.t_xmt
        reference_bytes = self.reference[:4].ljust(4, b"\0")

        return pack(
            "!BBbbHHHH4sLLLLLLLL",
            b1,
            self.stratum,
            self.poll,
            self.precision,
            delay_secs,
            delay_frac,
            dispersion_secs,
            dispersion_frac,
            reference_bytes,
            t_ref_secs,
            t_ref_frac,
            t_org_secs,
            t_org_frac,
            t_rec_secs,
            t_rec_frac,
            t_xmt_secs,
            t_xmt_frac,
        )

    @staticmethod
    def deserialize(b: bytes, t: float | None = None) -> "NtpMessage":
        """Parse an NTP server response from its wire representation.

        Args:
            b: Raw packet payload received from the network.
            t: Local Unix timestamp recorded when the packet was received. If
                omitted, the current system time is used.

        Returns:
            An ``NtpMessage`` populated from the received packet, with the local
            destination timestamp stored in ``t_dst``.

        Raises:
            NtpPacketError: If the packet length, version, mode, or required
                timestamps are invalid.
            NtpDeniedError: If the server returned a kiss-o'-death response that
                denies service.
            NtpThrottledError: If the server returned a kiss-o'-death response
                requesting a lower query rate.
        """
        if t is None:
            t = time()

        b = b[:48]
        if len(b) != 48:
            raise NtpPacketError("Invalid packet")

        (
            b1,
            stratum,
            poll,
            precision,
            delay_secs,
            delay_frac,
            dispersion_secs,
            dispersion_frac,
            reference_bytes,
            t_ref_secs,
            t_ref_frac,
            t_org_secs,
            t_org_frac,
            t_rec_secs,
            t_rec_frac,
            t_xmt_secs,
            t_xmt_frac,
        ) = unpack("!BBbbHHHH4sLLLLLLLL", b)

        leap = (b1 >> 6) & 3
        version = (b1 >> 3) & 7
        mode = (b1 >> 0) & 7

        if version != VERSION and version != 3:
            raise NtpPacketError("Invalid response version")

        if mode != 4:  # We only handle client - server use case.
            raise NtpPacketError("Invalid response mode")

        if stratum == 0:
            if reference_bytes == b"DENY" or reference_bytes == b"RSTR":
                raise NtpDeniedError
            if reference_bytes == b"RATE":
                raise NtpThrottledError

        if t_ref_secs == 0 and t_ref_frac == 0:
            raise NtpPacketError("Invalid t_ref in response")
        if t_rec_secs == 0 and t_rec_frac == 0:
            raise NtpPacketError("Invalid t_rec in response")
        if t_xmt_secs == 0 and t_xmt_frac == 0:
            raise NtpPacketError("Invalid t_xmt in response")

        return NtpMessage(
            delay=NtpMessage.from_short(delay_secs, delay_frac),
            dispersion=NtpMessage.from_short(dispersion_secs, dispersion_frac),
            leap=leap,
            mode=mode,
            poll=poll,
            precision=precision,
            reference=reference_bytes,
            stratum=stratum,
            t=t,
            t_dst=ntptime(t),
            t_org=(t_org_secs, t_org_frac),
            t_rec=(t_rec_secs, t_rec_frac),
            t_ref=(t_ref_secs, t_ref_frac),
            t_xmt=(t_xmt_secs, t_xmt_frac),
            version=version,
        )


class NtpState:
    """Snapshot of the time-quality metrics derived from NTP samples."""

    def __init__(
        self,
        *,
        delay: float = MAXDISP,
        dispersion: float = MAXDISP,
        jitter: int = 0,
        offset: float = 0,
        t: float | None = None,
    ):
        """Initialize a state snapshot.

        Args:
            delay: Estimated round-trip network delay in seconds.
            dispersion: Estimated maximum error of the sample in seconds.
            jitter: Variation between recent offset samples, in seconds.
            offset: Estimated correction to apply to the local clock, in
                seconds.
            t: Local Unix timestamp at which the state was computed. If
                omitted, the current system time is used.
        """
        if t is None:
            t = time()

        self.delay = delay
        self.dispersion = dispersion
        self.jitter = jitter
        self.offset = offset
        self.t = t

    def __str__(self):
        return "offset=%g delay=%g dispersion=%g jitter=%g" % (
            self.offset,
            self.delay,
            self.dispersion,
            self.jitter,
        )


class NtpAssociation:
    """Maintain polling state and statistics for a single NTP peer."""

    def __init__(
        self,
        *,
        address: str,
        port: int = 123,
        precision: int = PRECISION,
        tolerance: float = TOLERANCE,
        start_randomization: float | None = None,
        max_poll: int | None = None,
    ):
        """Initialize an association with a single NTP server.

        Args:
            address: IPv4 or IPv6 address of the remote NTP server.
            port: UDP port of the remote NTP server.
            precision: Local clock precision encoded as a base-2 exponent.
            tolerance: Assumed maximum local clock drift, in seconds per
                second.
            start_randomization: Optional maximum initial random delay, in
                seconds, used to stagger the first poll.
            max_poll: Optional upper bound for the polling interval, in
                seconds.
        """
        ip = ip_address(address)
        self.ipv6 = isinstance(ip, IPv6Address)
        self.address = (address, port)
        self.precision = precision
        self.tolerance = tolerance
        self.outgoing = None
        self.max_poll = max_poll
        t = time()
        self.incoming = NtpMessage(t=t)
        # RFC discusses reachability and timeouts. We don't do anything
        # special in this respect. Timeouts fill the register with dummy
        # stats. Which in turn makes the aggregate metrics degrade.
        # So all we do is select the peers that meet a fitness threshold.
        self.register = [NtpState(t=t) for _ in range(NSTAGE)]
        self.calculate_state(t)
        # Don't burst out all queries at once, randomize them within 5s.
        self.poll = MINPOLL
        self.poll_t = t
        if start_randomization is not None:
            self.poll_t += random() * start_randomization  # noqa: S311
        log.info("NTP association %s initialized", self)
        log.debug("%s Scheduled at %s", self, self.poll_t)

    def __hash__(self) -> int:
        return hash(self.address)

    def __eq__(self, other: object):
        if isinstance(other, NtpAssociation):
            return self.address == other.address
        if isinstance(other, tuple):
            return self.address == other
        return False

    def __str__(self) -> str:
        return "%s" % self.address[0]

    def __repr__(self) -> str:
        return self.__str__()

    def schedule_poll(self, t: float | None = None) -> None:
        """Schedule the next poll time for this peer.

        The next poll is jittered slightly around the current polling interval
        to avoid synchronized bursts against multiple servers.

        Args:
            t: Local Unix timestamp to use as the scheduling base. If omitted,
                the current system time is used.
        """
        if t is None:
            t = time()

        self.poll = min(MAXPOLL, self.poll)
        if self.max_poll is not None:
            self.poll = min(self.max_poll, self.poll)
        self.poll = max(MINPOLL, self.poll)

        interval = self.poll + random() * self.poll / 2 - self.poll / 4  # noqa: S311
        self.poll_t = t + interval
        self.poll *= 1.5
        log.debug("%s Scheduled in %s secs at %s", self, interval, self.poll_t)

    def calculate_state(self, t: float | None = None) -> None:
        """Recompute the aggregate peer state from the sample register.

        Args:
            t: Local Unix timestamp to associate with the newly computed state.
                If omitted, the current system time is used.

        Returns:
            None.
        """
        if t is None:
            t = time()

        del self.register[:-NSTAGE]
        register = sorted(self.register, key=lambda x: x.delay)

        offset = register[0].offset
        delay = register[0].delay
        dispersion = sum(r.dispersion / (2**i) for i, r in enumerate(register, 1))
        jitter = (
            sum((r.offset - offset) ** 2 for r in register) / (len(register) - 1) ** 0.5
        )

        self.state = NtpState(
            offset=offset,
            delay=delay,
            dispersion=dispersion,
            jitter=jitter,
            t=t,
        )

    def root_distance(self, t: float | None = None) -> float:
        """Estimate the peer's root distance.

        Root distance is the synchronization error bound used by NTP selection.
        It combines network delay, dispersion, jitter, and accumulated drift
        since the last update.

        Args:
            t: Current local Unix timestamp. If omitted, the current system
                time is used.

        Returns:
            The estimated root distance in seconds.
        """
        if t is None:
            t = time()

        incoming = self.incoming
        state = self.state

        return (
            max(MINDISP, incoming.delay + state.delay) / 2
            + incoming.dispersion
            + state.dispersion
            + state.jitter
            + self.tolerance * abs(t - incoming.t)
        )

    def merit_factor(self, t: float | None = None) -> float:
        """Compute the peer's ranking score for clock selection.

        Lower scores are better. The score primarily favors lower stratum
        servers and then uses root distance as a tie-breaker.

        Args:
            t: Current local Unix timestamp. If omitted, the current system
                time is used.

        Returns:
            The merit factor used to sort candidate peers.
        """
        return self.incoming.stratum * MAXDIST + self.root_distance(t)

    def is_synchronized(self) -> bool:
        """Check whether the peer reports itself as synchronized.

        Returns:
            ``True`` if the peer's last response indicates a synchronized
            server with an acceptable stratum and dispersion, otherwise
            ``False``.
        """
        incoming = self.incoming
        return (
            incoming.leap != NOSYNC
            and 0 < incoming.stratum < MAXSTRAT
            and incoming.delay / 2 + incoming.dispersion < MAXDISP
        )

    def is_fit(self, t: float | None = None) -> bool:
        """Check whether the peer is suitable for clock selection.

        Args:
            t: Current local Unix timestamp. If omitted, the current system
                time is used.

        Returns:
            ``True`` if the peer is synchronized and its root distance is below
            the implementation's acceptance threshold, otherwise ``False``.
        """
        return self.is_synchronized() and self.root_distance(t) < MAXDISP

    def prepare_request(self, t: float | None = None) -> bytes:
        """Build the next client request packet for this peer.

        Args:
            t: Local Unix timestamp to use for the transmit time. If omitted,
                the current system time is used.

        Returns:
            The serialized NTP client request packet.
        """
        if t is None:
            t = time()

        self.outgoing = NtpMessage(
            t=t,
            t_org=self.incoming.t_xmt,
            t_rec=self.incoming.t_dst,
            t_xmt=ntptime(t),
            version=self.incoming.version,
        )
        return self.outgoing.serialize()

    def response_error(self, error: Exception, t: float | None = None) -> None:
        """Record a communication failure for this peer.

        Communication failures degrade the peer's sample history so that peer
        selection naturally stops favoring it until valid replies arrive again.

        Args:
            error: The communication error that occurred while sending or
                receiving a packet.
            t: Local Unix timestamp at which the error was observed. If
                omitted, the current system time is used.
        """
        # Communication errors, including timeouts, cause degradation
        # of samples in the register and render the peer unfit.
        if t is None:
            t = time()

        log.info("%s Communication error: %s", self, error)

        self.outgoing = NtpMessage(
            t=t,
            t_xmt=(0, 0),
            version=self.incoming.version,
        )
        self.register.append(NtpState(t=t))
        self.calculate_state(t)
        self.schedule_poll(t)

    def process_response(self, payload: bytes, t: float | None = None) -> None:
        """Process a received NTP server response.

        Valid replies update the association state and sample register. Invalid
        or unsynchronized replies are converted into degraded samples so the
        peer becomes less likely to be selected.

        Args:
            payload: Raw UDP payload received from the peer.
            t: Local Unix timestamp recorded when the payload was received. If
                omitted, the current system time is used.

        Raises:
            AssertionError: If called before a request has been prepared and no
                outgoing packet state is available.
        """
        if t is None:
            t = time()

        log.debug("%s Got a packet", self)
        assert self.outgoing is not None

        try:
            r = NtpMessage.deserialize(payload, t)
            if r.t_org != self.outgoing.t_xmt:
                raise NtpPacketError("Bogus packet")
            if r.t_xmt == self.outgoing.t_org:
                # This should not really happen, as we zero t_xmt
                # and then dupes trigger "bogus packet" above.
                raise NtpPacketError("Duplicate packet")

            self.incoming = r
            self.outgoing = NtpMessage(
                t=t,
                t_org=self.incoming.t_xmt,
                t_rec=self.incoming.t_dst,
                t_xmt=(0, 0),
                version=self.incoming.version,
            )
            if not self.is_synchronized():
                raise NtpUnsynchronizedError("%s is not synchronized" % self)

            # RFC does the initial subtraction in integer arithmetics,
            # but we right away convert to FP64.
            # It still yields some 10us of precision given that seconds
            # from 1900 take 10 decimal digits.
            t1 = NtpMessage.from_timestamp(*r.t_org)
            t2 = NtpMessage.from_timestamp(*r.t_rec)
            t3 = NtpMessage.from_timestamp(*r.t_xmt)
            t4 = NtpMessage.from_timestamp(*r.t_dst)

            # Offset is the value we need to add to our local clock
            # in order, to be in sync with the peer. Therefore,
            # negative offset means our clock is running fast.
            offset = (t2 - t1 + t3 - t4) / 2
            delay = max(t4 - t1 - t3 + t2, 2**self.precision)
            dispersion = 2**r.precision + 2**self.precision + (t4 - t1) * self.tolerance
            state = NtpState(
                offset=offset,
                delay=delay,
                dispersion=dispersion,
                t=t,
            )
            self.register.append(state)
            self.calculate_state(t)
            log.debug("%s Update with %s", self, state)

        except NtpUnsynchronizedError:
            self.register.append(NtpState(t=t))
            self.calculate_state(t)

        except NtpError as e:
            log.info("%s %s", self, e.args[0])

        finally:
            self.schedule_poll(t)


Edge: TypeAlias = tuple[float, int, int, NtpAssociation]
State: TypeAlias = tuple[int, float, float]


class NtpArena:
    """Manage a set of NTP peers and derive a combined clock estimate."""

    peers: dict[tuple[str, int], NtpAssociation]
    sockv4: socket | None
    sockv6: socket | None

    def __init__(
        self,
        *,
        addresses: Iterable[str],
        socket_timeout: float = 5.0,
        precision: int = PRECISION,
        tolerance: float = TOLERANCE,
        start_randomization: float | None = None,
        max_poll: int | None = None,
    ):
        """Initialize the arena and its peer sockets.

        Args:
            addresses: IP addresses of the NTP servers to poll.
            socket_timeout: Timeout for socket receive operations, in seconds.
            precision: Local clock precision encoded as a base-2 exponent.
            tolerance: Assumed maximum local clock drift, in seconds per
                second.
            start_randomization: Optional maximum initial random delay, in
                seconds, used to stagger the first poll for each peer.
            max_poll: Optional upper bound for each peer's polling interval, in
                seconds.

        Raises:
            ValueError: If no usable IPv4 or IPv6 addresses are provided.
        """
        needs_ipv4 = False
        needs_ipv6 = False
        self.peers = {}
        for i in set(addresses):
            p = NtpAssociation(
                address=i,
                precision=precision,
                tolerance=tolerance,
                start_randomization=start_randomization,
                max_poll=max_poll,
            )
            self.peers[p.address] = p
            if p.ipv6:
                needs_ipv6 = True
            else:
                needs_ipv4 = True

        if not needs_ipv4 and not needs_ipv6:
            raise ValueError("No IPv4/IPv6 addresses provided")

        self.sockv4 = None
        if needs_ipv4:
            self.sockv4 = socket(AF_INET, SOCK_DGRAM)
            self.sockv4.settimeout(socket_timeout)
            self.sockv4.bind(("0.0.0.0", 0))  # noqa: S104
            log.debug("Created IPv4 socket")

        self.sockv6 = None
        if needs_ipv6:
            self.sockv6 = socket(AF_INET6, SOCK_DGRAM)
            self.sockv6.settimeout(socket_timeout)
            self.sockv6.bind(("::", 0))
            log.debug("Created IPv6 socket")

    def query_peers(
        self,
        *,
        query_limit: int | None = None,
        time_limit: float | None = None,
        response_callback: Callable[[], None] | None = None,
    ) -> float:
        """Poll due peers until the next wait period begins.

        The method sends requests to peers whose scheduled poll time has
        arrived, waits for a matching response from each, and updates the peer
        state accordingly.

        Args:
            query_limit: Optional maximum number of peer queries to perform in
                this call.
            time_limit: Optional maximum wall-clock time, in seconds, to spend
                inside this call.
            response_callback: Optional callback invoked after each successful
                response is processed.

        Returns:
            The number of seconds until the next peer should be queried.

        Raises:
            ValueError: If the arena has no peers to query.
        """
        log.debug("Query peers")
        i = 0
        start = time()
        while True:
            poll_q = sorted(self.peers.values(), key=lambda p: p.poll_t)
            if not poll_q:
                raise ValueError("No NTP peers found")
            # Polling loop:
            #   1. Choose the next peer.
            #   2. Send a query to it.
            #   3. Block the thread waiting for a reply.
            #   4. Process the reply.
            #   5. Go back to 1.
            # It is slow, but arguably offers the most precise timing
            # of packets, as there is nothing else involved apart from kernel
            # sending the packet out and then waking the thread up as soon as
            # the reply arrives. Especially if that's the only active thread.
            for p in poll_q:
                i += 1
                t = time()
                diff = p.poll_t - t
                if diff > 1:
                    log.debug("No more peers to query for now")
                    return diff
                if query_limit is not None and i > query_limit:
                    log.debug("Query limit reached")
                    return diff
                if time_limit is not None and t - start > time_limit:
                    log.debug("Time limit reached")
                    return diff

                s = self.sockv6 if p.ipv6 else self.sockv4
                assert s is not None

                try:
                    s.sendto(p.prepare_request(), p.address)
                    while True:
                        payload, address = s.recvfrom(4096)
                        t = time()
                        if address[:2] == p:
                            p.process_response(payload, t)
                            if response_callback:
                                response_callback()
                            break
                except OSError as e:
                    p.response_error(e)

    def filter_clocks(self, edges: Iterable[Edge], low: float, high: float) -> State:
        """Select survivor peers and combine them into a system clock state.

        Args:
            edges: Interval boundary records derived from candidate peers,
                containing lower bounds, midpoints, upper bounds, and peer
                references.
            low: Lower bound of the consensus interval.
            high: Upper bound of the consensus interval.

        Returns:
            A ``(leap, offset, jitter)`` tuple representing the combined system
            state, where ``leap`` is the leap-second correction indicator,
            ``offset`` is the estimated clock correction in seconds, and
            ``jitter`` is the aggregate jitter in seconds.

        Raises:
            NtpUnsynchronizedError: If no peers remain within the consensus
                interval.
        """
        # Truechimers have their midpoint in the found interval.
        truechimers = set()
        for e in edges:
            if e[2]:
                if low <= e[0] <= high:
                    truechimers.add(e[-1])

        if not truechimers:
            raise NtpUnsynchronizedError("No truechimers found")
        log.debug("Truechimers: %s", truechimers)

        while len(truechimers) > NMIN:
            min_jitter = None
            max_jitter = None
            max_jitter_peer = None

            for t in truechimers:
                offset = t.state.offset
                jitter = (
                    sum((p.state.offset - offset) ** 2 for p in truechimers)
                    / (len(truechimers) - 1)
                ) ** 0.5
                if min_jitter is None or min_jitter > t.state.jitter:
                    min_jitter = t.state.jitter
                if max_jitter is None or max_jitter < jitter:
                    max_jitter = jitter
                    max_jitter_peer = t

            assert min_jitter is not None
            assert max_jitter is not None

            if max_jitter < min_jitter:
                break

            assert max_jitter_peer is not None
            truechimers.remove(max_jitter_peer)

        t = time()
        # First on the sorted list is our system peer
        survivors = sorted(truechimers, key=lambda p: p.merit_factor(t))
        log.debug("Survivors: %s", survivors)

        # Page 97, implements weighted average of survivors to produce
        # final offset and jitter. That's what is implemented here.
        weight = 0
        offset = 0
        jitter = 0
        leap_0 = survivors[0].incoming.leap
        # Convert the 3bit leap value to the extra second with sign.
        # Can be -1 (day is shorter by 1sec),
        # 0 (usual, no adjustment) or 1 (extra sec in the day).
        leap = -1 if leap_0 == 2 else leap_0
        offset_0 = survivors[0].state.offset
        for p in survivors:
            offset_p = p.state.offset
            weight_p = 1 / p.root_distance(t)
            weight += weight_p
            offset += offset_p * weight_p
            jitter += (offset_p - offset_0) ** 2 * weight_p

        offset /= weight
        jitter = (jitter / weight) ** 0.5
        log.debug("offset=%g jitter=%g leap=%d", offset, jitter, leap)
        return leap, offset, jitter

    def calculate_state(self) -> State:
        """Compute the current combined clock state from all fit peers.

        This runs the NTP clock-selection and clustering steps over the peers
        that are currently considered fit.

        Returns:
            A ``(leap, offset, jitter)`` tuple representing the selected system
            clock state.

        Raises:
            NtpUnsynchronizedError: If there are no fit peers or if the peers
                do not reach consensus.
        """
        t = time()

        fit = [p for p in self.peers.values() if p.is_fit(t)]
        if not fit:
            raise NtpUnsynchronizedError("No fit peers found")
        log.debug("Fit peers: %s", fit)

        edges: list[Edge] = []
        for p in fit:
            offset = p.state.offset
            distance = p.root_distance(t)
            edges.append((offset - distance, 1, 0, p))
            edges.append((offset, 0, 1, p))
            edges.append((offset + distance, -1, 0, p))

        edges.sort(key=lambda x: x[0])

        for i in range(max(1, len(fit) // 2)):
            log.debug("Finding consensus, assuming %d falsetickers", i)

            midpoints = 0
            low = None
            high = None

            count = 0
            for e in edges:
                count += e[1]
                if count >= len(fit) - i:
                    low = e[0]
                    break
                midpoints += e[2]

            count = 0
            for e in reversed(edges):
                count -= e[1]
                if count >= len(fit) - i:
                    high = e[0]
                    break
                midpoints += e[2]

            if midpoints <= i and low is not None and high is not None and low < high:
                return self.filter_clocks(edges, low, high)

        raise NtpUnsynchronizedError("No consensus found")


def argv_parser(progname: str | None = None) -> "ArgumentParser":
    """Create the command-line argument parser for the NTP client.

    Args:
        progname: Program name to display in help output. If omitted, ``ntp``
            is used.

    Returns:
        The configured argument parser.
    """
    import argparse

    if progname is None:
        progname = "ntp"

    parser = argparse.ArgumentParser(
        prog=progname,
        formatter_class=argparse.RawTextHelpFormatter,
        description="Pure python NTP client",
        epilog="Example: %s --output-count 1 pool.ntp.org" % progname,
    )
    parser.add_argument(
        "server",
        nargs="+",
        help="NTP server(s) to query, can be addresses or hostnames.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["error", "warning", "info", "debug"],
        default="info",
    )
    parser.add_argument(
        "--output-count",
        type=int,
        default=0,
        help=(
            "how many times the output should be produced."
            " It defaults to zero, which means 'run forever'."
        ),
    )
    parser.add_argument(
        "--output-interval",
        type=int,
        default=None,
        help=(
            "how often to produce the output (in seconds)."
            " Defaults to after each batch of queries."
            " Zero means after every reply from an NTP server."
            " Subject to availability of synchronization data."
        ),
    )
    parser.add_argument(
        "--output-format",
        type=str,
        default="{Y:04}-{M:02}-{D:02}T{h:02}:{m:02}:{s:02}.{u:06}Z",
        help=(
            "defaults to '{Y:04}-{M:02}-{D:02}T{h:02}:{m:02}:{s:02}.{u:06}Z'"
            " Other variables available: count, offset, jitter, leap and time."
            " For example: 'offset={offset}'"
        ),
    )
    parser.add_argument(
        "--socket-timeout",
        type=float,
        default=5.0,
        help="how long to wait for a reply from NTP server",
    )
    parser.add_argument(
        "--max-poll-interval",
        type=int,
        default=None,
        help=(
            "max interval between queries to each NTP server (in seconds)."
            " By default it is capped at 1h +/- 15m."
        ),
    )
    return parser


def main() -> None:
    """Run the command-line NTP client.

    The client resolves the requested servers, polls them repeatedly, and
    prints synchronized time output according to the configured format.

    Returns:
        None.
    """
    args = argv_parser().parse_args()
    log_level = getattr(logging, args.log_level.upper())
    output_format = args.output_format
    output_interval = args.output_interval
    output_count = max(0, args.output_count)
    output_t = time()
    output_i = 0

    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger().setLevel(log_level)

    def resolve(name):
        try:
            for i in getaddrinfo(name, 123):
                if i[0] == AF_INET or i[0] == AF_INET6:
                    yield i[-1][0]
        except gaierror as e:
            raise ValueError("Cannot resolve %s" % name) from e

    def output():
        nonlocal output_i, output_t
        try:
            leap, offset, jitter = ntp.calculate_state()
            t = time() + offset
            dt = datetime.fromtimestamp(t, timezone.utc)
            context = {
                "Y": dt.year,
                "M": dt.month,
                "D": dt.day,
                "h": dt.hour,
                "m": dt.minute,
                "s": dt.second,
                "u": dt.microsecond,
                "count": output_i + 1,
                "leap": leap,
                "time": t,
                "offset": offset,
                "jitter": jitter,
            }
            print(output_format.format_map(context), flush=True)
            output_i += 1
            if 0 < output_count <= output_i:
                raise StopIteration
            output_t = t
        except NtpUnsynchronizedError as e:
            output_t = time() + 3
            log.debug("%s", e)
        log.debug("Next output at %f", output_t)

    addresses = set()
    for i in args.server:
        addresses.update(resolve(i))
    ntp = NtpArena(
        addresses=addresses,
        socket_timeout=args.socket_timeout,
        max_poll=args.max_poll_interval,
        start_randomization=15,
    )

    time_limit = None
    if output_interval is not None and output_interval > 0:
        time_limit = output_interval
    response_callback = None
    if output_interval == 0:
        response_callback = output

    try:
        while output_count <= 0 or output_i < output_count:
            pause = ntp.query_peers(
                time_limit=time_limit,
                response_callback=response_callback,
            )
            if output_interval is None:
                output()
            elif output_interval > 0:
                current_t = time()
                if current_t - output_t >= output_interval:
                    output()
                pause = min(pause, output_interval - current_t + output_t)
            pause = max(pause, 1)
            log.debug("Pause %f seconds", pause)
            sleep(pause)
    except StopIteration:
        pass


if __name__ == "__main__":
    main()
