import struct
from collections import deque
from typing import Callable


__version__ = "1.0.0"
__author__ = "Mero <mero@crepe.moe>"


IKCP_RTO_NDL = 30
IKCP_RTO_MIN = 100
IKCP_RTO_DEF = 200
IKCP_RTO_MAX = 60000
IKCP_CMD_PUSH = 81
IKCP_CMD_ACK  = 82
IKCP_CMD_WASK = 83
IKCP_CMD_WINS = 84
IKCP_ASK_SEND = 1
IKCP_ASK_TELL = 2
IKCP_WND_SND = 32
IKCP_WND_RCV = 128
IKCP_MTU_DEF = 1400
IKCP_ACK_FAST	= 3
IKCP_INTERVAL	= 100
IKCP_DEADLINK = 20
IKCP_THRESH_INIT = 2
IKCP_THRESH_MIN = 2
IKCP_PROBE_INIT = 7000
IKCP_PROBE_LIMIT = 120000
IKCP_FASTACK_LIMIT = 5

IKCP_PACKET_HEAD_FORMAT = "<IIBBHIIII"
IKCP_OVERHEAD = struct.calcsize(IKCP_PACKET_HEAD_FORMAT)


class KcpException(Exception):
    pass


class KcpSegment:
    __slots__ = (
        "session_id", "cmd", "frg", "wnd",
        "ts", "sn", "una", "data",
        "resendts", "rto", "fastack", "xmit"
    )

    def __init__(self) -> None:
        self.data = b""

        self.resendts = 0
        self.rto = 0
        self.fastack = 0
        self.xmit = 0

    def parse(self, data):
        conv, token, cmd, frg, wnd, ts, sn, una, len =\
            struct.unpack(IKCP_PACKET_HEAD_FORMAT, data[:IKCP_OVERHEAD])

        self.session_id = conv << 32 | token
        self.cmd = cmd
        self.frg = frg
        self.wnd = wnd

        self.ts = ts
        self.sn = sn
        self.una = una
        self.data = data[IKCP_OVERHEAD:IKCP_OVERHEAD+len]

        return IKCP_OVERHEAD + len
    
    def encode(self) -> bytes:
        conv = self.session_id >> 32
        token = self.session_id & 0xffffffff

        return struct.pack(
            IKCP_PACKET_HEAD_FORMAT,
            conv, token, self.cmd, self.frg, self.wnd, self.ts, self.sn, self.una, len(self.data)
        ) + self.data


class Kcp:
    __slots__ = ("session_id", "current", "rx_srtt", "rx_rttval", "snd_wnd", "interval", "rx_minrto", "snd_nxt", "rmt_wnd", "snd_buf", "snd_una", "snd_queue", "updated", "ts_flush", "xmit", "state", "ts_probe", "probe_wait",
                 "use_fastask_conserve", "rcv_nxt", "rcv_wnd", "rcv_buf", "rcv_queue", "probe", "acklist", "cwnd", "mtu", "mss", "ssthresh", "incr", "rx_rto", "stream", "output", "nodelay", "nocwnd", "dead_link", "fastresend", "fastlimit")

    def __init__(self, session_id: int, output: Callable[[bytes], None]):
        assert session_id < 1 << 64

        self.use_fastask_conserve = False
        self.session_id = session_id
        self.output = output

        self.snd_una = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0

        self.ts_probe = 0
        self.probe_wait = 0

        self.snd_wnd = IKCP_WND_SND
        self.rcv_wnd = IKCP_WND_RCV
        self.rmt_wnd = IKCP_WND_RCV

        self.cwnd = 0
        self.incr = 0
        self.probe = 0

        self.mtu = IKCP_MTU_DEF
        self.mss = self.mtu - IKCP_OVERHEAD
        self.stream = False

        self.snd_buf = deque()
        self.rcv_buf = deque()
        self.rcv_queue = deque()
        self.snd_queue = deque()

        self.state = 0
        self.acklist = deque()

        self.rx_srtt = 0
        self.rx_rttval = 0
        self.rx_rto = IKCP_RTO_DEF
        self.rx_minrto = IKCP_RTO_MIN

        self.current = 0
        self.interval = IKCP_INTERVAL
        self.ts_flush = IKCP_INTERVAL
        self.nodelay = 0
        self.updated = False

        self.ssthresh = IKCP_THRESH_INIT
        self.fastresend = 0
        self.fastlimit = IKCP_FASTACK_LIMIT
        self.nocwnd = False
        self.xmit = 0
        self.dead_link = IKCP_DEADLINK

    def parse_una(self, una):
        while self.snd_buf:
            seg = self.snd_buf[0]

            if seg.sn >= una:
                break

            self.snd_buf.popleft()

    def shrink_buf(self):
        self.snd_una = self.snd_buf[0].sn if self.snd_buf else self.snd_nxt

    def update_ack(self, rtt):
        if self.rx_srtt == 0:
            self.rx_srtt = rtt
            self.rx_rttval = rtt // 2
        else:
            delta = abs(rtt - self.rx_srtt)
            self.rx_rttval = (3 * self.rx_rttval + delta) // 4
            self.rx_srtt = max((7 * self.rx_srtt + rtt) // 8, 1)

        rto = self.rx_srtt + max(self.interval, 4 * self.rx_rttval)
        self.rx_rto = min(max(self.rx_minrto, rto), IKCP_RTO_MAX)

    def parse_ack(self, sn):
        if self.snd_una > sn or self.snd_nxt <= sn:
            return

        for seg in self.snd_buf:
            if sn == seg.sn:
                self.snd_buf.remove(seg)
                break

            if seg.sn > sn:
                break

    def move_buf(self):
        while self.rcv_buf:
            seg = self.rcv_buf[0]
            if seg.sn != self.rcv_nxt or len(self.rcv_queue) >= self.rcv_wnd:
                break

            self.rcv_nxt += 1
            self.rcv_queue.append(self.rcv_buf.popleft())

    def parse_data(self, newseg):
        if (self.rcv_nxt + self.rcv_wnd) <= newseg.sn or self.rcv_nxt > newseg.sn:
            return

        repeat = False
        new_index = len(self.rcv_buf)

        for seg in reversed(self.rcv_buf):
            if seg.sn == newseg.sn:
                repeat = True
                break

            if seg.sn < newseg.sn:
                break

            new_index -= 1

        if not repeat:
            self.rcv_buf.insert(new_index, newseg)

        self.move_buf()

    def parse_fastack(self, sn, ts):
        if self.snd_una > sn or self.snd_nxt <= sn:
            return

        for seg in self.snd_buf:
            if seg.sn > sn:
                break
            elif sn != seg.sn and (self.use_fastask_conserve or seg.ts <= ts):
                seg.fastack += 1

    def input(self, data: bytes):
        if not data or len(data) < IKCP_OVERHEAD:
            raise KcpException(f"data size must be greater than {IKCP_OVERHEAD}")

        maxack = 0
        latest_ts = 0
        flag = False
        prev_una = self.snd_una

        while len(data) >= IKCP_OVERHEAD:
            seg = KcpSegment()
            data = data[seg.parse(data):]

            if seg.session_id != self.session_id:
                raise KcpException(f"wrong session id, got {seg.session_id} but {self.session_id} was expected")

            if seg.cmd not in (IKCP_CMD_PUSH, IKCP_CMD_ACK, IKCP_CMD_WASK, IKCP_CMD_WINS):
                raise KcpException(f"unknown kcp cmd {seg.cmd}")

            self.rmt_wnd = seg.wnd

            self.parse_una(seg.una)
            self.shrink_buf()

            if seg.cmd == IKCP_CMD_ACK:
                rtt = self.current - seg.ts
                if rtt >= 0:
                    self.update_ack(rtt)

                self.parse_ack(seg.sn)
                self.shrink_buf()

                if not flag:
                    flag = True
                    maxack = seg.sn
                    latest_ts = seg.ts
                elif maxack < seg.sn and (self.use_fastask_conserve or latest_ts > seg.ts):
                    maxack = seg.sn
                    latest_ts = seg.ts

            elif seg.cmd == IKCP_CMD_PUSH:
                if self.rcv_nxt + self.rcv_wnd > seg.sn:
                    self.acklist.append((seg.sn, seg.ts))
                    if self.rcv_nxt <= seg.sn:
                        self.parse_data(seg)

            elif seg.cmd == IKCP_CMD_WASK:
                self.probe |= IKCP_ASK_TELL

        if flag:
            self.parse_fastack(maxack, latest_ts)

        if self.snd_una - prev_una > 0 and self.cwnd < self.rmt_wnd:
            mss = self.mss
            if self.cwnd < self.ssthresh:
                self.cwnd += 1
                self.incr += mss
            else:
                if self.incr < mss:
                    self.incr = mss
                self.incr += mss * mss // self.incr + mss // 16
                if (self.cwnd + 1) * mss <= self.incr:
                    self.cwnd = (self.incr + mss - 1) // mss if mss > 0 else 1
            if self.cwnd > self.rmt_wnd:
                self.cwnd = self.rmt_wnd
                self.incr = self.rmt_wnd * mss

    def peeksize(self):
        if not self.rcv_queue:
            return -1

        seg = self.rcv_queue[0]
        if seg.frg == 0:
            return len(seg.data)
        if len(self.rcv_queue) < seg.frg + 1:
            return -1

        length = 0
        for seg in self.rcv_queue:
            length += len(seg.data)
            if seg.frg == 0:
                break

        return length

    def recv(self) -> bytes | None:
        if not self.rcv_queue:
            return None

        peeksize = self.peeksize()
        if peeksize < 0:
            return None

        recover = len(self.rcv_queue) >= self.rcv_wnd
        data = b""

        while seg := self.rcv_queue.popleft():
            data += seg.data
            if seg.frg == 0:
                break

        assert len(data) == peeksize
        self.move_buf()

        if len(self.rcv_queue) < self.rcv_wnd and recover:
            self.probe |= IKCP_ASK_TELL

        return data

    def send(self, data: bytes):
        assert self.mss > 0

        if self.stream:
            if self.snd_queue:
                seg = self.snd_queue[-1]
                if len(seg.data) < self.mss:
                    capacity = self.mss - len(seg.data)
                    extend = min(len(data), capacity)

                    seg.data += data[:extend]
                    data = data[extend:]
                    seg.frg = 0

            if not data:
                return
            
        count = (len(data) + self.mss - 1) // self.mss if len(data) > self.mss else 1
        if count >= IKCP_WND_RCV: raise KcpException("user buffer is too long")
        count = max(count, 1)

        for i in range(count):
            size = min(self.mss, len(data))

            newseg = KcpSegment()
            newseg.data = data[:size]
            newseg.frg = 0 if self.stream else count - i - 1

            data = data[size:]
            self.snd_queue.append(newseg)

    def update(self, current: int):
        assert current < 1 << 32
        self.current = current

        if not self.updated:
            self.updated = True
            self.ts_flush = self.current

        slap = self.current - self.ts_flush

        if slap >= 10000 or slap < -10000:
            self.ts_flush = self.current
            slap = 0

        if slap >= 0:
            self.ts_flush += self.interval
            if self.ts_flush <= self.current:
                self.ts_flush = self.current + self.interval
            self.flush()

    def wnd_unused(self):
        return max(self.rcv_wnd - len(self.rcv_queue), 0)

    def flush(self):
        if not self.updated:
            return

        seg = KcpSegment()
        seg.session_id = self.session_id
        seg.cmd = IKCP_CMD_ACK
        seg.frg = 0
        seg.wnd = self.wnd_unused()
        seg.una = self.rcv_nxt
        seg.sn = 0
        seg.ts = 0

        data = b""
        for sn, ts in self.acklist:
            if len(data) + IKCP_OVERHEAD > self.mtu:
                self.output(data)
                data = b""
            seg.sn = sn
            seg.ts = ts
            data += seg.encode()
        self.acklist.clear()

        if self.rmt_wnd == 0:
            if self.probe_wait == 0:
                self.probe_wait = IKCP_PROBE_INIT
                self.ts_probe = self.current + self.probe_wait
            elif self.ts_probe <= self.current:
                self.probe_wait = min(self.probe_wait + max(self.probe_wait, IKCP_PROBE_INIT) // 2, IKCP_PROBE_LIMIT)
                self.ts_probe = self.current + self.probe_wait
                self.probe |= IKCP_ASK_SEND
        else:
            self.ts_probe = 0
            self.probe_wait = 0

        if self.probe & IKCP_ASK_SEND:
            seg.cmd = IKCP_CMD_WASK
            if len(data) + IKCP_OVERHEAD > self.mtu:
                self.output(data)
                data = b""
            data += seg.encode()

        if self.probe & IKCP_ASK_TELL:
            seg.cmd = IKCP_CMD_WINS
            if len(data) + IKCP_OVERHEAD > self.mtu:
                self.output(data)
                data = b""
            data += seg.encode()

        self.probe = 0

        cwnd = min(self.snd_wnd, self.rmt_wnd)
        if not self.nocwnd:
            cwnd = min(self.cwnd, cwnd)

        while self.snd_una + cwnd > self.snd_nxt:
            if not self.snd_queue:
                break

            newseg = self.snd_queue.popleft()
            self.snd_buf.append(newseg)

            newseg.session_id = self.session_id
            newseg.cmd = IKCP_CMD_PUSH
            newseg.wnd = seg.wnd
            newseg.ts = self.current

            newseg.sn = self.snd_nxt
            self.snd_nxt += 1

            newseg.una = self.rcv_nxt
            newseg.resendts = self.current
            newseg.rto = self.rx_rto
            newseg.fastack = 0
            newseg.xmit = 0

        resent = 0xffffffff
        if self.fastresend > 0:
            resent = self.fastresend

        rtomin = 0
        if not self.nodelay:
            rtomin = self.rx_rto >> 3

        lost = False
        change = False

        for segment in self.snd_buf:
            needsend = False

            if segment.xmit == 0:
                needsend = True
                segment.xmit += 1
                segment.rto = self.rx_rto
                segment.resendts = self.current + segment.rto + rtomin
            elif segment.resendts <= self.current:
                needsend = True
                segment.xmit += 1
                self.xmit += 1
                if not self.nodelay:
                    segment.rto += max(segment.rto, self.rx_rto)
                else:
                    step = segment.rto if self.nodelay < 2 else self.rx_rto
                    segment.rto += step // 2
                segment.resendts = self.current + segment.rto
                lost = True
            elif segment.fastack >= resent and (segment.xmit <= self.fastlimit or self.fastlimit <= 0):
                needsend = True
                segment.xmit += 1
                segment.fastack = 0
                segment.resendts = self.current + segment.rto
                change = True

            if needsend:
                segment.ts = self.current
                segment.wnd = seg.wnd
                segment.una = self.rcv_nxt

                if len(data) + IKCP_OVERHEAD + len(segment.data) > self.mtu:
                    self.output(data)
                    data = b""

                data += segment.encode()
                if segment.xmit >= self.dead_link:
                    self.state = -1

        if data:
            self.output(data)

        if change:
            inflight = self.snd_nxt - self.snd_una
            self.ssthresh = max(inflight // 2, IKCP_THRESH_MIN)
            self.cwnd = self.ssthresh + resent
            self.incr = self.cwnd * self.mss

        if lost:
            self.ssthresh = max(cwnd // 2, IKCP_THRESH_MIN)
            self.cwnd = 1
            self.incr = self.mss

        if self.cwnd < 1:
            self.cwnd = 1
            self.incr = self.mss

    def check(self, current):
        assert current < 1 << 32

        ts_flush = self.ts_flush
        tm_packet = 0x7fffffff

        if not self.updated:
            return current

        if current - self.ts_flush >= 10000 or current - self.ts_flush < -10000:
            ts_flush = current

        if ts_flush <= current:
            return current

        tm_flush = ts_flush - current

        for seg in self.snd_buf:
            diff = seg.resendts - current
            if diff <= 0:
                return current
            if diff < tm_packet:
                tm_packet = diff

        return current + min(tm_flush, tm_packet, self.interval)

    def set_mtu(self, mtu: int):
        if mtu < 50 or mtu < IKCP_OVERHEAD:
            raise KcpException("invalid mtu")
        
        self.mtu = mtu
        self.mss = self.mtu - IKCP_OVERHEAD

    def set_nodelay(self, nodelay: int, interval: int, resend: int, nc: int):
        if nodelay >= 0:
            self.nodelay = nodelay
            if nodelay:
                self.rx_minrto = IKCP_RTO_NDL
            else:
                self.rx_minrto = IKCP_RTO_MIN

        if interval >= 0:
            self.interval = min(max(10, interval), 5000)

        if resend >= 0:
            self.fastresend = resend

        if nc >= 0:
            self.nocwnd = nc

    def set_wndsize(self, sndwnd: int, rcvwnd: int):
        if sndwnd > 0:
            self.snd_wnd = sndwnd
        if rcvwnd > 0:
            self.rcv_wnd = max(rcvwnd, IKCP_WND_RCV)
