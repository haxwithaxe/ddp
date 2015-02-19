from datetime import datetime
from StringIO import StringIO

import hashlib
import math
import os
import random
import subprocess
import sys
import threading
import time
import xmlrpclib
import gzip
import rs
import socket
import ossaudiodev

try:
    import serial
except ImportError:
    print("Failed to load the serial module, ensure PySerial is installed.")
    sys.exit(1)


from danlog import DanLog

DATAMODES = {"D-STAR":{
                    "debug":(
                    "Setting up for D-STAR (DV) mode."), 
                    "backend": "D-STAR", 
                    "callback":self.setupDSTAR},
            "RS-232":{
                    "debug":("Setting up for RS-232 mode."),
                    "backend": "RS-232",
                    "callback": self.setupRS232},
            "GMSK": {
                    "debug": ("Setting up for GMSK mode."),
                    "backend": "GMSK",
                    "callback": self.setupGMSK},
            "EXTENSION": {
                "debug": ("Setting up for EXTENSION mode."),
                "backend": self.extention.name,
                "callback": self.extension},
            "FDMDV": {
                    "debug": ("Setting up for FDMDV mode."),
                    "backend": "FDMDV",
                    "callback": self.setupFDMDV},
            "FLDIGI": {
                "debug": ("Setting up for Fldigi mode using %s.", self.conf.main_data_mode),
                "backend": "FLDIGI",
                "callback": self.setupFldigi}
            }




class DDP(object):

    def __init__(self, hostname = "localhost", port = 7362, data_mode = "PSK500R", carrier_frequency = 1000, sideband = "USB", retries = 5, data_length = 128, tx_wait = 0.15, rx_wait = 0.15, timeout = 30., ack_timeout = 15., tx_hangtime = 0.25, specification = 0, extension_init = None, disable_ec = False, disable_crypto = False, allow_unsigned_packets = False, application = "DDP", ignore_broadcast_packets = True, verify_packet_before_tx = True, repeater_mode = False, colour_logging = True, logger_name = "DDP", debug_mode = False):
        self.crypto = None
        self.devnull = None
        self.fdmdv = None
        self.fldigi = None
        self.prd = {}
        self.reedsolomon = None
        self.serial = None
        self._init_log()
        self._validate_platform()
        self._get_compression_mod()
        self._check_reed_solomon()
        self.application_id = self.sha1(application)

    def _init_log(self):
        # Initialise the new logger
        self.log = DanLog()
        self.log.info("Initialising DDP v%s...",  __version__)
        # Python version checking

    def _validate_platform(self):
        self.log.debug("Checking Python version...")
        self.log.debug("Running under Python v%d.%d.%d." % sys.version_info[:3])
        # Check the platform OS
        plat = sys.platform
        plat_low = plat.lower()
        if plat_low == "win32":
                self.log.warn("You appear to be running on Windows, this platform is not supported and it is preferred you run DDP under Cygwin instead.  Bug reports will not be accepted under this OS.")
        elif plat_low in ["os2", "os2emx", "riscos", "atheos"] or plat_low.startswith("freebsd") or plat.startswith("sunos"):
                self.log.warn("You appear to be running on %s, this platform has not been tested.  Please provide feedback for this operating system.", plat)

    def _get_compression_mod(self):
        # See what compression modules we can use
        self.log.debug("Checking compression module...")

    def _check_reed_solomon(self):
        # Sort out Reed-Solomon if we need to
        if not self.conf.main_disable_ec:
                if os.path.exists("pyreedsolomon"):
                        sys.path.append("pyreedsolomon")
                        try:
                                self.log.debug("Testing Reed-Solomon module...")
                                d = bytearray()
                                e = bytearray()
                                i = "\x00\x01\x02DDP EC\xfd\xfe\xff".ljust(self.RS_K, "\x00")
                                # The subs will need to told they're available
                                self.reedsolomon = rs
                                e.extend(self.encodeReedSolomon(i))
                                d.extend(self.decodeReedSolomon(e))
                                if d != i:
                                        raise Exception("pyreedsolomon comparsion test failed, EC won't be available.")
                                self.ec_available = True
                        except Exception, ex:
                                self.reedsolomon = None
                                self.log.warn("pyreedsolomon threw an exception, EC won't be available.", exc_info=True)
                if self.ec_available:
                        s = (self.RS_N - self.RS_K)/2.0
                        self.log.debug("pyreedsolomon tests successful, EC enabled (N = %d, K = %d, S = %.2f, Lmax = %.2f%%).", self.RS_N, self.RS_K, s, (s/self.RS_N)*100)
        else:
                self.log.warn("Error correction has been disabled as per application request.")

    def _check_crypto(self):
        # Now sort out the crypto module for callsign signatures
        if not self.conf.main_crypto:
            self.log.debug("Checking whether we can offer callsign signatures...")
            # Create the directory structures if we've got this far
            self.log.debug("Creating directories...")
            local_dir = os.path.join(self.conf.crypto_dir, self.conf.crypto_local_name)
            remote_dir = os.path.join(self.conf.crypto_dir, self.conf.crypto_remote_name)
            self.passwd_file = os.path.join(local_dir, self.conf.crypto_passwd_name)
            self.pubkey_file = os.path.join(local_dir, self.conf.crypto_pubkey_name)
            self.privkey_file = os.path.join(local_dir, self.conf.crypto_privkey_name)
            for path in [self.crypto_dir, local_dir, remote_dir]:
                if not os.path.exists(path):
                    os.mkdir(path)
            self._create_passwd_file(local_dir)

    def _create_passwd_file(self, local_dir):
        self.passwd_file = os.path.join(local_dir, self.conf.crypto_passwd_name)
        if not os.path.exists(passwd_file):
            self.log.warn("No passphrase file found, creating it at: %s", self.passwd_file)
            rsa = DanRSA()
            rsa.savePassphrase(self.passwd_file, rsa.generatePassphrase())
            del rsa

    def _read_passwd_file(self):
        # Read the passphrase in
        if os.path.exists(self.passwd_file):
            rsa = DanRSA()
            self.crypto_passwd = rsa.loadPassphrase(self.passwd_file)
            del rsa

    def _generate_keypairs(self):
        # Generate the key pairs, if required
        rsa = DanRSA(passphrasecallback = self.crypto_passwd)
        rsa.generateKeyPair(self.crypto_pubkey_file, self.crypto_privkey_file)
        del rsa

    def _validate_keypair(self):
        # Test the crypto with our keys, first encryption
        plain_text = "\x00\x01\x02DDP RSA\xfd\xfe\xff"
        cipher_text = self._encrypt_message(plain_text)
        if plain_text != self._decrypt_message(cipher_text):
            raise ValueError("Failed to encrypt and decrypt a message with (%s, %s)", self.crypto_pubkey_file, self.crypto_privkey_file)
        self.crypto_available = True

    def _encrypt_message(self, plain_text):
        rsa = DanRSA(self.crypto_pubkey_file, None, self.crypto_passwd)
        cipher_text = c.encrypt(plain_text)
        del rsa
        return cipher_text

    def _decrypt_message(self, cipher_text):
        # Now decryption
        rsa = DanRSA(None, self.crypto_privkey_FILE, self.crypto_passwd)
        plain_text = c.decrypt(cipher_text)
        del rsa
        return plain_text

    def _validate_config(self):
        if self.conf.main_allow_unsigned_packets:
            self.log.warn("Unsigned packets are allowed, this is not recommended.")
        self._validate_repeater_mode()
        self._validate_data_mode()
        if self.backend == "FLDIGI":
            if self.ec_available and not self.main_disable_ec:
                if datamode.startswith("PSK") and datamode.endswith("R"):
                    self.log.warn("EC is available but will not be used when using fldigi, a robust mode has already been chosen.")
                else:
                    self.log.warn("EC is available but will not be used when using fldigi, just use a robust digital mode like PSK500R.")

    def _load_data_mode(self, data_mode):
        dm_parts = DATAMODES.get(data_mode)
        self.log.debug(dm_parts.get("debug"))
        self.backend = dm_parts.get("backend")
        dm_parts.get("callback")(self, self.conf.main_hostname, self.conf.net_port)

    def _validate_repeater_mode(self):
        if self.conf.main_repeater_mode:
            self.log.info("DDP is running in repeater mode, packets will be handled differently (%s).", self.application_id)

    def _validate_data_mode(self):
        datamode = self.conf.main_data_mode.upper()
        if datamode in DATMODES:
            self._load_data_mode(datamode)
        else:
            #FIXME: probably need an exception here.
            self.log.warn("No data mode extension found matching '%s'", datamode)
        # Warnings
        if self.backend == "FLDIGI":
            if self.ec_available and not self.conf.main_disable_ec:
                if self.conf.main_data_mode.upper().startswith("PSK") and self.conf.main_data_mode.upper().endswith("R"):
                    self.log.warn("EC is available but will not be used when using fldigi, a robust mode has already been chosen.")
                else:
                    self.log.warn("EC is available but will not be used when using fldigi, just use a robust digital mode like PSK500R.")

    def _import_spec(self):
        # The specifications are now dynamically loaded, this allows for adding new specs without changing the core
        self.log.info("Importing specification ID %d..." % self.specification)
        self.spec_module = __import__("ddp_specification_%02d" % self.specification)
        self.spec_module.init(self)
        # Other useful information
        self.log.info("SYN packet timeout is %.2f seconds." % self.SYN_TIMEOUT)
        self.log.info("ACK packet timeout is %.2f seconds (when using TCP mode)." % self.ACK_TIMEOUT)
        self.log.info("TX hangtime (PTT) is %.3f seconds." % self.TX_HANGTIME)
        # Completed
        self.log.info("Initialisation complete.")
	
    def compressStream(self, data):
        self.log.debug("Running compressStream().")
        dio = StringIO()
        com = gzip.GzipFile(fileobj=dio, mode="wb", compresslevel= = 9)
        com.write(data)
        com.close()
        return dio.getvalue()
    
    def constructPacket(self, callsign_from, via, callsign_to, flags, data, application_id = "", signature = ""):
        self.log.debug("Running constructPacket().")
        if application_id == "":
                application_id = self.application_id
        return self.spec_module.constructPacket(self, callsign_from, via, callsign_to, flags, data, application_id, signature)
    
    def cw(self, message):
        self.log.debug("Running cw().")
        if self.serial:
            self.log.debug("Can't send CW over serial, so ignoring.")
        elif self.fldigi:
            self.fldigi.modem.set_by_name("CW")
            self.fldigi.modem.set_carrier(800)
            self.fldigi.text.clear_rx()
            self.fldigi.text.clear_tx()
            self.fldigi.text.add_tx("%s^r" % message)
            self.fldigi.main.tx()
            while self.fldigi.main.get_trx_status() == "tx":
                    time.sleep(self.TX_WAIT)
            # Reset
            self.fldigi.modem.set_by_name(self.conf.main_data_mode)
            self.fldigi.modem.set_carrier(self.conf.main_carrier_freq)
            self.fldigi.main.set_lock(True)
            self.fldigi.text.clear_rx()
            self.fldigi.text.clear_tx()
    
    def decodeBase128ToStream(self, data, offset = 0, hexmode = False):
        self.log.debug("Running decodeBase128ToStream().")
        ret = bytearray()
        for c in xrange(0, len(data), 2):
            if hexmode:
                ret.extend(chr(int(data[c:c + 2], 16)))
            else:
                ret.extend(chr(ord(data[c:c + 1]) + ord(data[c + 1:c + 2])))
        return self.offsetChar(str(ret), -offset)
    
    def decodeBaseToNumber(self, data, base = 256):
        self.log.debug("Running decodeBaseToNumber().")
        ret = 0
        for c in data:
            ret *= base
            ret += ord(c)
        return ret
    
    def decodeData(self, data, flags):
        self.log.debug("Running decodeData().")
        return self.spec_module.decodeData(self, data, flags)
    
    def decodeReedSolomon(self, data):
        self.log.debug("Running decodeReedSolomon.")
        coder = self.reedsolomon.RSCoder(self.RS_N, self.RS_K)
        ret = bytearray()
        for c in xrange(0, len(data), self.RS_N):
            ret.extend(coder.decode(str(data)[c:c + self.RS_N], nostrip = True))
        return str(ret)
    
    def decompressStream(self, data):
        self.log.debug("Running decompressStream().")
        dio = StringIO(data)
        com = gzip.GzipFile(fileobj=dio, mode="rb")
        return com.read()
    
    def deinterleave(self, data):
        self.log.info("Running deinterleave().")
        return self.interleave(data, log=False)
    
    def descramble(self, data):
        self.log.debug("Running descramble().")
        return self.scramble(data, log=False)
    
    def dispose(self):
        self.log.debug("Running dispose().")
        if self.devnull is not None:
            self.devnull.close()
        if self.fldigi is not None:
            self.fldigi = None
        elif self.serial is not None:
            self.serial.close()
            self.serial = None
    
    def encodeData(self, data, flags):
        self.log.debug("Running encodeData().")
        return self.spec_module.encodeData(self, data, flags)
    
    def encodeNumberToBase(self, number, base = 256):
        self.log.debug("Running encodeNumberToBase().")
        ret = ""
        while number != 0:
            ret = chr(number % base) + ret
            number /= base
        return ret
    
    def encodeReedSolomon(self, data):
        self.log.debug("Running encodeReedSolomon().")
        coder = self.reedsolomon.RSCoder(self.RS_N, self.RS_K)
        ret = bytearray()
        for b in xrange(0, len(data), self.RS_K):
            c = coder.encode(str(data)[b:b + self.RS_K].ljust(self.RS_K, "\x00"))
            ret.extend(c)
        return str(ret)
    
    def encodeStreamToBase128(self, data, offset = 0, hexmode = False):
        self.log.debug("Running encodeStreamToBase128().")
        ret = bytearray()
        for c in self.offsetChar(data, offset):
            if hexmode:
                ret.extend(hex(ord(c)).replace("0x", "").rjust(2, "0"))
            else:
                if ord(c) > 127:
                    ret.extend(chr(127))
                    ret.extend(chr(ord(c) - 127))
                else:
                    ret.extend(chr(0))
                    ret.extend(chr(ord(c)))
        return str(ret)
    
    def generatePacketID(self):
        return self.uuid()
    
    def interleave(self, data, log = True):
        self.log.debug("Running interleave().")
        ret = bytearray()
        llen = int(math.sqrt(self.RS_N))
        chunks = self.splitDataIntoChunks(data, self.RS_N)
        for subchunk in chunks:
            lines = self.splitDataIntoChunks(subchunk, llen)
            if len(lines) == llen:
                self.log.debug("""Matrix: -
                       12345678
                    -----------
                    A | %s
                    B | %s
                    C | %s
                    D | %s
                    E | %s
                    F | %s
                    G | %s
                    H | %s""", *lines[:8])
                for j in zip(lines[7], lines[6], lines[5], lines[4], lines[3], lines[2], lines[1], lines[0]):
                        for i in j[::-1]:
                                ret.extend(i)
            else:
                self.log.debug("The subchunks appear to have a invalid length (%d/%d), returning data so far...", len(lines), llen)
                return str(ret)
        self.log.info("In : %s", data)
        self.log.info("Out: %s", str(ret)[::-1])
        return str(ret)[::-1]
    
    def offsetChar(self, data, offset):
        self.log.debug("Running offsetChar().")
        if offset != 0:
            ret = bytearray()
            for c in data:
                x = 0
                if ord(c) + offset < 0:
                    x = (ord(c) + offset) + 256
                elif ord(c) + offset > 255:
                    x = (ord(c) + offset) - 256
                else:
                    x = (ord(c) + offset)
                ret.extend(chr(x))
            return str(ret)
        else:
            return data
    
    def ptt(self, state):
        self.log.info("Running...")
        if self.serial is not None:
            lock = threading.Lock()
            with lock:
                self.RTS_STATE = state
                self.serial.setRTS(state)
    
    def receiveData(self, callsign_from, callsign_to):
        self.log.debug("Running receiveData().")
        data = self.receiveDataFromAny(callsign_from)
        if data:
            # Verify the packet source
            if data[1][self.SECTION_SOURCE] == callsign_to:
                # And the destination
                if data[1][self.SECTION_DESTINATION] == callsign_from or (data[1][self.SECTION_DESTINATION] == self.BROADCAST_CALLSIGN and not self.IGNORE_BROADCAST_PACKETS):
                    return data
                else:
                    self.log.debug(*({True: ("Broadcast packet ignored as per user settings."), False: ("Packet didn't appear to be for us as it's for %s.", callsign_from)}[data[1][self.SECTION_DESTINATION] == self.BROADCAST_CALLSIGN]))
            else:
                self.log.debug("Packet didn't appear to come from %s.", callsign_to)
        else:
                self.log.debug("No valid data has been received...")
    
    def receiveDataFromAny(self, callsign_from):
        self.log.debug("Running receiveDataFromAny().")
        retries = 1
        rx = []
        # Loop around until we timeout or receive the FIN packet and ACK it
        while True:
            self.log.debug("Receiving packet.")
            packet = self.receivePacket(self.SYN_TIMEOUT)
            error = False
            if packet:
                # If the from_callsign is blank, set to what the packet has - useful for monitoring packets
                if callsign_from == "" and not self.IGNORE_BROADCAST_PACKETS:
                    callsign_from = packet[self.SECTION_DESTINATION]
                # Ensure the packet is for us before continuing
                if packet[self.SECTION_DESTINATION] == callsign_from or (packet[self.SECTION_DESTINATION] == self.BROADCAST_CALLSIGN and not self.IGNORE_BROADCAST_PACKETS):
                    # Check the flags
                    f = str(packet[self.SECTION_FLAGS])[::-1]
                    if f[self.FLAG_RST] == "1":
                        self.log.debug("The returned packet was RST.")
                    else:
                        if f[self.FLAG_SYN] == "1" and f[self.FLAG_ACK] == "0":
                            # All looks good, move on - the actual data isn't important
                            rx.append(packet)
                            # TCP traffic must be ACK'ed
                            if f[self.FLAG_TCP] == "1":
                                self.log.debug("SYN (TCP) packet received, ACK'ing.")
                                flags = Bits()
                                flags.set(self.FLAG_COMPRESSION, 0)
                                flags.set(self.FLAG_SYN, 1)
                                flags.set(self.FLAG_ACK, 1)
                                self.transmitPacket(callsign_from, "", packet[self.SECTION_SOURCE], flags, "SYN-ACK")
                            else:
                                self.log.debug("SYN (UDP) packet received.")
                        elif f[self.FLAG_FIN] == "1" and f[self.FLAG_ACK] == "0":
                            if f[self.FLAG_TCP] == "1":
                                # FIN received, send a FIN-ACK
                                self.log.debug("FIN (TCP) packet received, ACK'ing.")
                                flags = Bits()
                                flags.set(self.FLAG_COMPRESSION, 0)
                                flags.set(self.FLAG_ACK, 1)
                                flags.set(self.FLAG_FIN, 1)
                                self.transmitPacket(callsign_from, "", packet[self.SECTION_SOURCE], flags, "FIN-ACK")
                            else:
                                self.log.debug("FIN (UDP) packet received.")
                            # FIN indicates the end of the data, so return the data
                            break
                        # Return the data if the packet has been flagged to do so
                        if f[self.FLAG_RETURN_DATA] == "1":
                            self.log.info("Returning data as requested by the packet flag.")
                            break
                else:
                    if packet[self.SECTION_DESTINATION] == self.BROADCAST_CALLSIGN:
                            self.log.debug("Broadcast packet ignored as per user settings.")
                    else:
                            self.log.debug("The packet wasn't for us, it was for %s.", packet[self.SECTION_DESTINATION])
            else:
                error = True
            # Timeout or packet not heard
            if error:
                self.log.debug("No valid packet was received.")
                if retries >= self.MAX_RETRIES:
                    self.log.debug("Maximum retries (%d) has been exceeded.", self.MAX_RETRIES)
                    return None
                retries += 1
        # Return the data
        if len(rx) == 0:
            return None
        else:
            data = bytearray()
            for r in rx:
                data.extend(self.decodeData(str(r[self.SECTION_DATA]), r[self.SECTION_FLAGS]))
            return [str(data), rx[0]]
    
    def receivePacket(self, timeout = 0.0):
        self.log.info("Running receivePacket().")
        buffer = bytearray()
        starttime = time.time()
        # Ensure we're not keyed up
        if self.serial:
            self.ptt(False)
        while True:
            extracted = None
            if self.fldigi:
                # Fldigi requires the buffer to be filled differently...
                buffer = bytearray()
                bytes = self.fldigi.text.get_rx_length()
                if bytes > 0:
                    # Ensure we're thread-safe
                    lock = threading.Lock()
                    with lock:
                        try:
                            # Check it twice, to reduce the chance of getting a "Integer parameter too high" exception
                            bytes = self.fldigi.text.get_rx_length()
                            if bytes > 0:
                                buffer.extend(str(self.fldigi.text.get_rx(0, bytes - 1).data))
                        except xmlrpclib.Fault, ex:
                            self.log.debug(ex, exc_info=True)
                x = str(buffer).rfind(self.PROTOCOL_HEADER)
                if x != -1:
                    y = str(buffer).rfind(self.PROTOCOL_FOOTER, x + len(self.PROTOCOL_HEADER))
                    if y <> -1:
                        if y > x:
                            self.log.debug("A packet has been found in the text.")
                            # Clear fldigi, we can't do it earlier since it misses chunks of information if we clear too often
                            self.fldigi.text.clear_rx()
                            y += len(self.PROTOCOL_FOOTER)
                            # There appears to be complete packet in there, extract it
                            extracted = self.spec_module.parsePacket(self, str(buffer[x:y]))
                        else:
                            self.log.debug("Packet not ready yet (%d/%d)." % (x, y))
            elif self.serial is not None:
                # We fill up the buffer with as much data as we can before the timeout and extract out any packets we find
                lock = threading.Lock()
                with lock:
                    try:
                        bytes = self.serial.read(self.serial.inWaiting())
                        if len(bytes) > 0:
                            self.log.debug("%d bytes will be put into the serial buffer." % len(bytes))
                            buffer.extend(bytes)
                    except Exception, ex:
                        self.log.fatal(str(ex))
                # Read the packet backwards to avoid getting any part packets in the buffer
                x = str(buffer).rfind(self.PROTOCOL_HEADER)
                if x != -1:
                    y = str(buffer).rfind(self.PROTOCOL_FOOTER, x + len(self.PROTOCOL_HEADER))
                    if y != -1:
                        if y > x:
                            self.log.debug("A packet has been found in the buffer.")
                            y += len(self.PROTOCOL_FOOTER)
                            # There appears to be complete packet in there, extract it
                            extracted = self.spec_module.parsePacket(self, str(buffer[x:y]))
                            if extracted is None:
                                # If the packet doesn't parse, clear the buffer otherwise we may enter a loop until the serial buffer overflows
                                self.log.debug("The packet didn't parse correctly, the buffer will be cleared.")
                                buffer = bytearray()
                        else:
                            self.log.debug("Packet not ready yet (%d/%d).", x, y)
            # Anything to return yet?
            if extracted:
                packet = self.splitPacket(extracted)
                if packet:
                    if self.verifyPacket(packet):
                        self.log.debug("Packet received is valid.")
                        return packet
                    else:
                        self.log.debug("Packet received is invalid.")
                        break
                else:
                    self.log.debug("Packet did not split correctly.")
                    break
            # Timer
            endtime = time.time()
            if (endtime - starttime) >= timeout:
                self.log.warn("Timeout waiting for packet.")
                break
            else:
                time.sleep(self.RX_WAIT)
    
    def scramble(self, data, log=True):
        self.log.debug("Running scramble().")
        random.seed(self.PROTOCOL_HEADER + self.PROTOCOL_VERSION + self.PROTOCOL_FOOTER)
        ret = bytearray()
        for char in data:
                ret.extend(chr(ord(char) ^ random.randint(0, 255)))
        return str(ret)
    
    def setCallsign(self, callsign):
        self.CALLSIGN = callsign
    
    def setupDSTAR(self, device = "/dev/ttyu0", port = "9600/8/N/1", timeout = 60.):
        self.log.debug("Running setupDSTAR().")
        self.setupRS232(device, port, timeout)
        # Fudge some settings for improved performance
        self.DATA_LENGTH = 640
        self.TX_HANGTIME = 0.1
    
    def setupFDMDV(self, play_device = "/dev/dsp0", record_device = "/dev/dsp1"):
        self.log.info("Running setupFDMDV().")
        try:
            self.fdmdv = FDMDV(colour_logging = self.COLOUR_LOGGING, debug_mode = self.DEBUG_MODE)
        except ImportError:
            self.log.fatal("Failed to load the FDMDV module, please note this will only work under FreeBSD, Linux, and other Unixes.")
        except Exception, ex:
            self.log.fatal("Failed to initialise the FDMDV backend.")
            self.log.fatal(str(ex))
    
    def setupFldigi(self, hostname="localhost", port=7362):
        self.log.("Running setupFldigi().")
        self.fldigi = xmlrpclib.ServerProxy("http://%s:%s" % (hostname, port))
        self.fldigi.main.set_lock(False)
        self.fldigi.modem.set_carrier(self.conf.main_carrier_freq)
        self.fldigi.modem.set_by_name(self.conf.main_data_mode)
        self.fldigi.main.set_sideband(self.SIDEBAND)
        self.fldigi.main.set_lock(True)
        # Fudge some settings for improved performance
        self.TX_HANGTIME = 0.2
    
    def setupGMSK(self, device = "/dev/ttyu0", port = "9600/8/N/1", timeout = 60.):
        self.log.debug("Running setupGMSK().")
        self.setupRS232(device, port, timeout)
        # Fudge some settings for improved performance
        self.TX_HANGTIME = 0.1
        self.PROTOCOL_PREAMPLE = "\xcc" * 16
    
    def setupRS232(self, device = "/dev/ttyu0", port = "9600/8/N/1", timeout = 60.0):
        self.log.debug("Running setupRS232().")
        try:
            conn = port.split("/")
            self.serial = serial.Serial()
            self.serial.baudrate = int(conn[0])
            self.serial.bytesize = int(conn[1])
            self.serial.parity = conn[2]
            self.serial.port = device
            self.serial.stopbits = int(conn[3])
            self.serial.timeout = timeout
            self.serial.writeTimeout = None
            self.serial.xonxoff = None
            self.serial.open()
            self.serial.setRTS(False)
            self.serial.flushInput()
            self.serial.flushOutput()
            # Fudge some settings for improved performance
            self.TX_HANGTIME = 0.075
            # How much data can we send per second?
            p = 0.0
            if self.serial.parity <> "N":
                p = 1.0
            self.SERIAL_BPS = float(self.serial.baudrate) / (float(self.serial.bytesize) + p + float(self.serial.stopbits))
            self.log.debug("Serial port can handle %d bytes per second.", self.SERIAL_BPS)
        except Exception, ex:
            self.log.fatal("Failed to initialise the RS-232 backend.")
            self.log.fatal(str(ex))
    
    def sha1(self, data):
        self.log.debug("Running sha1().")
        h = hashlib.sha1()
        h.update(data)
        return str(h.hexdigest())
    
    def splitDataIntoChunks(self, data, length):
        self.log.debug("Running splitDataIntoChunks().")
        chunks = []
        for i in xrange(0, len(data), length):
            chunks.append(data[i:i + length])
        return chunks
    
    def splitPacket(self, packet):
        self.log.debug("Running splitPacket().")
        return self.spec_module.splitPacket(self, packet)
    
    def transmitBroadcast(self, callsign_from, data):
        self.log.debug("Running transmitBroadcast().")
        # Broadcast packets are always UDP and never send a FIN packet when done
        self.transmitData(callsign_from, "", self.BROADCAST_CALLSIGN, data, 0, 0, False)
    
    def transmitData(self, callsign_from, via, callsign_to, data, tcp = 1, compress = 1, fin = True, return_data = 0):
        self.log.debug("Running transmitData().")
        chunks = self.splitDataIntoChunks(data, self.DATA_LENGTH)
        flags = Bits()
        flags.set(self.FLAG_TCP, tcp)
        if not self.spec_module.isCompressionAllowed(self):
            compress = 0
        flags.set(self.FLAG_COMPRESSION, compress)
        if self.backend <> "FLDIGI":
            flags.set(self.FLAG_EC, int(self.ec_available))
        flags.set(self.FLAG_RETURN_DATA, return_data)
        flags.set(self.FLAG_SYN, 1)
        for c in chunks:
            # First we send a SYN packet, we should get a SYN-ACK back (if using TCP) which means we can send the next packet
            retries = 1
            while True:
                self.log.debug("Sending SYN (attempt %d/%d)...", retries, self.MAX_RETRIES)
                self.transmitPacket(callsign_from, via, callsign_to, flags, c)
                # Wait the ACK packet back
                if tcp == 1:
                    self.log.debug("Waiting for SYN-ACK.")
                    back = self.receivePacket(self.ACK_TIMEOUT)
                    if back:
                        # Check the source
                        if back[self.SECTION_SOURCE] == callsign_to:
                            # And the destination
                            if back[self.SECTION_DESTINATION] == callsign_from:
                                # Check the flags
                                f = str(back[self.SECTION_FLAGS])[::-1]
                                if f[self.FLAG_RST] == "1":
                                    self.log.debug("The returned packet was RST.")
                                else:
                                    if f[self.FLAG_SYN] == "1" and f[self.FLAG_ACK] == "1":
                                        # All looks good, move on - the actual data bs[5] isn't important
                                        self.log.debug("SYN-ACK received.")
                                        break
                                    else:
                                        self.log.debug("Packet didn't appear to be ACK'ed.")
                            else:
                                self.log.debug("Packet didn't appear to be for us as it's for %s.", callsign_from)
                    else:
                        self.log.debug("Packet didn't appear to come from %s.", callsign_to)
                    # Timeout or packet not heard
                    self.log.debug("No valid packet was received.")
                    if retries >= self.MAX_RETRIES:
                        self.log.debug("No SYN-ACK received after %d retries...", self.MAX_RETRIES)
                        return False
                    retries += 1
                else:
                    break
        # Finally, send a FIN packet (if requested)
        if fin:
            flags = Bits()
            flags.set(self.FLAG_TCP, tcp)
            flags.set(self.FLAG_COMPRESSION, 0)
            if self.backend <> "FLDIGI":
                flags.set(self.FLAG_EC, int(self.ec_available))
            flags.set(self.FLAG_FIN, 1)
            retries = 1
            while True:
                # First we send a FIN packet, we should get a FIN-ACK (if using TCP) back which means we can send the next packet
                self.log.debug("Sending FIN (attempt %d/%d)...", retries, self.MAX_RETRIES)
                self.transmitPacket(callsign_from, via, callsign_to, flags, "73")
                # Wait the ACK packet back
                if tcp == 1:
                    self.log.debug("Waiting for FIN-ACK.")
                    back = self.receivePacket(self.ACK_TIMEOUT)
                    if back:
                        # Validate the source
                        if back[self.SECTION_SOURCE] == callsign_to:
                            # And now the destination
                            if back[self.SECTION_DESTINATION] == callsign_from:
                                # Check the flags
                                f = str(back[self.SECTION_FLAGS])[::-1]
                                if f[self.FLAG_RST] == "1":
                                    self.log.debug("The returned packet was RST.")
                                    break
                                else:
                                    if f[self.FLAG_FIN] == "1" and f[self.FLAG_ACK] == "1":
                                        # All looks good, move on - the actual data bs[5] isn't important
                                        self.log.debug("FIN-ACK received.")
                                        break
                                    else:
                                        self.log.debug("Packet didn't appear to be ACK'ed.")
                            else:
                                self.log.debug("Packet didn't appear to be for us as it's for %s.", callsign_from)
                        else:
                            self.log.debug("Packet didn't appear to come from %s.", callsign_to)
                    # Timeout or packet not heard
                    self.log.debug("No valid packet was received.")
                    if retries >= self.MAX_RETRIES:
                        self.log.debug("No SYN-ACK received after %d retries.", self.MAX_RETRIES)
                        return False
                    retries += 1
                else:
                    break
        # Ensure we've got the rig off key
        self.ptt(False)
        return True
    
    def transmitPacket(self, callsign_from, via, callsign_to, flags, data):
        self.log.debug("Running transmitPacket().")
        p = self.constructPacket(callsign_from, via, callsign_to, flags, data)
        self.transmitRawPacket(p)
    
    def transmitRawPacket(self, packet):
        self.log.debug("Running transmitRawPacket().")
        # First verify the packet (if required) before transmitting
        if self.VERIFY_PACKETS_BEFORE_TX:
            if not self.validatePacket(packet):
                return
        # Wait until we are rx'ing before continuing
        self.waitUntil(self.STATE_RX)
        lock = threading.Lock()
        if self.fldigi:
            with lock:
                s = bytearray()
                s.extend(str(packet))
                try:
                    self.fldigi.text.clear_rx()
                    self.fldigi.text.clear_tx()
                    self.fldigi.text.add_tx_bytes(xmlrpclib.Binary(str(s)))
                    self.log.debug("Transmitting raw packet %s (%d bytes)...",packet, len(str(packet)))
                    self.fldigi.main.tx()
                except xmlrpclib.Fault, ex:
                    self.log.debug(ex, exc_info=True)
        elif self.serial is not None:
            with lock:
                s = bytearray()
                s.extend(str(packet))
                wrote = None
                try:
                    self.ptt(True)
                    self.log.debug("Transmitting raw packet %s (%d bytes)...", packet, len(str(packet)))
                    # Time how long it takes to write the data in-case the OS caches the serial data
                    starttime = time.time()
                    wrote = self.serial.write(str(s))
                    self.serial.flush()
                    finishtime = time.time()
                    dlen = float(len(str(s)))
                    timeneeded = (dlen / self.SERIAL_BPS)
                    timetaken = (finishtime - starttime)
                    self.log.debug("Data length: %d, BPS: %d, Time required: %.5f, Time taken: %.5f", dlen, self.SERIAL_BPS, timeneeded, timetaken)
                    p = round(timeneeded - timetaken, 3)
                    if p > 0.:
                        self.log.debug("Waiting for %.3f seconds for data to flush.", p)
                        time.sleep(p)
                    if wrote is not None:
                        if wrote != len(s):
                            self.log.warn("%d/%d bytes where written to the serial port.", wrote, len(s))
                    self.ptt(False)
                except Exception, ex:
                    self.log.debug(ex, exc_info=True)
                if wrote:
                    if wrote != len(s):
                        self.log.debug("%d/%d bytes where written to the serial port.", wrote, len(s))
        elif self.fdmdv:
            with lock:
                s = bytearray()
                s.extend(str(packet))
                wrote = None
                try:
                    self.log.debug("Transmitting raw packet %s (%d bytes)...", packet, len(str(packet)))
                    self.fdmdv.transmitPacket(str(s))
                except Exception, ex:
                    self.log.debug(ex, exc_info=True)
                if wrote:
                    if wrote != len(s):
                        self.log.debug("%d/%d bytes where written to the serial port.", wrote, len(s))
        # Wait until everything has been tx'ed
        self.waitUntil(self.STATE_RX)

    def uuid(self, *args):
        self.log.debug("Running uuid().")
        t = long(time.time() * 1000)
        r = long(random.random() * 100000000000000000L)
        a = None
        try:
            a = socket.gethostbyname(socket.gethostname())
        except:
            # We can't get a network address, so improvise
            a = random.random() * 100000000000000000L
        data = "%l %l %s %s" % (t, r, a, args)
        return self.sha1(data)
    
    def validatePacket(self, packet):
        self.log.debug("Running validatePacket().")
        x = packet.rfind(self.PROTOCOL_HEADER)
        if x != -1:
            y = packet.rfind(self.PROTOCOL_FOOTER, x + len(self.PROTOCOL_HEADER))
            if y != -1:
                y += len(self.PROTOCOL_FOOTER)
                a = self.spec_module.parsePacket(self, str(packet[x:y]))
                if a:
                    b = self.spec_module.splitPacket(self, a)
                    if b:
                        c = self.spec_module.verifyPacket(self, b)
                        if c:
                            self.log.debug("Packet has been validated.")
                            return True
                        else:
                            self.log.error("The packet doesn't appear parse.")
                    else:
                        self.log.error("The packet failed to split correctly.")
                else:
                    self.log.error("The packet failed to parse correctly.")
            else:
                self.log.error("The packet doesn't appear to be complete (1).")
        else:
            self.log.error("The packet doesn't appear to be complete (2).")
        return False
    
    def verifyPacket(self, packet):
        self.log.debug("Running verifyPacket().")
        return self.spec_module.verifyPacket(self, packet)
    
    def waitUntil(self, state):
        self.log.debug("Running waitUntil().")
        if self.fldigi:
            while self.fldigi.main.get_trx_status() != state:
                time.sleep(self.TX_WAIT)
        elif self.serial or self.fdmdv:
            if state == self.STATE_RX:
                state = False
            elif state == self.STATE_TX:
                state = True
            if self.serial:
                while self.RTS_STATE != state:
                    time.sleep(self.TX_WAIT)
            elif self.fdmdv:
                while self.fdmdv.getState() != state:
                    time.sleep(self.TX_WAIT)

    def xorChecksum(self, data):
        s = 0
        for i in str(data):
            s = s ^ ord(i)
        s = "%02x" % s
        return s
