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


class FDMDV(object):

	def __init__(self, dsp_play_device ="/dev/dsp", dsp_record_device = "/dev/dsp", colour_logging = True, debug_mode = False):
		self.devnull = None
		self.dsp_play = None
		self.dsp_record = None
		self.AUDIO_CHANNELS = 1
		self.AUDIO_SAMPLERATE = 8000
		self.AUDIO_SPS = (self.AUDIO_CHANNELS * self.AUDIO_SAMPLERATE) * 2 # 2x for 16bit
		self.COLOUR_LOGGING = colour_logging
		self.DSP_PLAY_DEVICE = dsp_play_device
		self.DSP_RECORD_DEVICE = dsp_record_device
		self.DEBUG_MODE = debug_mode
		self.MODEM_BPS = 174 # 1400 / 8 (48 bit frames)
		self.PREAMPLE = "\xcc"
		self.RTS_STATE = False
		self.log.debug("Setting up DSP device \"%s\" for recording...", self.DSP_RECORD_DEVICE)
		self.dsp_record = ossaudiodev.open(self.DSP_RECORD_DEVICE, "r")
		self.dsp_record.setfmt(ossaudiodev.AFMT_S16_LE)
		self.dsp_record.channels(self.AUDIO_CHANNELS)
		self.dsp_record.speed(self.AUDIO_SAMPLERATE)
		self.log.debug("Setting up DSP device \"%s\" for playback...", self.DSP_PLAY_DEVICE)
		self.dsp_play = ossaudiodev.open(self.DSP_PLAY_DEVICE, "w")
		self.dsp_play.setfmt(ossaudiodev.AFMT_S16_LE)
		self.dsp_play.channels(self.AUDIO_CHANNELS)
		self.dsp_play.speed(self.AUDIO_SAMPLERATE)
		self.log.info("OSS module imported and configured successfully.")
		# Setup anything else we need
		self.devnull = open(os.devnull, "wb")
		self.log.debug("Modem can handle %d bytes per second.", self.MODEM_BPS)
	
	def decodeData(self, data):
	    self.log.debug("Running...")
		d = subprocess.Popen(["./fdmdv_demod", "-", "-"], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)
		if d is not None:
			r = d.communicate(data)
			d.wait()
			return r[0]
	
	def encodeData(self, data):
		if self.DEBUG_MODE:
			self.log.info("Running...")
		d = subprocess.Popen(["./fdmdv_mod", "-", "-"], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = False)
		if d is not None:
			r = d.communicate(data)
			d.wait()
			return r[0]
	
	def generatePreample(self, bytesneeded = 28, character = "\xcc"):
		self.log.debug("Running...")
		return character * bytesneeded
	
	def getState(self):
		self.log.debug("Running...")
		return self.RTS_STATE
	
	def padData(self, data, blocksize = 174):
		self.log.debug("Running...")
		dlen = len(str(data))
		major = dlen / blocksize
		minor = (dlen % blocksize) + 1 # Exact blocksizes causes data to be clipped
		blocks = major
		if minor > 0:
			blocks += 1
		self.log.debug("%d %d-blocks required for %d bytes of data.", blocks, blocksize, dlen)
		return str(data).center(blocks * blocksize, "\xcc")
	
	def playData(self, data):
		self.log.debug("Running...")
		self.dsp_play.write(data)
	
	def transmitPacket(self, data):
		self.log.debug("Running...")
		# Appears the modem takes a while to sync as well as trimming the data
		d = bytearray()
		d.extend(self.generatePreample(10))
		d.extend(data)
		d.extend(self.generatePreample(30))
		p = str(d)
		e = self.encodeData(p)
		self.log.debug("Transmitting raw packet %s (%d bytes)...", p, len(p))
		# Time how long it should take to transmit the data and wait accordingly
		starttime = time.time()
		self.RTS_STATE = True
		self.playData(e)
		finishtime = time.time()
		dlen = float(len(p))
		timeneeded = (dlen / self.MODEM_BPS)
		timetaken = (finishtime - starttime)
		self.log.debug("Data length: %d, BPS: %d, Time required: %.5f, Time taken: %.5f" % dlen, self.MODEM_BPS, timeneeded, timetaken)
		p = round(timeneeded - timetaken, 3)
		if p > 0.:
			self.log.debug("Waiting for %.3f seconds for data to be played...", p)
			time.sleep(p)
		self.RTS_STATE = False
