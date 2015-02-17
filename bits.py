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


class Bits(object):

    def __init__(self, bits = 16):
        self.bit = {}
        if bits < 1:
            bits = 16
        for x in xrange(0, bits):
            self.bit[x] = 0
    
    def __str__(self):
        s = ""
        for x in self.bit.values():
            s += str(x)
        return s[::-1]
    
    def get(self, bit):
        return self.bit[bit]
    
    def set(self, bit, value):
        self.bit[bit] = value

