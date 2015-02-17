import logging

LOGLEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARN, "error": logging.ERROR, "fatal": logging.ERROR}

class DanLog(object):

    def __init__(self, level="info", msg_format="", date_forma=""):
        self.info("DanLog has been initialised.")
        self.logger = logging.getLogger("DANLOG")
        self.logger.setLevel(LOGLEVELS[level.lower().stip()])
	
    def _log(self, *args, **kwargs):
        if "newline" in kwargs:
            del kwargs["newline"]
        kwargs["logger"](*args, **kwargs)

    def debug(self, *args, **kwargs):
        kwargs["logger"] = self.logger.debug
        self._log(*args, **kwargs)
	
    def exit(self, exitcode = 0):
	self.sys.exit(exitcode)
	
    def fatal(self, *args, **kwargs):
        kwargs["logger"] = self.logger.error
        self._log(*args, **kwargs)

    def error(self, *args, **kwargs):
        kwargs["logger"] = self.logger.error
        self._log(*args, **kwargs)

    def warn(self, *args, **kwargs):
        kwargs["logger"] = self.logger.warn
        self._log(*args, **kwargs)

    def info(self, *args, **kwargs):
        kwargs["logger"] = self.logger.info
        self._log(*args, **kwargs)

