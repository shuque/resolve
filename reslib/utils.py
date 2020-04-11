from reslib.common import *

def dprint(msg):
    """Print debugging message if DEBUG flag is set"""
    if Prefs.DEBUG:
        print(">> DEBUG: %s" % msg)
    return
                    
