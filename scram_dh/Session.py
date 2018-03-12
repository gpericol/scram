import time

class SessionExistsException(Exception):
    """Session Exception class"""
    pass

class SessionNotExistsException(Exception):
    """Session Exception class"""
    pass


class Session(object):
    """ Session class:
    Mantains Server sessions and makes them expire
    
    Constants:
    TTL: session time to live in seconds

    Attributes:
    __sessions: sessions list
    """
    TTL = 10
    __sessions = None

    def __init__(self):
        self.__sessions = {}

    def _clean_sessions(self):
        """Cleans expired sessions"""
        for id in self.__sessions.keys():
            if int(time.time()) > self.__sessions[id]['expiration']:
                del self.__sessions[id]

    def start_session(self, id):
        """Starts a new session given an ID"""
        if self.__sessions.has_key(id):
            raise SessionExistsException
        
        self.__sessions[id] = {}
        self.__sessions[id]['data'] = None
        self.__sessions[id]['expiration'] = int(time.time()) + self.TTL
        self._clean_sessions()
    
    def delete_session(self, id):
        """Deletes a session given a session ID"""
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        del self.__sessions[id]

    def get_session(self, id):
        """Returns a session given an ID"""
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        return self.__sessions[id]['data']
    
    def set_session(self, id, data):
        """Modifies a session, given a session ID and data"""
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        self.__sessions[id]['data'] = data