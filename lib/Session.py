
class SessionExistsException(Exception):
    """Session Exception class"""
    pass

class SessionNotExistsException(Exception):
    """Session Exception class"""
    pass



class Session(object):
    __sessions = None

    def __init__(self):
        self.__sessions = {}

    def start_session(self, id, data = None):
        """Starts a new session given an ID"""
        if self.__sessions.has_key(id):
            raise SessionExistsException
        
        self.__sessions[id] = data
        return data

    def delete_session(self, id):
        """Deletes a session given a session ID"""
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        del self.__sessions[id]

    def get_session(self, id):
        """Returns a session given an ID"""
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        return self.__sessions[id]
    
    def set_session(self, id, data):
        """Modifies a session, given a session ID and data"""
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        self.__sessions[id] = data
