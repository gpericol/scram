
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
        if self.__sessions.has_key(id):
            raise SessionExistsException
        
        self.__sessions[id] = data
        return data

    def delete_session(self, id):
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        del self.__sessions[id]

    def get_session(self, id):
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        return self.__sessions[id]
    
    def set_session(self, id, data):
        if not self.__sessions.has_key(id):
            raise SessionNotExistsException
        
        self.__sessions[id] = data
