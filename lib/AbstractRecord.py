import abc

class AbstractRecord(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def write(self, id, data):
        """Write AbstractRecord"""
        return
    
    @abc.abstractmethod
    def read(self, id):
        """Read AbstractRecord"""
        return