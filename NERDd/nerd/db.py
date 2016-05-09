"""
NERD entity database wrapper.

Provides EntityDatabase class -- an abstract layer above the database system 
implementing entity database.
"""

# import mongo

class UnknownEntityType(ValueError):
    pass

class EntityDatabase:
    """
    Abstract layer above the entity database. It provides an interface for 
    database operations independet on underlying database system.
    """
    # List of known/supported entity types - currently only IP addresses (both IPv4 and IPv6 are treated the same)
    _supportedTypes = ['ip']

    def __init__(self, config):
        """
        Connect to database and initialize all internal structures as neccessary.
        """
        self._db = {'ip': {}}

#     def __del__(self):
#         """
#         Destructor. Close connection to database.
#         """
#         pass

    def getEntityTypes(self):
        """
        Return list of known entity types.
        
        Currently only 'ip' type is supported.
        """
        return self._supportedTypes


    def get(self, etype, key):
        """
        Return record of given entity.
        
        Arguments:
        etype   entity type (str), e.g. 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        
        Return the record as JSON document or None it is not present in the database.
        
        Raise UnknownEntityType if there is not database collection for given etype.
        """
        if etype not in self._supportedTypes:
            raise UnknownEntityType("There is no collection for entity type "+str(etype))
        
        return self._db[etype].get(key, None)
        
    def add(self, etype, key, record):
        """
        Store new record into the database.
        
        Arguments:
        etype   entity type (str), e.g. 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        record  JSON document with properties of the entity to be stored in DB
        """
        self.update(etype, key, record)
    
    def update(self, etype, key, record):
        """
        Replace record of given entity by the new one.
        
        Arguments:
        etype   entity type (str), e.g. 'ip'
        key     entity identifier (str), e.g. '192.0.2.42'
        record  JSON document with properties of the entity to be stored in DB
        """
        if etype not in self._supportedTypes:
            raise UnknownEntityType("There is no collection for entity type "+str(etype))
        
        self._db[etype][key] = record  



