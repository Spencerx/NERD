"""
NERD update manager.

Provides UpdateManager class - a NERD component which handles updates of entity
records, including chain reaction of updates casued by other updates.
"""
import sys
import os
import threading
# import multiprocessing
import queue
from datetime import datetime, timezone
import time
from collections import defaultdict, deque, Iterable, OrderedDict
import logging
import traceback

import g

ENTITY_TYPES = ['ip', 'asn']

#  Update request specification = list of three-tuples:
#    - [(op, key, value), ...]
#      - ('set', key, value)        - set new value to given key (rec[key] = value)
#      - ('append', key, value)     - append new value to array at key (rec[key].append(key))
#      - ('add_to_set', key, value) - append new value to array at key if it isn't present in the array yet (if value not in rec[key]: rec[key].append(value))
#      - ('extend_set', key, iterable) - append values from iterable to array at key if the value isn't present in the array yet (for value in iterable: if value not in rec[key]: rec[key].append(value))
#      - ('add', key, value)        - add given numerical value to that stored at key (rec[key] += value)
#      - ('sub', key, value)        - subtract given numerical value from that stored at key (rec[key] -= value)
#      - ('setmax', key, value)     - set new value of the key to larger of the given value and the current value (rec[key] = max(value, rec[key]))
#      - ('setmin', key, value)     - set new value of the key to smaller of the given value and the current value (rec[key] = min(value, rec[key]))
#      - ('remove', key, None)      - remove given key (and all subkeys) from the record (parameter is ignored) (do nothing if the key doesn't exist)
#      - ('next_step', key, (key_base, min, step)) - set value of 'key' to the smallest value of 'rec[key_base] + N*step' that is greater than 'min' (used by updater to set next update time); key_base MUST exist in the record!
#      - ('event', !name, param)    - do nothing with record, only trigger functions hooked on the event name
#  The tuple is passed to functions watching for updates of given keys / events
#  with given name. Event names must begin with '!' (attribute keys mustn't).
#  Update manager performs the requested update and calls functions hooked on 
#  the attribute/event.
#  A hooked function receives a list of updates that triggered its call, 
#  i.e. a list of 2-tuples (attr_name, new_value) or (event_name, param)
#  (if more than one update triggers the same function, it's called only once). 

# TODO: Let each module (or rather hook function) tell, whether it needs the whole record.
# Many of them probably won't so we can save the load from database
# (we just need to block any other updates, which is now done by keeping the record in _records_being_processed).

# TODO: Vyresit reakci na !NEW pri pridani noveho modulu.
# Spousta modulu reaguje na !NEW, ale pri pridani takoveho modulu do systemu
# se nepridaji nove polozky k existujicim zaznamum (protoze uz existuji),
# ani kdyz jsou updatovatny.
# Bude ptoreba pridat nejakou udalost !NEW_MODULE, ktera se pouzije na vsechny existujici zaznamy v databazi

# TODO:
# Handling of non-IP entities: Modules must call .update() when thay want to make some change in another entity (even of the same type)
# Hooked functions must be registered not only on a specific attribute/event, but also entity type
# Stav:
#  - predelan UpdateManager (mapovani funkce<->atributy je zvlast pro kazdy typ entity)
#  - zmenila se registracni funkce (pridan param etype) -> nutno zmenit vsechny moduly


def get_func_name(func_or_method):
    """Get name of function or method as pretty string."""
    try:
        fname = func_or_method.__func__.__qualname__
    except AttributeError:
        fname = func_or_method.__name__
    return func_or_method.__module__ + '.' + fname


def perform_update(rec, updreq):
    """
    Update a record according to given update reqeust.
    
    updreq - 3-tuple (op, key, value)
    
    Return specification of performed updates - either a pair (upated_key,
    new_vlaue) or None.
    (None is returned when nothing was changed, either because op=add_to_set and
    value was already in the array, or an unknown operation was requested)
    """
    op, key, value = updreq
    
    # Process keys with hierarchy, i.e. containing dots (like "events.scan.count")
    # rec will be the inner-most subobject ("events.scan"), key the last attribute ("count")
    # If path doesn't exist in the hierarchy, it's created
    while '.' in key:
        first_key, key = key.split('.',1)
        if first_key.isdecimal(): # index of array
            rec = rec[int(first_key)]
        else: # key of object/dict
            if first_key not in rec:
                rec[first_key] = {}
            rec = rec[first_key]
    
    if op == 'set':
        rec[key] = value
    
    elif op == 'append':
        if key not in rec:
            rec[key] = [value]
        else:
            rec[key].append(value)

    elif op == 'add_to_set':
        if key not in rec:
            rec[key] = [value]
        elif value not in rec[key]:
            rec[key].append(value)
        else:
            return None
    
    elif op == 'extend_set':
        if key not in rec:
            rec[key] = list(value)
        else:
            changed = False
            for val in value:
                if val not in rec[key]:
                    rec[key].append(value)
                    changed = True
            if not changed:
                return None
    
    elif op == 'add':
        if key not in rec:
            rec[key] = value
        else:
            rec[key] += value
    
    elif op == 'sub':
        if key not in rec:
            rec[key] = -value
        else:
            rec[key] -= value
    
    elif op == 'setmax':
        if key not in rec:
            rec[key] = value
        else:
            rec[key] = max(value, rec[key])
    
    elif op == 'setmin':
        if key not in rec:
            rec[key] = value
        else:
            rec[key] = min(value, rec[key])
    
    elif op == 'remove':
        if key in rec:
            del rec[key]
            return (updreq[1], None)
        return None
    
    elif op == 'next_step':
        key_base, min, step = value
        base = rec[key_base]
        rec[key] = base + ((min - base) // step + 1) * step 
    
    else:
        print("ERROR: perform_update: Unknown operation {}".format(op), file=sys.stderr)
        return None
    
    # Return tuple (updated attribute, new value)
    return (updreq[1], rec[key]) 


class UpdateManager:
    """
    Manages updates of entity records triggered by NERD modules.
    
    TODO: detailed description
    """

    def __init__(self, config, db):
        """
        Initialize update manager.
        
        Arguments:
        config -- global NERDd configuration (dict)
        db -- instance of EntityDatabase which should be used to load/store 
              entity records.
        """
        self.log = logging.getLogger("UpdateManager")
        #self.log.setLevel('DEBUG')
        
        self.db = db
        
        # Mapping of names of attributes to a list of functions that should be 
        # called when the attrbibute is updated
        # (One such mapping for each entity type)
        self._attr2func = {etype: {} for etype in ENTITY_TYPES}
        
        # Set of attributes thet may be updated by a function
        self._func2attr = {etype: {} for etype in ENTITY_TYPES}

        # Mapping of functions to set of attributes the function watches, i.e.
        # is called when the attribute is changed
        self._func_triggers = {etype: {} for etype in ENTITY_TYPES}
        
        # Initialize a queue for pending update requests
        self._request_queue = queue.Queue()#multiprocessing.JoinableQueue()
        
        # List of worker threads for processing the update requests
        self._workers = []
        
        # Number of restarts of threads by watchdog
        self._watchdog_restarts = 0
        # Register watchdog to scheduler
        g.scheduler.register(self.watchdog, second="*/30")

        # Temporary storage of records being updated.
        # Mapping of "ekey" to the following 3-tuple:
        #     (record [JSON-like object], 
        #      event handler call queue [queue.Queue containing tuples (func, event)],
        #      attributes that may change due to planned handler calls [set]
        #     )
        self._records_being_processed = {}
        # Since _records_being_processed may be accessed by many thread, locking is necessary
        self._records_being_processed_lock = threading.Lock()
        
        # Count of update requests processed (per update type)
        self._update_counter = OrderedDict([
            ('ip_new_entity',0), # New entity (usually because of new event)
            ('ip_event',0), # New event added to existing entity
            ('ip_regular_1d',0), # Regular daily update
            ('ip_regular_1w',0), # Regular weekly update
            ('ip_other',0), # Other updates
            ('asn_new_entity',0), # New entity (usually because of new event)
            ('asn_event',0), # New event added to existing entity
            ('asn_regular_1d',0), # Regular daily update
            ('asn_regular_1w',0), # Regular weekly update
            ('asn_other',0), # Other updates
        ])
        self._last_update_counter = self._update_counter.copy()

        # Call it every 2 seconds
        if ("upd_cnt_file" in g.config):
            g.scheduler.register(self.log_update_counter, second="*/2")


    def log_update_counter(self):
        # Write update counter to file (every 2 sec)
        # Lines 1-5: (IP) total number of updates (per update type)
        # Lines 6-10: (ASN) total number of updates (per update type)
        # Lines 10-15: (IP) number of updates per second (avg from last period)
        # Lines 16-20: (ASN) number of updates per second (avg from last period)
        # Line 21: current length of update request queue
        filename = g.config.get("upd_cnt_file", None)
        if not filename:
            return
        # Write to a temp file and then rename, so at no time there is a partially written file (rename is atomic operation)
        tmp_filename = filename + "_tmp$"
        with open(tmp_filename, "w") as f:
            for _,cnt in self._update_counter.items():
                f.write('{}\n'.format(cnt))
            for (_,last),(_,cnt) in zip(self._last_update_counter.items(), self._update_counter.items()):
                f.write('{}\n'.format(cnt-last))
            f.write("{}\n".format(self.get_queue_size()))
        os.replace(tmp_filename, filename)
        self._last_update_counter = self._update_counter.copy()


    def register_handler(self, func, etype, triggers, changes):
        """
        Hook a function (or bound method) to specified attribute changes/events.

        Arguments:
        func -- function or bound method
        etype -- entity type (only changes of attributes of this etype trigger the func)
        triggers -- set/list/tuple of attributes whose update trigger the call of the method (update of any one of the attributes will do)
        changes -- set/list/tuple of attributes the method call may update
        
        Notes:
        Each function must be registered only once. 
        """
        if etype not in ENTITY_TYPES:
            raise ValueError("Unknown entity type '{}'".format(etype))
        
        # _func2attr[etype]: function -> list of attrs it may change
        # _attr2func[etype]: attribute -> list of functions its change triggers
        # _func_triggers[etype]: function -> list of attrs that trigger it
        # There are separate mappings for each entity type.
        
        # Check types (because common error is to pass string instead of 1-tuple)
        if not isinstance(triggers, Iterable) or isinstance(triggers, str):
            raise TypeError('Argument "triggers" must be iterable and must not be str.')
        if not isinstance(changes, Iterable) or isinstance(changes, str):
            raise TypeError('Argument "changes" must be iterable and must not be str.')
        
        self._func2attr[etype][func] = tuple(changes) if changes is not None else ()
        self._func_triggers[etype][func] = set(triggers)
        for attr in triggers:
            if attr in self._attr2func[etype]:
                self._attr2func[etype][attr].append(func)
            else:
                self._attr2func[etype][attr] = [func]

    def get_queue_size(self):
        """Return current number of requests in the queue."""
        return self._request_queue.unfinished_tasks
        

    def update(self, ekey, update_spec):
        """
        Request an update of one or more attributes of an entity record.
        
        Put given requests into an internal queue to be processed by some of the
        worker threads. Requests may request changes of some attribute or they
        may issue events. 
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_spec -- list of 3-tuples ... (see above) TODO
        """
        # TODO check data validity
        self._request_queue.put((ekey, update_spec))
        
    
    # TODO cache results (clear cache when register_handler is called)
    def get_all_possible_changes(self, etype, attr):
        """
        Returns all attributes (as a set) that may be changed by a "chain reaction"
        of changes triggered by update of given attrbiute (or event).
        
        Warning: There must be no loops in the sequence of attributes and  
        triggered functions.
        """
        may_change = set() # Attributes that may be changed
        funcs_to_call = set(self._attr2func[etype].get(attr, ()))
        f2a = self._func2attr[etype]
        a2f = self._attr2func[etype]
        while funcs_to_call:
            func = funcs_to_call.pop()
            attrs_to_change = f2a[func]
            may_change.update(attrs_to_change)
            for attr in attrs_to_change:
                funcs_to_call |= set(a2f.get(attr, ()))
        return may_change
    
    
    def _process_update_req(self, ekey, update_requests):
        """
        Main processing function - update attributes or trigger an event.
        
        Arguments:
        ekey -- Entity type and key (2-tuple)
        update_requests -- list of 3-tuples as described above
        
        Return True if a new record was created, False otherwise.
        """ 
        etype = ekey[0]
        
        # Load record corresponding to the key -- either from database, or from
        # temporary storage of records being currently updated.
        # If record doesn't exist, create new.
        # Also load/create associated auxiliary objects:
        #   call_queue - queue of functions that should be called to update the record.
        #     queue.Queue of tuples (function, list_of_update_spec), where list_of_update_spec is a list of
        #     updates (2-tuples (key, new_value) or (event, param) which tirggered the function.
        #   may_change - set of attributes that may be changed by planned function calls

        self._records_being_processed_lock.acquire()
        if ekey in self._records_being_processed:
            # *** The record is already being processed by someone else. ***
            # Just put our update requests to its list of requests to process.
            
            # Load the records and its list of requests to process
            rec, requests_to_process, requests_to_process_lock = self._records_being_processed[ekey]
            self._records_being_processed_lock.release()
            
            # Try to add new requests to process (so they will be processed by 
            # the thread currently working with the record)
            requests_to_process_lock.acquire()
            # Check whether the record is still being processed by the other 
            # thread (it might get finished in the meantime).
            self._records_being_processed_lock.acquire()
            if ekey in self._records_being_processed:
                self._records_being_processed_lock.release()
                # It's OK, put the new requests to the list and exit
                requests_to_process.extend(update_requests)
                requests_to_process_lock.release()
                return False
            else:
                requests_to_process_lock.release()
                # The processing by the other thread was finished while we were  
                # waiting for requests_to_process_lock and the record was 
                # written back to DB and removed from _records_being_processed.
                # 
                # Let's continue like it was never processed by anyone else
                # (we have _records_being_processed locked, so noone else can 
                # start processing the record now)
        
        
        # *** The record is currently not being processed by anyone. ***
            
        # Fetch the record from database or create a new one
        new_rec_created = False
        rec = self.db.get(ekey[0], ekey[1])
        if rec is None:
            now = datetime.utcnow()
            rec = {
                'ts_added': now,
                'ts_last_update': now,
            }
            new_rec_created = True
            # New record was created -> add "!NEW" event to attrib_updates
            #self.log.debug("New record {} was created, injecting event '!NEW'".format(ekey))
            update_requests.insert(0,('event','!NEW',None))
        
        # Short-circuit if update_requests is empty (used to only create a record if it doesn't exist)
        if not update_requests:
            self._records_being_processed_lock.release()
            return False
        
        # Store the record and a list of update requests to the storage of records being processed
        requests_to_process = update_requests # may be accessed by other threads - locking necessary
        requests_to_process_lock = threading.Lock()
        self._records_being_processed[ekey] = (rec, requests_to_process, requests_to_process_lock)
        
        self._records_being_processed_lock.release()
        
        
        # *** Now we have the record, process the requested updates ***
        
        # auxiliary objects
        call_queue = deque() # planned calls of handler functions due to their hooking to attribute updates  
        may_change = set() # which attributes may change after performing all calls in call_queue
        
        # TODO vyresit loop counter, kdyz muzou prichazet asynchronne nove pozadavky
        loop_counter = 0 # counter used to stop when looping too long - probably some cycle in attribute dependencies
        
        # *** call_queue loop ***
        while True:
            # *** If any update requests are pending, process them ***
            # (i.e. perform requested changes, add calls to hooked functions to
            # the call_queue and update the set of attributes that may change)
            # (there will always be some requests in the first iteration and  
            # they will be immediately processed, but some may be added later 
            # asynchronously when some other worker thread fetches a request for 
            # update of the same entity, that's why the processing is inside the
            # loop)
            requests_to_process_lock.acquire()
            if requests_to_process:
                # Process update requests (perform updates, put hooked functions to call_queue and update may_change set)
                self.log.debug("UpdateManager: New update requests for {}: {}".format(ekey, requests_to_process))
                for updreq in update_requests:
                    op, attr, val = updreq
                    assert(op != 'event' or attr[0] == '!') # if op=event, attr must begin with '!'
                    
                    if op == 'event':
                        #self.log.debug("Initial update: Event ({}:{}).{} (param={})".format(ekey[0],ekey[1],attr,val))
                        updated = (attr, val)
                    else:
                        #self.log.debug("Initial update: Attribute update: ({}:{}).{} [{}] {}".format(ekey[0],ekey[1],attr,op,val))
                        updated = perform_update(rec, updreq)
                        if updated is None:
                            #self.log.debug("Attribute value wasn't changed.")
                            continue
                    
                    # Add to the call_queue all functions directly hooked to the attribute/event 
                    for func in self._attr2func[etype].get(attr, []):
                        # If the function is already in the queue...
                        for f,updates in call_queue:
                            if f == func:
                                # ... just add upd to list of updates that triggered it
                                # TODO FIXME: what if one attribute is updated several times? It should be in the list only once, with the latest value.
                                updates.append(updated)
                                break
                        # Otherwise put the function to the queue
                        else:
                            call_queue.append((func, [updated]))
                
                    # Compute all attribute changes that may occur due to this event and add 
                    # them to the set of attributes to change
                    #self.log.debug("get_all_possible_changes: {} -> {}".format(str(attr), repr(self.get_all_possible_changes(etype, attr))))
                    may_change |= self.get_all_possible_changes(etype, attr)
                    #self.log.debug("may_change: {}".format(may_change))
                
                # All reqests were processed, clear the list
                update_requests.clear()
            
            if not call_queue:
                break # No more work to do (but keep requests_to_process_lock locked so noone can assign us new requests)
            
            # *** Do all function calls planned in the call queue ***
            
#             self.log.debug("call_queue loop iteration {}:\n  call_queue: {}\n  may_change: {}".format(
#                 loop_counter,
#                 list(map(lambda x: (get_func_name(x[0]), x[1]), call_queue)),
#                 may_change)
#             )
            # safety check against infinite looping
            loop_counter += 1
            if loop_counter > 20:
                self.log.warning("Too many iterations when updating {}, something went wrong! Update chain stopped.".format(ekey))
                break
            
            requests_to_process_lock.release()
            
            func, updates = call_queue.popleft()
            
            # If the function watches some attributes that may be updated later due 
            # to expected subsequent events, postpone its call.
            if may_change & self._func_triggers[etype][func]:  # nonempty intersection of two sets
                # Put the function call back to the end of the queue
                self.log.debug("call_queue: Postponing call of {}({})".format(get_func_name(func), updates))
                call_queue.append((func, updates))
                continue
            
            # Call the event handler function.
            # Set of requested updates of the record should be returned
            self.log.debug("Calling: {}({}, ..., {})".format(get_func_name(func), ekey, updates))
            try:
                reqs = func(ekey, rec, updates)
            except Exception as e:
                self.log.exception("Unhandled exception during call of {}({}, rec, {}). Traceback follows:"
                    .format(get_func_name(func), ekey, updates) )
                reqs = []

            # Set requested updates to requests_to_process
            if reqs:
                requests_to_process_lock.acquire()
                requests_to_process.extend(reqs)
                requests_to_process_lock.release()
            
            # TODO FIXME - toto asi predpoklada, ze urcity atribut muze byt menen jen jednou handler funkci
            # (coz jsem mozna nekde zadal jako nutnou podminku; kazdopadne jestli to tak je, musi to byt nekde velmi jasne uvedeno) 
            # Remove set of possible attribute changes of that function from
            # may_change (they were either already changed (or are in requests_to_process) or they won't be changed)
            #self.log.debug("Removing {} from may_change.".format(self._func2attr[etype][func]))
            may_change -= set(self._func2attr[etype][func])
            #self.log.debug("New may_change: {}".format(may_change))
        
        #self.log.debug("call_queue loop end")
        # FIXME: Temporarily disabled, removing from may_change doesn't work well, the whole algorithm must be reworked
        #assert(len(may_change) == 0)
        
        # Set ts_last_update
        rec['ts_last_update'] = datetime.utcnow()
        
        #self.log.debug("RECORD: {}: {}".format(ekey, rec))
        
        # Put the record back to the DB
        self.db.put(ekey[0], ekey[1], rec)
        # and delete the entity record from list of records being processed
        self._records_being_processed_lock.acquire()
        del self._records_being_processed[ekey]
        self._records_being_processed_lock.release()
        
        # Release requests_to_process_lock - if there was some thread waiting 
        # with a new bunch of requests (it may appear after our last check of
        # requests_to_process), it will have to wait until now. It then must
        # check again if the record is still being processed, it finds out that
        # it's not and takes the processing itself.
        requests_to_process_lock.release()
        
        return new_rec_created

    
    def start(self):
        """Run the worker threads."""
        num_workers = g.config.get('worker_threads', 8)
        self.log.info("Starting {} worker threads".format(num_workers))
        #self._process = multiprocessing.Process(target=self._main_loop)
        self._workers = [ threading.Thread(target=self._worker_func, args=(i,), name="UMWorker-"+str(i)) for i in range(num_workers) ]
        for worker in self._workers:
            worker.start()
    
    def stop(self):
        """
        Stop the manager (signal all worker threads to finish and wait).
        
        All modules writing to the request queue should already be stopped.
        If some request is written to the queue after a call of this function,
        it probably won't be performed.
        """
        self.log.info("Telling all workers to stop ...")
        # Thread for printing debug messages about worker status
        threading.Thread(target=self._dbg_worker_status_print, daemon=True).start()
        
        # Wait until all work is done (other modules should be stopped now, but some tasks may still be added as a result of already ongoing processing (e.g. new IP adds new ASN))
        self._request_queue.join()
        # Send None to request_queue to signal workers to stop (one for each worker)
        for _ in self._workers:
            self._request_queue.put(None) 
        # Wait until all workers stopped (this should be immediate)
        for worker in self._workers:
            worker.join()
        # Delete file with updates count log
        filename = g.config.get("upd_cnt_file", None)
        if filename:
            try:
                os.remove(filename)
            except Exception:
                pass
        # Cleanup
        self._workers = []


    def watchdog(self):
        """
        Check whether all workers are running and restart them if not.
        
        Should be called periodically by scheduler.
        Stop whole program after 20 restarts of threads.
        """
        for i,worker in enumerate(self._workers):
            if not worker.is_alive():
                if self._watchdog_restarts < 20:
                    self.log.error("Thread {} is dead, restarting.".format(worker.name))
                    worker.join()
                    new_thread = threading.Thread(target=self._worker_func, args=(i,), name="UMWorker-"+str(i))
                    self._workers[i] = new_thread
                    new_thread.start()
                    self._watchdog_restarts += 1
                else:
                    self.log.critical("Thread {} is dead, more than 20 restarts attempted, giving up...".format(worker.name))
                    g.daemon_stop_lock.release()
                    break


    def _dbg_worker_status_print(self):
        """
        Print status of workers and the request queue every 5 seconds.
        
        Should be run as a separate (deamon) thread.
        Exits when all workers has finished.
        """
        while True:
            alive_workers = filter(threading.Thread.is_alive, self._workers)
            if not alive_workers:
                break
            self.log.debug("Queue size: {:3}, records in processing {:3}, workers alive: {}".format(
                self.get_queue_size(),
                len(self._records_being_processed),
                ','.join(map(lambda s: s.name[9:], alive_workers))) # 9 = len("UMWorker-")
            )
            time.sleep(5)
            
    
    def _worker_func(self, thread_index):
        """
        Main processing function.
        
        Run as a separate thread/process. Read request queue. For each request
        pull corresponding record from database, and call "_process_update_req"
        function.
        
        During the updating process, the record is "locked" and 
        no other worker can directly update it. Other workers can however
        put new requests into the running updating process (see beginning of 
        _process_update_req() for details).
        """
        while True:
            # Get update request from the queue
            # (None object in the queue causes termination of the process, used 
            # to exit the program)
            req = self._request_queue.get()
            if req is None:
                self.log.debug("'None' recevied from main queue - exitting".format(thread_index))
                self._request_queue.task_done()
                break
            ekey, updreq = req
            
#             self.log.debug("New update request: {},{}".format(ekey, updreq))
            
            # Call update method (pass copy of updreq since we need it unchanged for the logging code below)
            new_rec_created = self._process_update_req(ekey, updreq.copy())
            
#             self.log.debug("Task done")
            self._request_queue.task_done()
            
            # Increment corresponding update counter
            if ekey[0] in ['ip', 'asn']:
                if new_rec_created:
                    self._update_counter[ekey[0]+'_new_entity'] += 1
                elif any(u == ('add', 'events.total', 1) for u in updreq):
                    self._update_counter[ekey[0]+'_event'] += 1
                elif any(u[1] == '!every1w' for u in updreq):
                    self._update_counter[ekey[0]+'_regular_1w'] += 1
                elif any(u[1] == '!every1d' for u in updreq):
                    self._update_counter[ekey[0]+'_regular_1d'] += 1
                else:
                    self._update_counter[ekey[0]+'_other'] += 1



