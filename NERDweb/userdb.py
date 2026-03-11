# NERDweb module for handling user database
from __future__ import print_function
from datetime import datetime
from psycopg2.pool import ThreadedConnectionPool
from psycopg2 import InterfaceError, OperationalError
import string
import random
import os.path
import psycopg2
import sys

__all__ = ['get_user_info', 'get_all_groups', 'authenticate_with_token', 'generate_unique_token']

cfg = None
acl = {}
db_pool = None


# ***** DB helpers *****

def _cursor():
    """
    Return cursor from pool with automatic reconnect.
    """
    global db_pool

    conn = db_pool.getconn()

    try:
        conn.autocommit = True # don't use transactions, every action has immediate effect
        cur = conn.cursor()
        return conn, cur
    except (InterfaceError, OperationalError):
        try:
            db_pool.putconn(conn, close=True)
        except Exception:
            pass
        conn = db_pool.getconn()
        conn.autocommit = True
        return conn, conn.cursor()


def _putconn(conn):
    global db_pool

    db_pool.putconn(conn)


def _execute(query, params=None):
    """
    Execute query with retry on broken connection.
    """
    conn, cur = _cursor()

    try:
        cur.execute(query, params)
        return conn, cur
    except (InterfaceError, OperationalError):
        _putconn(conn)
        conn, cur = _cursor()
        cur.execute(query, params)
        return conn, cur


# ***** Initialization *****

def init(config, cfg_dir):
    """
    Initialize user database wrapper.
    """
    global cfg, acl, db_pool

    db_pool = ThreadedConnectionPool(
        1,  # minconn
        10, # maxconn
        database=config.get('userdb.dbname', 'nerd_users'),
        user=config.get('userdb.dbuser', 'nerd'),
        password=config.get('userdb.dbpassword', None)
    )
    cfg = config
    acl_cfg_file = os.path.join(cfg_dir, config.get('acl_config'))

    # Load "acl" file
    # Mapping of "resource_id" to two sets of groups: "groups_allow", "groups_deny".
    # To access a resource, a user must be in at least one group of "groups_allow"
    # and must not be in any of "groups_deny".
    # Format (one resource per line):
    # <resource_id> <comma_separated_list_of_groups_allow>[;<comma_separated_list_of_groups_deny>]
    # (* means anyone)
    with open(acl_cfg_file, 'r') as f:
        for line in f:
            if line.strip() == "" or line.startswith("#"):
                continue
            id, rest = line.split(None, 1)
            allow, deny = rest.split(';') if ';' in rest else (rest, '')
            allow = set(filter(None, map(str.strip, allow.split(','))))
            deny = set(filter(None, map(str.strip, deny.split(','))))
            acl[id] = (allow, deny)


# ***** Access control functions *****

def get_all_groups():
    """Return all groups defined in the "acl" file."""
    groups = set()
    for allow,deny in acl.values():
        groups.update(allow)
        groups.update(deny)
    groups.discard('*')
    return sorted(list(groups))


def get_user_groups(full_id):
    conn, cur = _execute("SELECT groups FROM users WHERE id = %s", (full_id,))
    row = cur.fetchone()
    _putconn(conn)
    if not row:
        return set() # Unknown user - no group
    return set(row[0])


def get_ac_func(user_groups):
    """
    Return a function for testing access permissions of a specific user.
    """
    user_groups2 = user_groups.copy()
    user_groups2.add('*') # every user is in group '*', so acl rule containing '*' always matches
    def ac(resource):
        """"
        Access control test - check if current user has access to given resource.
        """
        if resource in acl and acl[resource][0] & user_groups2 and not acl[resource][1] & user_groups2:
            return True
        else:
            return False
    return ac


# TODO - split authentication and authorization/get_user_information

def get_user_info(session):
    """
    Return info about current user (or None if noone is logged in) and
    the access control function.

    To be called by all page handlers as:
      user, ac = get_user_info(session)

    'user' contains:
      login_type, id, fullid, groups, name, email, org, api_token, rl-bs, rl-tps
      `----------v---------'  `-----------v------------------------------------'
            from session            from database (find by 'fullid')
    """
    # Get ID of user logged in
    if 'user' in session:
        user = session['user'].copy() # should contain 'id', 'login_type' and optionally 'name'
        user['fullid'] = user['login_type'] + ':' + user['id']
    else:
        # No user logged in
        return None, get_ac_func(set())

    # Get user info from DB
    # TODO: get only what is normally needed (id, groups, name (to show in web header), rl-*)
    conn, cur = _execute("SELECT * FROM users WHERE id = %s", (user['fullid'],))
    col_names = [col.name for col in cur.description]
    row = cur.fetchone()
    _putconn(conn)
    if not row:
        # User not found in DB = user is authenticated (e.g. via shibboleth) but has no account yet
        user['groups'] = set()
        user['rl_bs'] = None
        user['rl_tps'] = None
        return user, get_ac_func(user['groups'])

    # Put all fields from DB into 'user' dict
    col_names[0] = 'fullid' # rename column 'id' to 'fullid', other columns can be mapped directly as they are in DB
    user.update(zip(col_names, row))

    # Convert user.groups from array/list to set
    user['groups'] = set(user['groups'])

    # Convert user.name from utf8 (TODO: this can be probably removed when we start using python3)
    if isinstance(user['name'], bytes):
        user['name'] = user['name'].decode('utf-8') if user['name'] else None

    # If the user is in "admin" group, he can select groups that take effect.
    # The set of selected groups is stored as "selected_groups" in the session
    # (which was copied into "user").
    if 'admin' in user['groups'] and 'selected_groups' in user:
        ac = get_ac_func(set(user['selected_groups']))
    else:
        ac = get_ac_func(user['groups'])

    # Update timestamp of the users last login
    t_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn, cur = _execute("UPDATE users SET t_last_login = %s WHERE id = %s", (t_now, user['fullid']))
    _putconn(conn)
    return user, ac


def authenticate_with_token(token):
    """
    Like get_user_info, but authentication uses API token
    """
    user = {}
    conn, cur = _execute("SELECT * FROM users WHERE api_token = %s", (token,))
    col_names = [col.name for col in cur.description]
    row = cur.fetchone()
    _putconn(conn)
    if not row:
        return None, lambda x: False # user not found

    col_names[0] = 'fullid' # rename column 'id' to 'fullid', other columns can be mapped directly as they are in DB
    user.update(zip(col_names, row))
    user['groups'] = set(user['groups'])
    ac = get_ac_func(user['groups'])

    # Update timestamp of the users last API call
    t_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn, cur = _execute("UPDATE users SET t_last_api_call = %s WHERE api_token = %s", (t_now, token))
    _putconn(conn)
    return user, ac


def generate_unique_token(user):
    while True:
        token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
        try:
            conn, cur = _execute("SELECT id FROM users WHERE api_token = %s", (token,))
            row = cur.fetchone()
            if not row:
                cur.execute("UPDATE users SET api_token = %s WHERE id = %s", (token, user['fullid'],))
                _putconn(conn)
                return True
            _putconn(conn)
        except psycopg2.Error as e:
            print(e.pgerror, file=sys.stderr)
            return False
