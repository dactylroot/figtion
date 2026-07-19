import os as _os
import copy as _copy
import time as _time
import yaml as _yaml
import threading as _threading
import contextlib as _contextlib
from pathlib import Path as _Path
import nacl.secret as _secret
import nacl.exceptions as _nacl_exc

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX platform (e.g. Windows)
    _fcntl = None

_MASK_FLAG = "masked configs"
_DEFAULT_MASK = "*****"

### Advisory-lock registry, keyed by absolute file path, tracking paths
### *this thread* currently holds the OS-level lock for. Serializes
### load()/dump() across separate processes (e.g. gunicorn workers) AND
### separate threads within one process sharing the same file, while
### staying reentrant *within a single thread* so the mask()/dump()/
### _unmask() call chain — which can nest load()/dump() calls against the
### same path — never self-deadlocks.
###
### This is thread-local by design: a bare dict keyed only by path cannot
### tell "I am nested inside my own outer call" apart from "another thread
### is mid-operation on this path" — the latter must still block on the
### real flock(), not be waved through as if it were reentrant.
_lock_registry = _threading.local()


def _thread_registry():
    try:
        return _lock_registry.registry
    except AttributeError:
        _lock_registry.registry = {}
        return _lock_registry.registry


@_contextlib.contextmanager
def _file_lock(path):
    path = _os.path.abspath(path)
    registry = _thread_registry()
    entry = registry.get(path)
    if entry is not None:
        entry[1] += 1
        try:
            yield
        finally:
            entry[1] -= 1
        return

    if _fcntl is None:
        ### No advisory locking available on this platform; degrade to
        ### unlocked access rather than blocking config reads/writes.
        yield
        return

    lockpath = path + '.lock'
    try:
        _os.makedirs(_os.path.dirname(lockpath), exist_ok=True)
        fd = _os.open(lockpath, _os.O_CREAT | _os.O_RDWR)
        _fcntl.flock(fd, _fcntl.LOCK_EX)
    except OSError:
        yield
        return

    registry[path] = [fd, 1]
    try:
        yield
    finally:
        del registry[path]
        _fcntl.flock(fd, _fcntl.LOCK_UN)
        _os.close(fd)


class Config(dict):
    ### Public flag: set to True when a dynamic reload pulled in new values.
    ### The user is responsible for observing and clearing this flag.
    changed = False

    @property
    def filepath(self):
        return self._filepath

    def __init__(self, filepath = None, defaults = None, secretpath = None, verbose=True, promiscuous=False, description = None, concise=False, reload_interval=5, strict_secrets=True, mask_fields=None):
        self.description = description if description else "configurations"
        if filepath:
            self._filepath = _os.path.abspath(_os.path.expanduser(filepath))
        else:
            self._filepath = None
        ### Deep-copy so nested mutations don't alias self with self._defaults
        self._defaults = _copy.deepcopy(defaults) if defaults else defaults
        self._interred = None
        self._masks = {}
        self._verbose=verbose
        self._concise=concise
        self._allsecret = description == _MASK_FLAG
        self._promiscuous = promiscuous or (not defaults)

        ### Dynamic reload state. The public `changed` class attribute is
        ### the user-observable flag (declared at class scope above).
        ### `_reloading` starts True so that overridden read methods invoked
        ### during init (via load()/_recursive_strict_update) skip the reload
        ### check until construction is complete.
        self._reload_interval = reload_interval
        self._last_check = _time.monotonic()
        self._file_mtimes = {}
        self._reloading = True
        ### Depth counter incremented during dump()/_mask()/_unmask() to suppress
        ### _maybe_reload() re-entry while mask/unmask operations are in flight.
        self._masking = 0

        ### In-process guard, separate from _file_lock (which only serializes
        ### the actual file I/O). load()/dump()/mask() hold this for their
        ### *entire* body, including the window where a masked field is
        ### transiently written into self as a placeholder before being
        ### restored to its real value — so a concurrent reader on another
        ### thread (__getitem__/get/etc., which never touch _file_lock) can't
        ### observe that placeholder mid-cycle.
        self._state_lock = _threading.RLock()

        if secretpath:
            if not filepath:
                self._filepath = _os.path.abspath(_os.path.expanduser(secretpath))
                self._allsecret = True
            else:
                ### Inner secrets Config: disable its own reload checking;
                ### the outer Config drives reloads for both files.
                try:
                    self._interred = Config(filepath=secretpath,description=_MASK_FLAG,promiscuous=True,reload_interval=None)
                except OSError as e:
                    ### A missing/mismatched FIGKEY (or corrupt secrets file) means
                    ### secrets can't be decrypted right now. With strict_secrets=True
                    ### (default) that's fatal, matching prior behavior. Otherwise,
                    ### construct without decrypted secrets rather than failing the
                    ### whole outer Config — mask()/_unmask() already treat a missing
                    ### _interred as "nothing to resolve", so masked fields simply
                    ### keep their mask placeholder until the key is restored.
                    if strict_secrets:
                        raise
                    if verbose:
                        print(f"Warning: could not load secrets file '{secretpath}' ({e}); "
                              "continuing without decrypted secrets.")
                    self._interred = None

        ### Precedence of YAML over defaults
        if defaults:
            self.update(_copy.deepcopy(defaults))

        ### Register masked fields *before* the load() below, not just via a
        ### separate mask() call afterward. On a fresh install, filepath
        ### doesn't exist yet, so load() (next) hits FileNotFoundError and
        ### self-dumps a starter file — with self._masks still empty at that
        ### point (the normal path: caller constructs, then calls mask()
        ### afterward), that self-dump writes every field, including
        ### soon-to-be-masked secrets, to filepath in plaintext, with
        ### nothing yet staged in secretpath. Two processes/threads racing
        ### to be the first-ever construction against that not-yet-existing
        ### filepath can each hit this window. Pre-registering here means
        ### the very first self-dump already masks these fields correctly -
        ### see _mask(), invoked from within the load()-triggered dump()
        ### below - equivalent to calling mask(key) for each field
        ### immediately after construction, just early enough to cover that
        ### first write too. Requires secretpath (mask() raises without one
        ### anyway); each key must already exist in `defaults`.
        if mask_fields:
            if self._interred is None:
                raise Exception('Cannot mask without a secretpath serializing path.')
            for _key in mask_fields:
                self._masks[_key] = _DEFAULT_MASK

        if self._filepath:
            self.load()
        self._refresh_mtimes()
        self._reloading = False

    @_contextlib.contextmanager
    def _locked(self):
        """ Acquire this Config's file lock(s) for the duration of load()/
            dump()/mask(). When a secrets file is attached, both self.filepath
            and self._interred.filepath are locked up front, in a fixed
            (sorted) order — not the incidental order in which nested calls
            happen to reach them — so that two Config graphs whose filepath/
            secretpath roles are swapped relative to each other can never
            acquire the two locks in opposite orders. Without this, one
            Config's mask()/dump() taking filepath-then-secretpath can
            deadlock against another Config taking secretpath-then-filepath
            for the same two files. """
        paths = {self.filepath}
        if self._interred is not None:
            paths.add(self._interred.filepath)
        with _contextlib.ExitStack() as stack:
            for path in sorted(paths):
                stack.enter_context(_file_lock(path))
            yield

    def dump(self,filepath=None):
        """ Serialize to YAML """
        if filepath:
            self._filepath = filepath
        if not self._filepath:
            raise ValueError("dump() requires a filepath")

        ### self._state_lock guards in-memory access (see its declaration);
        ### _locked() serializes the actual file I/O against other processes/
        ### threads sharing these files, in a deadlock-safe fixed order.
        ### Reentrant, so the nested _unmask() call below (which may itself
        ### call dump()) does not self-deadlock.
        with self._state_lock, self._locked():
            ### Suppress _maybe_reload() for the mask + write phase so that dict
            ### accesses inside _mask() and the list comprehensions below (self.keys(),
            ### self[k]) do not trigger a file reload — which would recurse back into
            ### _unmask() → dump() infinitely when reload_interval=0.
            self._masking += 1
            try:
                self._mask()

                default_keys = set(self._defaults.keys()) if self._defaults else set()
                used       = [k for k in self.keys() if k in default_keys]
                modified   = {k:self[k] for k in used if self[k] != self._defaults[k]}
                unmodified = {k:self[k] for k in used if self[k] == self._defaults[k]}
                deprecated = {k:self[k] for k in self.keys() if k not in default_keys}

                store = "%YAML 1.1\n---\n"
                _yams = _yaml.dump(modified,default_flow_style=False,indent=4)
                if self._concise:
                    store += _yams
                else:
                    store += "# this file should be located at {}\n".format(self.filepath)
                    store += "\n\n"
                    store += "############################################################\n"
                    store += "#### {: ^50} ####\n".format(self.description)
                    store += "############################################################\n"
                    store += "\n\n"

                    store += "##############################\n"
                    store += "#### {: ^20} ####\n".format('Modified')
                    store += "##############################\n"
                    if modified:
                        store += _yams
                    store += "\n\n"

                    if unmodified and not self._concise:
                        store += "##############################\n"
                        store += "#### {: ^20} ####\n".format('Default')
                        store += "##############################\n"
                        _yams = _yaml.dump(unmodified,default_flow_style=False,indent=4)
                        store += _yams
                        store += "\n\n"

                    if deprecated and not self._concise:
                        store += "##############################\n"
                        store += "#### {: ^20} ####\n".format('Deprecated')
                        store += "##############################\n"
                        _yams = _yaml.dump(deprecated,default_flow_style=False,indent=4)
                        store += _yams
                        store += "\n\n"

                # Store encrypted values
                _os.makedirs(_Path(self.filepath).parent,exist_ok=True)
                key = self._getcipherkey()
                if key: # encrypt secrets before writing
                    box = _secret.SecretBox(key)

                    store = box.encrypt(store.encode())
                    with open(self.filepath,'wb') as ymlfile:
                        ymlfile.write(store.nonce + store.ciphertext)
                else:
                    with open(self.filepath,'w') as ymlfile:
                        ymlfile.write(store)
            finally:
                self._masking -= 1
                ### Refresh mtimes so the _maybe_reload() check in _unmask() (and on
                ### the next dict access) does not see a spurious change and re-trigger.
                self._refresh_mtimes()

            self._unmask()

    def _recursive_strict_update(self,a,b):
        """ Update only items from 'b' which already have a key in 'a'.
            This defines behavior when there is a "schema change".
            a corresponds to canon schema.
            b corresponds to serialized (potentially outdated) YAML file:
              * values present in 'b' preside
              * 'promiscuous=False': only items defined in 'a' are kept
              * 'promiscuous=True' : items defined in 'b' are also kept
        """
        if not b:
            return
        if not a:
            a.update(b)
            return

        for key in b.keys():
            if isinstance(b[key],dict):
                if not isinstance(a.get(key), dict):
                    a[key] = {}
                self._recursive_strict_update(a[key],b[key])
            elif key in a.keys() or self._promiscuous:
                a[key] = b[key]

    def _getcipherkey(self):
        """ return cipherkey environment variable forced to 32-bit bytestring
            return None to indicate no encryption """
        key = _os.getenv("FIGKEY",default="")
        if not key or not self._allsecret:
            return None
        if len(key) > 32:
            return key[:32].encode()
        else:
            return key.ljust(32).encode()

    def load(self):
        """ Load from filepath and overwrite local items. """
        with self._state_lock, self._locked():
            try:
                key = self._getcipherkey()
                if key:
                    with open(self.filepath,'rb') as ymlfile:
                        nc = ymlfile.read()
                        nonce = nc[:_secret.SecretBox.NONCE_SIZE]
                        ciphertext = nc[_secret.SecretBox.NONCE_SIZE:]

                    box = _secret.SecretBox(key)
                    newstuff = box.decrypt(ciphertext=ciphertext,nonce=nonce)
                    newstuff = newstuff.decode('utf-8')

                else:
                    with open(self.filepath,'r') as ymlfile:
                        newstuff = ymlfile.read()

                newstuff = _yaml.load(newstuff, Loader=_yaml.FullLoader)
                self._recursive_strict_update(self,newstuff)
                self._unmask()
            except Exception as e:
                if isinstance(e, FileNotFoundError):
                    self.dump()
                    if self._verbose:
                        print(f"Initialized config file '{self.filepath}'")
                elif type(e) is UnicodeDecodeError:
                    raise OSError(f"Missing the encryption key for file '{self.filepath}'")
                elif isinstance(e, (_nacl_exc.CryptoError, _nacl_exc.ValueError)):
                    raise OSError(f"Decryption failed for '{self.filepath}': file may be plaintext but FIGKEY is set")
                else:
                    raise e

    def _watched_files(self):
        files = []
        if self._filepath:
            files.append(self._filepath)
        if self._interred is not None and self._interred._filepath:
            files.append(self._interred._filepath)
        return files

    def _refresh_mtimes(self):
        for fp in self._watched_files():
            try:
                self._file_mtimes[fp] = _os.path.getmtime(fp)
            except OSError:
                self._file_mtimes[fp] = None

    def _maybe_reload(self):
        """ If reload_interval has elapsed since last check, compare source
            file mtimes; on change, reload and set `changed` if any value
            actually differs. Guarded against reentry from load()/_unmask(). """
        if self._reloading or self._reload_interval is None or self._masking:
            return
        now = _time.monotonic()
        if now - self._last_check < self._reload_interval:
            return
        self._last_check = now

        file_changed = False
        for fp in self._watched_files():
            try:
                mtime = _os.path.getmtime(fp)
            except OSError:
                continue
            if mtime != self._file_mtimes.get(fp):
                file_changed = True
                break
        if not file_changed:
            return

        self._reloading = True
        try:
            ### Snapshot under guard so dict(self)'s iteration doesn't recurse.
            before = _copy.deepcopy(dict(self))
            self.load()
            after = dict(self)
        finally:
            self._reloading = False
        ### Refresh after load: dump()s triggered inside _unmask() bump mtimes.
        self._refresh_mtimes()
        if after != before:
            self.changed = True

    def __getitem__(self, key):
        with self._state_lock:
            self._maybe_reload()
            return super().__getitem__(key)

    def __contains__(self, key):
        with self._state_lock:
            self._maybe_reload()
            return super().__contains__(key)

    def get(self, key, default=None):
        with self._state_lock:
            self._maybe_reload()
            return super().get(key, default)

    def keys(self):
        ### Note: the returned view is still live against self after this
        ### method returns and _state_lock is released, so iterating it
        ### later is not itself protected against a concurrent mutation —
        ### only the read at the moment of the call is guarded.
        with self._state_lock:
            self._maybe_reload()
            return super().keys()

    def values(self):
        with self._state_lock:
            self._maybe_reload()
            return super().values()

    def items(self):
        with self._state_lock:
            self._maybe_reload()
            return super().items()

    def __iter__(self):
        with self._state_lock:
            self._maybe_reload()
            return super().__iter__()

    def __len__(self):
        with self._state_lock:
            self._maybe_reload()
            return super().__len__()

    def _nestupdate(self,key,val):
        cfg = self
        parts = key.split('.')
        for segment in parts[:-1]:
            cfg = dict.__getitem__(cfg, segment)
        dict.__setitem__(cfg, parts[-1], val)

    def _nestread(self,key):
        cfg = self
        for part in key.split('.'):
            cfg = dict.__getitem__(cfg, part)
        return cfg

    def mask(self,cfg_key,mask=_DEFAULT_MASK):
        """ Separate flagged variables for storage.
            Replace flagged variables with mask value.
            Good for sensitive credentials.
            Mask is serialized to `self.filepath`.
            True value serialized to `self.secretpath`. """
        if self._interred is None:
            raise Exception('Cannot mask without a secretpath serializing path.')

        ### Hold the same locks dump()/load() use for the whole stage+persist
        ### cycle, not just the individual load()/dump() calls inside
        ### _unmask() — otherwise another thread/process could interleave
        ### between staging the secret here and _unmask() persisting it.
        with self._state_lock, self._locked():
            self._masks[cfg_key] = mask
            current = self._nestread(cfg_key)
            if current != mask:
                self._interred[cfg_key] = current
            self._unmask()

    def _mask(self):
        if self._masks:

            for key,mask in self._masks.items():
                self._interred[key] = self._nestread(key)
                self._nestupdate(key,mask)

            self._interred.update({'_masks':self._masks})
            self._interred.dump()

    def _unmask(self):
        """ resolve hierarchy: {new_val > interred > mask} """
        if self._interred is None:
            return
        self._interred.load()

        try:
            self._masks.update(self._interred.pop('_masks'))
        except KeyError:
            pass

        for key,mask in self._masks.items():
            current = self._nestread(key)

            if current != mask:
                self._interred[key] = current
                self._interred.dump() # write to protected YAML
                self.dump()           # write to external YAML

            try:
                self._nestupdate(key,self._interred[key])
            except KeyError:
                pass

    def __repr__(self):
        str = ('secret ' if self._allsecret else '') + f"config reading from {self._filepath}"
        if self._interred is not None:
            str+= f"\nsecrets stored in {self._interred._filepath}"
        if self._promiscuous:
            str+= "\npromiscuous mode"
        if self._verbose:
            str+= "\nverbose mode"
        str += "\nValues:\n"
        str += super().__repr__()
        return str

with open(_Path(_os.path.abspath(_os.path.dirname(__file__))) / '__doc__','r') as _f:
    __doc__ = _f.read()
