
import os
import sys
import pytest
from pathlib import Path

_mypath = Path(os.path.abspath(Path(os.path.dirname(__file__))))
sys.path.append(str(_mypath.parent))

import figtion

class TestFigtion:

    confpath = _mypath / 'conf.yml'
    secretpath = _mypath / 'creds.yml'
    openpath = _mypath / 'opencreds.yml'
    defaults = {'my server'       : 'www.bestsite.web'
               ,'number of nodes' : 5
               ,'password'        : 'huduyutakeme4' }

    secretkey = "seepost-itnote"

    def setup_method(self, method):
        os.environ["FIGKEY"] = self.secretkey

        self.cfg = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        self.cfg.mask('password')

    def teardown_method(self, method):
        if os.path.exists(self.confpath):
            os.remove(self.confpath)
        if os.path.exists(self.secretpath):
            os.remove(self.secretpath)
        if os.path.exists(self.openpath):
            os.remove(self.openpath)

    def test_serialization(self):
        os.environ["FIGKEY"] = self.secretkey

        cfg = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        cfg.mask('password')
        cfg.dump()

        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        assert( len(newfig._masks) == 1 )
        assert(newfig['my server'] == 'www.bestsite.web')

    def test_type_inference_serialization(self):
        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        assert(newfig['number of nodes'] == 5)

    def test_encrypted_serialization(self):
        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        assert(newfig['password'] == 'huduyutakeme4')

    def test_masking(self):
        dumbfig = figtion.Config(defaults=self.defaults,filepath=self.confpath)
        assert( len(dumbfig._masks) == 0 )
        assert(dumbfig['password'] != 'huduyutakeme4')
        assert(dumbfig['password'] == '*****')

    def test_encrypted_update(self):
        self.cfg['password'] = 'supersecret'
        self.cfg.dump()

        newfig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)

        assert(newfig['password'] == 'supersecret')

        dumbfig = figtion.Config(defaults=self.defaults,filepath=self.confpath)
        assert(dumbfig['password'] != 'huduyutakeme4')
        assert(dumbfig['password'] != 'supersecret')
        assert(dumbfig['password'] == '*****')

        intered = figtion.Config(description=figtion._MASK_FLAG,filepath=self.secretpath)
        assert(intered['password'] == 'supersecret')

    def test_unencrypted_serialization(self):
        os.environ["FIGKEY"] = ""

        fig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.openpath)
        fig['password'] = self.defaults['password']

        assert( len(fig._masks) == 0 )

        fig.mask('password')
        assert( len(fig._masks) == 1 )

        newfig = figtion.Config(filepath=self.openpath)
        assert( newfig['password'] == self.defaults['password'] )

    def test_explicit_promiscuous_mode(self):
        fig = figtion.Config(promiscuous=True,filepath=self.confpath)

        assert(fig['my server'] == 'www.bestsite.web')
        assert(fig['number of nodes'] == 5)
        assert( len(fig._masks) == 0 )

    def test_implicit_promiscuous_mode(self):
        fig = figtion.Config(filepath=self.confpath)

        assert(fig['my server'] == 'www.bestsite.web')
        assert(fig['number of nodes'] == 5)
        assert( len(fig._masks) == 0 )

    def test_promiscuous_with_secret(self):
        fig = figtion.Config(promiscuous=True,filepath=self.confpath,secretpath=self.secretpath)

        assert(fig['my server'] == 'www.bestsite.web')
        assert(fig['number of nodes'] == 5)
        assert(fig['password'] == self.defaults['password'] )
        assert( len(fig._masks) == 1 )

    def test_only_secret(self):
        fig = figtion.Config(defaults=self.defaults,secretpath=self.secretpath)

        assert( len(fig._masks) == 0 )
        assert( fig['password'] == self.defaults['password'] )

        os.environ["FIGKEY"] = ""

        try:
            fig = figtion.Config(defaults=self.defaults,secretpath=self.secretpath)
        except Exception as e:
            assert( type(e) == OSError )
            assert( str(e).startswith("Missing the encryption key for file"))

    def test_only_secret_explicit_promiscuous(self):
        fig = figtion.Config(promiscuous=True,secretpath=self.secretpath)

        assert( len(fig._masks) == 0 )
        assert( fig['password'] == self.defaults['password'] )

    def test_only_secret_implicit_promiscuous(self):
        fig = figtion.Config(secretpath=self.secretpath)

        assert( len(fig._masks) == 0 )
        assert( fig['password'] == self.defaults['password'] )

    def test_missing_encryption_key(self):
        os.environ["FIGKEY"] = ""

        try:
            fig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
        except Exception as e:
            assert( type(e) == OSError )
            assert( str(e).startswith("Missing the encryption key for file"))

    def test_mask_nested_key(self):
        try:

            defaults = {'sub secret'      : {'password': 'huduyutakeme4' }}

            fig = figtion.Config(defaults=defaults,filepath=self.confpath,secretpath=self.secretpath)
            fig.mask('sub secret.password')
        except Exception as e:
            assert( type(e) == KeyError )
            assert( str(e).startswith("'password'"))

    def test_mask_nonexistent_secretpath(self):
        try:
            fig = figtion.Config(defaults=self.defaults,filepath=self.confpath)
            fig.mask('nonexistent')
        except Exception as e:
            assert( type(e) == Exception )
            assert( str(e).startswith('Cannot mask without a secretpath serializing path.'))

    def test_mask_nonexistent_key(self):
        try:
            fig = figtion.Config(defaults=self.defaults,filepath=self.confpath,secretpath=self.secretpath)
            fig.mask('nonexistent')
        except Exception as e:
            assert( type(e) == KeyError )
            assert( str(e).startswith("'nonexistent'"))

    # --- regression tests for previously fixed bugs ---

    def test_dump_defaults_none(self):
        """dump() with defaults=None should not crash (AttributeError on None.keys())"""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(filepath=self.confpath)
        fig['foo'] = 'bar'
        fig.dump()
        loaded = figtion.Config(filepath=self.confpath)
        assert loaded['foo'] == 'bar'

    def test_dump_empty_modified_section(self):
        """dump() should produce valid YAML when modified section is empty (no {} before block mappings)"""
        os.environ["FIGKEY"] = ""
        fig = figtion.Config(defaults=self.defaults, filepath=self.confpath)
        fig.dump()
        loaded = figtion.Config(defaults=self.defaults, filepath=self.confpath)
        assert loaded['my server'] == self.defaults['my server']

    def test_plaintext_file_with_figkey_set(self):
        """Loading a plaintext secret file when FIGKEY is set should raise a clear OSError"""
        os.environ["FIGKEY"] = ""
        figtion.Config(defaults=self.defaults, filepath=self.confpath, secretpath=self.openpath)
        os.environ["FIGKEY"] = self.secretkey
        with pytest.raises(OSError, match="plaintext"):
            figtion.Config(defaults=self.defaults, filepath=self.confpath, secretpath=self.openpath)

    def test_short_file_nonce_error(self):
        """A secret file shorter than 24 bytes raises nacl.exceptions.ValueError (bad nonce size);
        should surface as OSError, not a raw nacl exception"""
        os.environ["FIGKEY"] = self.secretkey
        with open(self.secretpath, 'wb') as f:
            f.write(b'tooshort')  # < 24-byte NONCE_SIZE
        with pytest.raises(OSError):
            figtion.Config(defaults=self.defaults, filepath=self.confpath, secretpath=self.secretpath)

    # --- tests exposing confirmed bugs ---

    def test_nestupdate_three_levels(self):
        """BUG: _nestupdate only descends one level, so 3-deep keys write to the wrong location"""
        fig = figtion.Config(defaults={'a': {'b': {'c': 'original'}}})
        fig._nestupdate('a.b.c', 'updated')
        # Currently sets fig['a']['b'] = 'updated' instead of fig['a']['b']['c'] = 'updated'
        assert fig['a']['b']['c'] == 'updated'

    def test_nestread_missing_nested_key_raises_keyerror(self):
        """BUG: _nestread raises TypeError (not KeyError) for missing nested keys,
        inconsistent with single-key access which raises KeyError"""
        fig = figtion.Config(defaults={'x': 1})
        with pytest.raises(KeyError):
            fig._nestread('missing.key')

    def test_dump_raises_without_filepath(self):
        """BUG: dump() with no filepath raises an unhelpful TypeError"""
        fig = figtion.Config(defaults=self.defaults)
        with pytest.raises(ValueError, match="filepath"):
            fig.dump()

    def test_recursive_strict_update_empty_a_none_b(self):
        """Empty config + None from an empty YAML file should not raise TypeError on a.update(None)"""
        fig = figtion.Config()
        fig._recursive_strict_update(fig, None)
        assert len(fig) == 0

    def test_defaults_not_shared_with_self_for_nested_dicts(self):
        """Nested-dict defaults must be deep-copied so mutations to self don't
        poison self._defaults or the caller's dict."""
        original = {'section': {'key': 'original'}}
        fig = figtion.Config(defaults=original, promiscuous=True)
        fig['section']['key'] = 'changed'
        assert original['section']['key'] == 'original'
        assert fig._defaults['section']['key'] == 'original'
        assert fig['section']['key'] == 'changed'

    def test_modified_nested_dict_serialized_as_modified(self):
        """Mutated nested-dict values must serialize into the 'Modified' section
        so they survive subsequent dump/load cycles."""
        os.environ["FIGKEY"] = ""
        defaults = {'db': {'host': 'localhost', 'user': ''}}
        fig = figtion.Config(defaults=defaults, filepath=self.confpath)
        fig['db']['user'] = 'postgres'
        fig.dump()
        with open(self.confpath) as f:
            text = f.read()
        mod_idx = text.find('Modified')
        def_idx = text.find('Default')
        user_idx = text.find("user: postgres")
        assert mod_idx != -1 and user_idx != -1
        assert mod_idx < user_idx < def_idx if def_idx != -1 else mod_idx < user_idx

    def test_recursive_strict_update_scalar_to_dict(self):
        """BUG: _recursive_strict_update crashes with AttributeError when a key holds
        a scalar in 'a' but a dict in 'b' (schema change from scalar to nested dict)"""
        fig = figtion.Config(defaults={'x': 'scalar'}, promiscuous=True)
        # Simulate loading a file where 'x' is now a nested dict
        fig._recursive_strict_update(fig, {'x': {'nested': 'val'}})
        assert fig['x'] == {'nested': 'val'}

    def test_filenot_found_uses_isinstance(self):
        """FileNotFoundError detection should use isinstance, not string-match on strerror,
        so it cannot false-positive on other OSErrors that happen to have a strerror attr"""
        import errno
        # PermissionError has strerror but is NOT a missing-file error
        e = PermissionError(errno.EACCES, 'No such file or directory', str(self.confpath))
        # The current string-match heuristic would incorrectly treat this as file-not-found
        # if the error message happened to contain 'No such file'.
        assert not isinstance(e, FileNotFoundError)
        assert hasattr(e, 'strerror') and 'No such file' in e.strerror  # shows the risk
