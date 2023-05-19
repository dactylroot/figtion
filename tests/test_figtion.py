
import os
import sys
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
