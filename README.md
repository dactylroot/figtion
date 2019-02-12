# figtion

Configuration-dictionary package

## Why Though?

This is the simplest config interface with text file support.

## Benefits

  * seemless Python `dict` interface
    * unified config definition and defaults
  * YAML text file source for file-system input & serialization
  * simple precedence
    * `defaults` **keys** define config **keys**
    * YAML **values** override `defaults` **values**
  * secrets support
    * secrets saved to private YAML
    * auto-updates from public YAML

## Examples

### Config Definition and Defaults

    import figtion

    defaults = {'my server'       : 'www.bestsite.web'
               ,'number of nodes' : 5
               ,'password'        : 'huduyutakeme4' }
    cfg = figtion.Config(defaults=defaults,filepath='~/conf.yml')

    print(cfg['my server'])  

This will print 'www.bestsite.web' unless the value of 'my server' in `~/conf.yml` has something else.

### Config Secrets

When you want a public config file and a separate secret one.

    cfg = figtion.Config(defaults=defaults,filepath='~/conf.yml',secretpath='/opt/creds.yml')
    cfg.mask('password')

    print(cfg['password'])

This will print the value of `'password'`, which is stored in `/opt/creds.yml` and not `~/conf.yml`. If the value of `'password'` is changed in either YAML file, the password will be updated and masked from `~/creds.yml` again the next time the class is loaded in Python.
The python class always return the correct value.

## Roadmap

  * 0.9 - secrets store in separate location
  * 1.0 - secrets store in encrypted location

