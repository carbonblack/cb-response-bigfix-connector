# -*- mode: python -*-
import cbapi
import os

cbapi_base_dir = os.path.dirname(cbapi.__file__)
a = Analysis(['src/fletch.py'],
             datas=[
               (os.path.join(cbapi_base_dir, 'response', 'models'), 'cbapi/response/models'),
               (os.path.join(cbapi_base_dir, 'protection', 'models'), 'cbapi/protection/models'),
               ('src/statics', 'src/statics')
             ],
             pathex=['src'],
             hiddenimports=['unicodedata', 'xml.etree', 'xml.etree.ElementTree'],
             hookspath=None,
             runtime_hooks=None)
print(a.datas)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='cb-response-bigfix-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='cb-response-bigfix-connector')
