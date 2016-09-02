# -*- mode: python -*-
a = Analysis(['src/fletch.py'],
             datas=[
               ('/usr/local/lib/python2.7/site-packages/cbapi/response/models', 'cbapi/response/models'),
               ('/usr/local/lib/python2.7/site-packages/cbapi/protection/models', 'cbapi/protection/models'),
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
