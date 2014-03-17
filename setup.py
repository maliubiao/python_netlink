#! /usr/bin/env python
from distutils.core import setup, Extension

m = Extension('netdev',
        sources = ['netdev.c'] 
        )


setup(name = 'netdev',
        version = '1.0',
        description = 'python native library for network device',
        ext_modules = [m])
