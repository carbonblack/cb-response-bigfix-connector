#!/usr/bin/env python
# heavily borrowed from Jason Garman's example on GitHub
# carbonblack/cb-threatconnect-connector project.

import os
# from distutils.core import setup
# from distutils.core import Command
# from distutils.command.bdist_rpm import bdist_rpm
# from distutils import log
# from distutils.file_util import write_file
# from distutils.util import change_root, convert_path

from setuptools import setup, find_packages

# from subprocess import call

__author__ = 'Doran Smestad'

#
# class bdist_binaryrpm(bdist_rpm):
#     description = "create a Cb Open Source Binary RPM distribution"
#
#     def initialize_options(self):
#         pass
#
#     def finalize_options(self):
#         pass
#
#     def run(self):
#         sdist = self.reinitialize_command('sdist')
#         self.run_command('sdist')
#         source = sdist.get_archive_files()[0]
#         self.copy_file(source, os.path.join(os.getenv("HOME"), "rpmbuild", "SOURCES"))
#
#         # Lots TODO here: generate spec file on demand from the rest of this setup.py file, for starters...
#         # self._make_spec_file()
#         call(['rpmbuild', '-bb', '%s.spec' % self.distribution.get_name()])


setup(
    name='python-cb-response-bigfix-integration',
    version="1.0",
    packages=find_packages(exclude=['test.*']),
    url='http://www.carbonblack.com/',
    license='MIT',
    author='Carbon Black',
    author_email='dev-support@bit9.com',
    description='Carbon Black BigFix Integration - Cb Response Module',
    # data_files=data_files,
    classifiers=[
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',

        # Pick your license as you wish (should match "license" above)
         'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='carbonblack bit9',
    # cmdclass={'bdist_binaryrpm': bdist_binaryrpm}
)