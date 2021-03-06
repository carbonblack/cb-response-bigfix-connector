from distutils.core import setup
from distutils.core import Command
from distutils.command.bdist_rpm import bdist_rpm
from distutils.file_util import write_file
from distutils.util import change_root, convert_path

from setuptools import find_packages

import os
from subprocess import call
from datetime import datetime


__version__ = datetime.now().strftime('%Y.%m.%d.%H.%M.%S')
__author__ = 'Carbon Black, R&D'


class bdist_binaryrpm(bdist_rpm):
    description = "Create a Cb Open Source Binary RPM distribution"

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        sdist = self.reinitialize_command('sdist')
        self.run_command('sdist')
        source = sdist.get_archive_files()[0]
        self.copy_file(source, os.path.join(os.getenv("HOME"), "rpmbuild", "SOURCES/"))

        # auto set the version within the RPM spec file
        call_result = call(['cp', 'rpmbuild.spec.template', 'rpmbuild.spec'])
        call_result = call(['sed',
                            '-i',
                            's\\version 0.0.9\\version {}\g'.format(self.distribution.metadata.version),
                            'rpmbuild.spec'
                            ])

        # Lots TODO here: generate spec file on demand from the rest of this setup.py file, for starters...
        # self._make_spec_file()
        # ENSURE PRELINK IS DISABLED BEFORE RUNNING THIS, causes digest errors in the rpm if you don't.
        call(['rpmbuild', '-bb', '-vv', 'rpmbuild.spec'])


class install_cb(Command):
    """This install_cb plugin will install all data files associated with the
    tool as well as the pyinstaller-compiled single binary folder scripts so that
    they can be packaged together in a binary RPM."""

    description = "install binary distribution files"

    user_options = [
        ('install-dir=', 'd',
         "base directory for installing data files "
         "(default: installation base dir)"),
        ('root=', None,
         "install everything relative to this alternate root directory"),
        ('force', 'f', "force installation (overwrite existing files)"),
        ('record=', None,
         "filename in which to record list of installed files"),
        ]

    boolean_options = ['force']

    def initialize_options(self):
        self.install_dir = None
        self.outfiles = []
        self.root = None
        self.force = 0
        self.data_files = self.distribution.data_files
        self.warn_dir = 1
        self.record = None

    def finalize_options(self):
        self.set_undefined_options('install',
                                   ('install_data', 'install_dir'),
                                   ('root', 'root'),
                                   ('force', 'force'),
                                  )

    def run(self):
        print(self.__dict__)
        for f in self.data_files:
            if isinstance(f, str):
                # don't copy files without path information
                pass
            else:
                # it's a tuple with path to install to and a list of files
                dir = convert_path(f[0])
                if not os.path.isabs(dir):
                    dir = os.path.join(self.install_dir, dir)
                elif self.root:
                    dir = change_root(self.root, dir)
                self.mkpath(dir)

                if f[1] == []:
                    # If there are no files listed, the user must be
                    # trying to create an empty directory, so add the
                    # directory to the list of output files.
                    self.outfiles.append(dir)
                else:
                    # Copy files, adding them to the list of output files.
                    for data in f[1]:
                        data = convert_path(data)
                        (out, _) = self.copy_file(data, dir)
                        self.outfiles.append(out)

        print("Scripts: {}".format(scripts))
        for scriptname in scripts.keys():
            pathname = scripts[scriptname]['dest']
            dir = convert_path(pathname)
            dir = os.path.dirname(dir)
            dir = change_root(self.root, dir)
            self.mkpath(dir)

            data = os.path.join('dist', scriptname)
            out = self.copy_tree(data, dir, preserve_mode=True)
            self.outfiles.extend(out)

        if self.record:
            outputs = self.get_outputs()
            if self.root:               # strip any package prefix
                root_len = len(self.root)
                for counter in xrange(len(outputs)):
                    outputs[counter] = outputs[counter][root_len:]
            self.execute(write_file,
                         (self.record, outputs),
                         "writing list of installed files to '%s'" %
                         self.record)

    def get_inputs(self):
        return self.data_files or []

    def get_outputs(self):
        return self.outfiles


def get_data_files(rootdir):
    # automatically build list of (dir, [file1, file2, ...],)
    # for all files under src/root/ (or provided rootdir)
    results = []
    for root, dirs, files in os.walk(rootdir):
        if len(files) > 0:
            dirname = os.path.relpath(root, rootdir)
            flist = [os.path.join(root, f) for f in files]
            results.append(("/%s" % dirname, flist))

    return results


if __name__ == "__main__":

    data_files = get_data_files("root")
    # data_files.append(('', ['pyinstaller.spec']))
    # data_files.append('scripts/cb-wildfire-connector')

    scripts = {
       'cb-response-bigfix-connector': {
           'spec': 'pyinstaller.spec',
           'dest': '/usr/share/cb/integrations/bigfix/bin/'
       }
    }

    setup(
        name='cb-response-bigfix-connector',
        version=__version__,
        packages=find_packages(exclude=['test.*']),
        url='http://www.carbonblack.com/',
        license='MIT',
        author='Carbon Black',
        author_email='dev-support@bit9.com',
        description='Carbon Black BigFix Integration - Cb Response Module',
        data_files=data_files,
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
        cmdclass={'install_cb': install_cb, 'bdist_binaryrpm': bdist_binaryrpm}
    )